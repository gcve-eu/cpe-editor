import os

from flask import Flask
from sqlalchemy import event

from .cli import register_cli
from .models import db
from .views import bp


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    database_uri = os.getenv(
        "DATABASE_URL", f"sqlite:///{os.path.join(app.instance_path, 'cpe_editor.db')}"
    )
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-key"),
        SQLALCHEMY_DATABASE_URI=database_uri,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        ADMIN_USERNAME=os.getenv("ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD=os.getenv("ADMIN_PASSWORD", "admin"),
        PROPOSAL_RATE_LIMIT_PER_HOUR=int(os.getenv("PROPOSAL_RATE_LIMIT_PER_HOUR", "10")),
        OLLAMA_BASE_URL=os.getenv("OLLAMA_BASE_URL", "").strip(),
        OLLAMA_HOST=os.getenv("OLLAMA_HOST", "127.0.0.1"),
        OLLAMA_PORT=int(os.getenv("OLLAMA_PORT", "11434")),
        OLLAMA_MODEL=os.getenv("OLLAMA_MODEL", "qwen3.6:35b"),
    )
    if database_uri.startswith("sqlite"):
        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "connect_args": {
                "timeout": int(os.getenv("SQLITE_BUSY_TIMEOUT_SECONDS", "30")),
            }
        }

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    if database_uri.startswith("sqlite"):
        with app.app_context():
            engine = db.engine

            @event.listens_for(engine, "connect")
            def set_sqlite_pragmas(dbapi_connection, _connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute(
                    "PRAGMA busy_timeout = "
                    f"{int(os.getenv('SQLITE_BUSY_TIMEOUT_SECONDS', '30')) * 1000}"
                )
                cursor.close()

    app.register_blueprint(bp)
    register_cli(app)

    with app.app_context():
        db.create_all()

    return app
