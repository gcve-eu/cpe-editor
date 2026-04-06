import os

from flask import Flask

from .cli import register_cli
from .models import db
from .views import bp


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-key"),
        SQLALCHEMY_DATABASE_URI=os.getenv(
            "DATABASE_URL", f"sqlite:///{os.path.join(app.instance_path, 'cpe_editor.db')}"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        ADMIN_USERNAME=os.getenv("ADMIN_USERNAME", "admin"),
        ADMIN_PASSWORD=os.getenv("ADMIN_PASSWORD", "admin"),
    )

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    app.register_blueprint(bp)
    register_cli(app)

    with app.app_context():
        db.create_all()

    return app
