"""Production WSGI entry point for CPE Editor.

Use this module with a production WSGI server, for example:

    gunicorn --bind 0.0.0.0:8000 wsgi:app
"""

from app import create_app

app = create_app()
