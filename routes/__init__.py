"""
routes/__init__.py
──────────────────
Registers all Flask Blueprints with the application factory.

Usage (in app.py):
    from routes import register_blueprints
    register_blueprints(app)
"""

from routes.hide     import hide_bp
from routes.extract  import extract_bp
from routes.analysis import analysis_bp


def register_blueprints(app):
    """Attach every route Blueprint to the Flask application instance."""
    app.register_blueprint(hide_bp)
    app.register_blueprint(extract_bp)
    app.register_blueprint(analysis_bp)
