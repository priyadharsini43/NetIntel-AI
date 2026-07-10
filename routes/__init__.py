from .main import main_bp

def register_blueprints(app):
    """Registers all blueprints with the Flask application instance."""
    app.register_blueprint(main_bp)
