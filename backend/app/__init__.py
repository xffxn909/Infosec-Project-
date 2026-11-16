"""Flask application factory for the Secure Document Management System."""

import os

from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()

# In-memory JWT blocklist (replace with Redis for production multi-process use)
jwt_blocklist: set = set()


def create_app() -> Flask:
    """Create and configure the Flask application.

    Returns:
        A fully configured Flask application instance with all extensions
        initialised and all blueprints registered.
    """
    app = Flask(__name__)

    # Load configuration
    from app.config import Config
    app.config.from_object(Config)

    # Ensure required directories exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["KEYS_FOLDER"], exist_ok=True)

    # Initialise extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    CORS(app, origins=app.config.get("CORS_ORIGINS", "*"))

    # JWT token-in-blocklist callback
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        """Return True if the token JTI is in the blocklist."""
        return jwt_payload.get("jti") in jwt_blocklist

    @jwt.revoked_token_loader
    def revoked_token_response(jwt_header, jwt_payload):
        from flask import jsonify
        return jsonify({"error": "Token has been revoked. Please log in again."}), 401

    @jwt.expired_token_loader
    def expired_token_response(jwt_header, jwt_payload):
        from flask import jsonify
        return jsonify({"error": "Token has expired. Please log in again."}), 401

    @jwt.unauthorized_loader
    def unauthorized_response(error):
        from flask import jsonify
        return jsonify({"error": "Authorization token is missing or invalid."}), 401

    # Register blueprints
    from app.auth import auth_bp
    from app.documents import documents_bp
    from app.audit import audit_bp
    from app.admin import admin_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(documents_bp, url_prefix="/api/documents")
    app.register_blueprint(audit_bp, url_prefix="/api/audit")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")

    @app.route("/api/health", methods=["GET"])
    def health():
        from flask import jsonify
        return jsonify({"status": "healthy", "service": "Secure Document Management API"}), 200

    # Import models so Flask-Migrate can discover them
    with app.app_context():
        from app import models  # noqa: F401

    return app
