"""Application configuration loaded from environment variables."""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration class.

    All settings are read from environment variables so that no secrets are
    baked into source code.  Copy .env.example to .env and fill in real values
    before running the application.
    """

    # Flask core
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "change-this-secret-key")
    DEBUG: bool = os.environ.get("FLASK_DEBUG", "0") == "1"

    # Database
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL", "postgresql://user:password@localhost:5432/securedocs"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # JWT
    JWT_SECRET_KEY: str = os.environ.get("JWT_SECRET_KEY", "change-this-jwt-key")
    JWT_ACCESS_TOKEN_EXPIRES: int = 3600  # 1 hour in seconds
    JWT_TOKEN_LOCATION: list = ["headers"]
    JWT_BLOCKLIST_ENABLED: bool = True
    JWT_BLOCKLIST_TOKEN_CHECKS: list = ["access"]

    # File uploads
    UPLOAD_FOLDER: str = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        os.environ.get("UPLOAD_FOLDER", "uploads"),
    )
    KEYS_FOLDER: str = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "keys"
    )
    MAX_CONTENT_LENGTH: int = 50 * 1024 * 1024  # 50 MB

    # TOTP / MFA
    MFA_ISSUER: str = os.environ.get("MFA_ISSUER", "SecureDocSystem")

    # CORS — tighten in production
    CORS_ORIGINS: list = os.environ.get("CORS_ORIGINS", "*").split(",")
