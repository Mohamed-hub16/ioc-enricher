import logging
import os
import traceback
from flask import Flask, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
limiter = Limiter(key_func=get_remote_address, default_limits=[])

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app() -> Flask:
    # Fail fast if cryptography is missing — better than a silent 500 at runtime.
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "Package 'cryptography' is not installed. "
            "Run: pip install -r requirements.txt"
        ) from exc

    app = Flask(__name__)

    instance_dir = os.path.join(_BASE_DIR, "instance")
    os.makedirs(instance_dir, exist_ok=True)

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set. "
            "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
        )

    is_production = os.getenv("FLASK_ENV", "production").lower() != "development"

    app.config.update(
        SECRET_KEY=secret_key,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{os.path.join(instance_dir, 'ioc_enricher.db')}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        WTF_CSRF_TIME_LIMIT=3600,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=is_production,
    )

    @app.after_request
    def _security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Connectez-vous pour accéder à cette page."
    login_manager.login_message_category = "warning"

    from .models import User, Comment  # noqa: F401

    @login_manager.user_loader
    def load_user(user_id: str):
        return User.query.get(int(user_id))

    @app.errorhandler(403)
    def forbidden(_e):
        flash("Accès non autorisé.", "danger")
        return redirect(url_for("ioc.index"))

    @app.errorhandler(429)
    def too_many_requests(_e):
        flash("Trop de tentatives de connexion. Veuillez patienter avant de réessayer.", "danger")
        return redirect(url_for("auth.login"))

    @app.errorhandler(500)
    def internal_error(exc):
        app.logger.error("500 Internal Server Error:\n%s", traceback.format_exc())
        db.session.rollback()
        return (
            "500 Internal Server Error — "
            "L'erreur a été enregistrée dans les logs du serveur.",
            500,
        )

    from .auth import auth_bp
    from .ioc_routes import ioc_bp
    from .admin_routes import admin_bp
    from .deploy_routes import deploy_bp
    from .api_routes import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(ioc_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(deploy_bp)
    app.register_blueprint(api_bp)
    csrf.exempt(api_bp)

    with app.app_context():
        db.create_all()
        # Migration: add threat_score column to existing databases
        try:
            db.session.execute(db.text(
                "ALTER TABLE ioc_records ADD COLUMN threat_score INTEGER NOT NULL DEFAULT 0"
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
        # Migration: add view_count column to existing databases
        try:
            db.session.execute(db.text(
                "ALTER TABLE ioc_records ADD COLUMN view_count INTEGER NOT NULL DEFAULT 0"
            ))
            db.session.commit()
        except Exception:
            db.session.rollback()
        # Migration: add REST API token hash column
        try:
            db.session.execute(db.text("ALTER TABLE users ADD COLUMN rest_api_key_hash VARCHAR(64)"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Migration: add encrypted API key columns to users table
        for _col in ["virustotal_key_enc", "abuseipdb_key_enc", "urlscan_key_enc",
                     "groq_key_enc", "greynoise_key_enc", "abusech_key_enc"]:
            try:
                db.session.execute(db.text(f"ALTER TABLE users ADD COLUMN {_col} TEXT"))
                db.session.commit()
            except Exception:
                db.session.rollback()

        # Migration: add extended IOCRecord columns (PR #1)
        for _col_def in [
            "verdict VARCHAR(20)",
            "malware_family VARCHAR(120)",
            "tags_json TEXT",
            "score_breakdown_json TEXT",
            "paragraphs_json TEXT",
        ]:
            try:
                db.session.execute(db.text(f"ALTER TABLE ioc_records ADD COLUMN {_col_def}"))
                db.session.commit()
            except Exception:
                db.session.rollback()

        # Migration: clamp any out-of-range scores left by the old formula
        db.session.execute(db.text(
            "UPDATE ioc_records SET threat_score = 100 WHERE threat_score > 100"
        ))
        db.session.execute(db.text(
            "UPDATE ioc_records SET threat_score = 0 WHERE threat_score < 0"
        ))
        db.session.commit()

    return app
