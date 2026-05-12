import os
from flask import Flask, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app() -> Flask:
    app = Flask(__name__)

    instance_dir = os.path.join(_BASE_DIR, "instance")
    os.makedirs(instance_dir, exist_ok=True)

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set. "
            "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
        )

    app.config.update(
        SECRET_KEY=secret_key,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{os.path.join(instance_dir, 'ioc_enricher.db')}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        WTF_CSRF_TIME_LIMIT=3600,
    )

    db.init_app(app)
    csrf.init_app(app)

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

    @app.context_processor
    def inject_constants():
        from webapp.models import STALE_DAYS, TLP_LEVELS
        return {"STALE_DAYS": STALE_DAYS, "TLP_LEVELS": TLP_LEVELS}

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
        for _col in [
            "virustotal_key_enc", "abuseipdb_key_enc", "urlscan_key_enc", "groq_key_enc",
            "greynoise_key_enc", "abuse_ch_key_enc",
        ]:
            try:
                db.session.execute(db.text(f"ALTER TABLE users ADD COLUMN {_col} TEXT"))
                db.session.commit()
            except Exception:
                db.session.rollback()

        # Migration: structured Groq output, score breakdown, TLP, tags
        for _stmt in [
            "ALTER TABLE ioc_records ADD COLUMN structured_json TEXT",
            "ALTER TABLE ioc_records ADD COLUMN verdict VARCHAR(20)",
            "ALTER TABLE ioc_records ADD COLUMN malware_family VARCHAR(120)",
            "ALTER TABLE ioc_records ADD COLUMN score_breakdown_json TEXT",
            "ALTER TABLE ioc_records ADD COLUMN tlp VARCHAR(15) NOT NULL DEFAULT 'AMBER'",
            "ALTER TABLE ioc_records ADD COLUMN tags_json TEXT",
        ]:
            try:
                db.session.execute(db.text(_stmt))
                db.session.commit()
            except Exception:
                db.session.rollback()

        # Indexes for the new filter columns (idempotent)
        for _idx in [
            "CREATE INDEX IF NOT EXISTS ix_ioc_records_verdict ON ioc_records (verdict)",
            "CREATE INDEX IF NOT EXISTS ix_ioc_records_malware_family ON ioc_records (malware_family)",
            "CREATE INDEX IF NOT EXISTS ix_ioc_records_ioc_type ON ioc_records (ioc_type)",
            "CREATE INDEX IF NOT EXISTS ix_ioc_records_enriched_at ON ioc_records (enriched_at)",
            "CREATE INDEX IF NOT EXISTS ix_ioc_records_threat_score ON ioc_records (threat_score)",
        ]:
            try:
                db.session.execute(db.text(_idx))
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
