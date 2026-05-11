import os
from flask import Flask, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app() -> Flask:
    app = Flask(__name__)

    instance_dir = os.path.join(_BASE_DIR, "instance")
    os.makedirs(instance_dir, exist_ok=True)

    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-only-change-me"),
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{os.path.join(instance_dir, 'ioc_enricher.db')}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    db.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Connectez-vous pour accéder à cette page."
    login_manager.login_message_category = "warning"

    from .models import User  # noqa: F401

    @login_manager.user_loader
    def load_user(user_id: str):
        return User.query.get(int(user_id))

    @app.errorhandler(403)
    def forbidden(_e):
        flash("Accès non autorisé.", "danger")
        return redirect(url_for("ioc.index"))

    from .auth import auth_bp
    from .ioc_routes import ioc_bp
    from .admin_routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(ioc_bp)
    app.register_blueprint(admin_bp)

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
        # Migration: clamp any out-of-range scores left by the old formula
        db.session.execute(db.text(
            "UPDATE ioc_records SET threat_score = 100 WHERE threat_score > 100"
        ))
        db.session.execute(db.text(
            "UPDATE ioc_records SET threat_score = 0 WHERE threat_score < 0"
        ))
        db.session.commit()

    return app
