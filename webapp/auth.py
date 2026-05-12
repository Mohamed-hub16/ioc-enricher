import os
import re
from urllib.parse import urlparse
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from webapp import db
from webapp.models import User

auth_bp = Blueprint("auth", __name__)


def _validate_password(password: str) -> str | None:
    if len(password) < 12:
        return "Le mot de passe doit faire au moins 12 caractères."
    if not re.search(r"[A-Z]", password):
        return "Le mot de passe doit contenir au moins une majuscule."
    if not re.search(r"[0-9]", password):
        return "Le mot de passe doit contenir au moins un chiffre."
    if not re.search(r"[!@#$%^&*\-_=+]", password):
        return "Le mot de passe doit contenir au moins un caractère spécial (!@#$%^&*-_=+)."
    return None


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("ioc.index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash("Email ou mot de passe incorrect.", "danger")
        elif not user.is_approved:
            flash("Votre compte est en attente d'approbation par un administrateur.", "warning")
        else:
            login_user(user, remember=True)
            next_url = request.args.get("next", "")
            if next_url and urlparse(next_url).netloc == "":
                return redirect(next_url)
            return redirect(url_for("ioc.index"))
    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("ioc.index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Email et mot de passe requis.", "danger")
            return render_template("register.html")
        pwd_error = _validate_password(password)
        if pwd_error:
            flash(pwd_error, "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("Cet email est déjà utilisé.", "danger")
            return render_template("register.html")

        user = User(email=email)
        user.set_password(password)

        admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
        if User.query.count() == 0 or (admin_email and email == admin_email):
            user.role = "admin"
            flash("Compte créé avec les droits administrateur.", "success")
        else:
            flash("Inscription envoyée — en attente d'approbation par un administrateur.", "info")

        db.session.add(user)
        db.session.commit()
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@auth_bp.route("/settings/api-keys", methods=["GET", "POST"])
@login_required
def api_keys():
    if not current_user.is_approved:
        flash("Votre compte n'est pas encore approuvé.", "warning")
        return redirect(url_for("ioc.index"))

    if request.method == "POST":
        vt        = request.form.get("virustotal_key", "").strip()
        abuse     = request.form.get("abuseipdb_key", "").strip()
        urlscan   = request.form.get("urlscan_key", "").strip()
        groq      = request.form.get("groq_key", "").strip()
        greynoise = request.form.get("greynoise_key", "").strip()
        abuse_ch  = request.form.get("abuse_ch_key", "").strip()
        if not vt and not current_user.virustotal_key_enc:
            flash("La clé VirusTotal est obligatoire.", "danger")
            reveal_key = session.pop("reveal_api_key", None)
            return render_template("api_keys.html", reveal_key=reveal_key)

        current_user.set_api_keys(
            vt=vt, abuse=abuse, urlscan=urlscan, groq=groq,
            greynoise=greynoise, abuse_ch=abuse_ch,
        )
        db.session.commit()
        flash("Clés API enregistrées avec succès.", "success")
        return redirect(url_for("ioc.enrich"))

    reveal_key = session.pop("reveal_api_key", None)
    return render_template("api_keys.html", reveal_key=reveal_key)


@auth_bp.route("/settings/api-token/generate", methods=["POST"])
@login_required
def generate_api_token():
    if not current_user.is_approved:
        flash("Votre compte n'est pas encore approuvé.", "warning")
        return redirect(url_for("ioc.index"))
    plain_key = current_user.generate_rest_api_key()
    db.session.commit()
    session["reveal_api_key"] = plain_key
    return redirect(url_for("auth.api_keys"))


@auth_bp.route("/settings/api-token/revoke", methods=["POST"])
@login_required
def revoke_api_token():
    if not current_user.is_approved:
        flash("Votre compte n'est pas encore approuvé.", "warning")
        return redirect(url_for("ioc.index"))
    current_user.revoke_rest_api_key()
    db.session.commit()
    flash("Token API révoqué.", "info")
    return redirect(url_for("auth.api_keys"))


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("ioc.index"))
