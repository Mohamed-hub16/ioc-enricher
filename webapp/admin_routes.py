from flask import Blueprint, render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from webapp import db
from webapp.models import User

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _require_admin() -> None:
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


@admin_bp.route("/users")
@login_required
def users():
    _require_admin()
    pending = User.query.filter_by(role="pending").order_by(User.created_at).all()
    approved = User.query.filter(User.role != "pending").order_by(User.created_at).all()
    return render_template("admin.html", pending=pending, approved=approved)


@admin_bp.route("/approve/<int:user_id>", methods=["POST"])
@login_required
def approve(user_id: int):
    _require_admin()
    user = User.query.get_or_404(user_id)
    user.role = "analyst"
    db.session.commit()
    flash(f"{user.email} approuvé comme analyste.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/reject/<int:user_id>", methods=["POST"])
@login_required
def reject(user_id: int):
    _require_admin()
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"Compte {user.email} supprimé.", "info")
    return redirect(url_for("admin.users"))


@admin_bp.route("/revoke/<int:user_id>", methods=["POST"])
@login_required
def revoke(user_id: int):
    _require_admin()
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash("Impossible de révoquer un administrateur.", "danger")
        return redirect(url_for("admin.users"))
    user.role = "pending"
    db.session.commit()
    flash(f"Accès révoqué pour {user.email}.", "warning")
    return redirect(url_for("admin.users"))
