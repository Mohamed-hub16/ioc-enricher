"""Auto-deploy webhook — called by GitHub on push to main."""

import hashlib
import hmac
import os
import subprocess

import httpx
from flask import Blueprint, request, jsonify
from webapp import csrf

deploy_bp = Blueprint("deploy", __name__)

_REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _verify_signature(payload: bytes, header: str) -> bool:
    secret = os.getenv("DEPLOY_SECRET", "")
    if not secret or not header:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def _pa_reload() -> bool:
    token = os.getenv("PA_API_TOKEN", "")
    username = os.getenv("PA_USERNAME", "")
    domain = os.getenv("PA_DOMAIN", "")
    if not all([token, username, domain]):
        return False
    try:
        resp = httpx.post(
            f"https://www.pythonanywhere.com/api/v0/user/{username}/webapps/{domain}/reload/",
            headers={"Authorization": f"Token {token}"},
            timeout=15.0,
        )
        return resp.status_code == 200
    except Exception:
        return False


@deploy_bp.route("/webhook/deploy", methods=["POST"])
@csrf.exempt
def deploy():
    sig = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_signature(request.data, sig):
        return jsonify({"error": "invalid signature"}), 403

    payload = request.get_json(silent=True) or {}
    ref = payload.get("ref", "")
    if ref and ref != "refs/heads/main":
        return jsonify({"status": "skipped", "reason": "not main branch"}), 200

    # 1 — Pull latest code
    pull = subprocess.run(
        ["git", "-C", _REPO_DIR, "pull", "origin", "main"],
        capture_output=True, text=True, timeout=60,
    )

    # 2 — Reload web app
    # NOTE: _pa_reload() is called LAST so the 200 response is sent before
    # the worker restarts (avoids 502 from GitHub).
    reloaded = _pa_reload()

    return jsonify({
        "status":         "ok",
        "git_stdout":     pull.stdout.strip(),
        "git_returncode": pull.returncode,
        "reloaded":       reloaded,
    }), 200
