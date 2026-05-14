"""Auto-deploy webhook — called by GitHub on push to main."""

import hashlib
import hmac
import os
import subprocess
import sys

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


def _run_script_detached(script_name: str) -> bool:
    """Launch a Python script in a detached subprocess (fire-and-forget).
    The process outlives the web worker and writes output to <script>.log."""
    script_path = os.path.join(_REPO_DIR, script_name)
    if not os.path.isfile(script_path):
        return False
    log_path = script_path.replace(".py", ".log")
    try:
        subprocess.Popen(
            [sys.executable, "-u", script_path],
            cwd=_REPO_DIR,
            stdout=open(log_path, "a"),
            stderr=subprocess.STDOUT,
            start_new_session=True,   # detach from web-worker process group
        )
        return True
    except Exception:
        return False


def _run_script_sync(script_name: str, timeout: int = 60) -> dict:
    """Run a Python script synchronously and return stdout + returncode."""
    script_path = os.path.join(_REPO_DIR, script_name)
    if not os.path.isfile(script_path):
        return {"returncode": -1, "stdout": f"{script_name} not found"}
    result = subprocess.run(
        [sys.executable, "-u", script_path],
        cwd=_REPO_DIR,
        capture_output=True, text=True, timeout=timeout,
    )
    return {"returncode": result.returncode, "stdout": result.stdout.strip()[-800:]}


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

    # 2 — Recompute scores from existing raw data (fast, ~1s)
    recompute = _run_script_sync("recompute_scores.py", timeout=60)

    # 3 — Patch missing enricher sources in background (calls APIs, may take minutes)
    patch_launched = _run_script_detached("patch_enrich.py")

    # 4 — Reload the web app
    reloaded = _pa_reload()

    return jsonify({
        "status":              "ok",
        "git_stdout":          pull.stdout.strip(),
        "git_returncode":      pull.returncode,
        "recompute_scores":    recompute,
        "patch_enrich":        "launched in background" if patch_launched else "skipped",
        "reloaded":            reloaded,
    }), 200
