"""
Authentication blueprint: register, login, logout, refresh, and profile.
All passwords hashed with bcrypt. JWTs stored in httpOnly cookies.
Account lockout after configurable failed attempts.
"""
from datetime import timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity,
    set_access_cookies, set_refresh_cookies,
    unset_jwt_cookies,
)
from email_validator import validate_email, EmailNotValidError

from .models import db, User
from .security import (
    require_json, bot_guard, check_honeypot, sanitize_input,
    escape_html, get_real_ip
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _json_error(message: str, code: int) -> tuple:
    return jsonify({"error": escape_html(message)}), code


# ─── Register ─────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
@bot_guard
@require_json
def register():
    from flask_bcrypt import Bcrypt
    bcrypt = current_app.extensions["bcrypt"]

    data = request.get_json(silent=True) or {}

    # Honeypot check (for API clients that send it)
    if check_honeypot(data):
        return _json_error("Forbidden", 403)

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    # ── Validate email ────────────────────────────────────────────────────────
    try:
        valid = validate_email(email, check_deliverability=False)
        email = valid.normalized
    except EmailNotValidError as exc:
        return _json_error(f"Invalid email: {exc}", 400)

    # ── Validate password ─────────────────────────────────────────────────────
    if not isinstance(password, str) or len(password) < 8:
        return _json_error("Password must be at least 8 characters", 400)
    if len(password) > 128:
        return _json_error("Password too long", 400)
    # Enforce minimal complexity
    if not any(c.isupper() for c in password):
        return _json_error("Password must contain at least one uppercase letter", 400)
    if not any(c.isdigit() for c in password):
        return _json_error("Password must contain at least one digit", 400)

    # ── Check duplicate ───────────────────────────────────────────────────────
    if User.query.filter_by(email=email).first():
        # Intentionally vague to prevent email enumeration
        return _json_error("Registration failed — please try again", 409)

    # ── Hash & create ─────────────────────────────────────────────────────────
    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(email=email, password_hash=pw_hash)
    db.session.add(user)
    db.session.commit()

    current_app.logger.info(f"New user registered: {email} from {get_real_ip()}")

    # Issue tokens immediately
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    response = jsonify({"message": "Account created", "user": user.to_dict()})
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)
    return response, 201


# ─── Login ────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
@bot_guard
@require_json
def login():
    bcrypt = current_app.extensions["bcrypt"]
    cfg = current_app.config

    data = request.get_json(silent=True) or {}

    if check_honeypot(data):
        return _json_error("Forbidden", 403)

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    # Basic format check before DB query (prevent unnecessary DB load)
    if not email or not password:
        return _json_error("Email and password are required", 400)

    user = User.query.filter_by(email=email, is_active=True).first()

    # ── Lockout check ─────────────────────────────────────────────────────────
    if user and user.is_locked():
        current_app.logger.warning(f"Login attempt on locked account: {email} from {get_real_ip()}")
        return _json_error(
            f"Account locked due to too many failed attempts. "
            f"Try again after {cfg['AUTH_LOCKOUT_MINUTES']} minutes.",
            423,
        )

    # ── Verify credentials ────────────────────────────────────────────────────
    # Check password ONLY if user exists (still do dummy hash compare to
    # prevent timing-based email enumeration)
    _DUMMY_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyNiGNnvx8KGCK"
    pw_hash = user.password_hash if user else _DUMMY_HASH
    is_correct = bcrypt.check_password_hash(pw_hash, password)

    if not user or not is_correct:
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= cfg["AUTH_MAX_FAILED_ATTEMPTS"]:
                from datetime import datetime, timezone
                user.locked_until = datetime.now(timezone.utc) + timedelta(
                    minutes=cfg["AUTH_LOCKOUT_MINUTES"]
                )
                current_app.logger.warning(f"Account locked: {email} from {get_real_ip()}")
            db.session.commit()
        return _json_error("Invalid credentials", 401)

    # ── Success ───────────────────────────────────────────────────────────────
    user.failed_login_attempts = 0
    user.locked_until = None
    from datetime import datetime, timezone
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()

    current_app.logger.info(f"User logged in: {email} from {get_real_ip()}")

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    response = jsonify({"message": "Logged in", "user": user.to_dict()})
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)
    return response, 200


# ─── Logout ───────────────────────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    response = jsonify({"message": "Logged out"})
    unset_jwt_cookies(response)
    return response, 200


# ─── Token Refresh ────────────────────────────────────────────────────────────

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return _json_error("User not found", 404)

    access_token = create_access_token(identity=str(user.id))
    response = jsonify({"message": "Token refreshed"})
    set_access_cookies(response, access_token)
    return response, 200


# ─── Profile ──────────────────────────────────────────────────────────────────

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return _json_error("User not found", 404)
    return jsonify({"user": user.to_dict()}), 200
