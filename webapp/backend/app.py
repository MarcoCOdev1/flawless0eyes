"""
Flask application factory for OSINT Agent web application.
Wires together all extensions, blueprints, error handlers, and serves frontend.
"""
import os
import logging
from pathlib import Path
from flask import Flask, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_cors import CORS

from .config import Config
from .models import db
from .security import (
    apply_security_headers,
    rate_limit_exceeded_handler,
    get_real_ip,
)

# Frontend static files directory
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


def create_app(config_class=Config) -> Flask:
    app = Flask(
        __name__,
        static_folder=str(FRONTEND_DIR),
        static_url_path="",
    )

    # ── Load Config ───────────────────────────────────────────────────────────
    app.config.from_object(config_class)
    # Push OSINT API keys into environment for existing modules
    config_class.inject_into_env()

    # ── Logging ───────────────────────────────────────────────────────────────
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    # Never log API keys or passwords
    app.logger.setLevel(logging.INFO)

    # ── Extensions ────────────────────────────────────────────────────────────
    db.init_app(app)

    bcrypt = Bcrypt(app)
    # Store bcrypt in extensions dict so blueprints can access it
    app.extensions["bcrypt"] = bcrypt

    jwt = JWTManager(app)

    limiter = Limiter(
        key_func=get_real_ip,
        app=app,
        default_limits=[app.config.get("RATELIMIT_DEFAULT", "200 per hour")],
        storage_uri=app.config.get("RATELIMIT_STORAGE_URL", "memory://"),
        headers_enabled=True,
    )
    # Store limiter for use in blueprints
    app.extensions["limiter"] = limiter

    CORS(
        app,
        origins=app.config.get("CORS_ORIGINS", ["http://localhost:5000"]),
        supports_credentials=True,
    )

    # ── JWT error handlers ────────────────────────────────────────────────────
    @jwt.expired_token_loader
    def expired_token(_jwt_header, _jwt_data):
        return jsonify({"error": "Token expired", "code": "token_expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token(reason):
        return jsonify({"error": "Invalid token", "code": "invalid_token"}), 401

    @jwt.unauthorized_loader
    def unauthorized(reason):
        return jsonify({"error": "Authentication required", "code": "unauthorized"}), 401

    # ── Rate limit error handler ───────────────────────────────────────────────
    app.register_error_handler(429, rate_limit_exceeded_handler)

    # ── Generic error handlers ────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        # If request is for API route, return JSON. Otherwise serve frontend.
        if request_is_api():
            return jsonify({"error": "Not found"}), 404
        return send_from_directory(str(FRONTEND_DIR), "index.html"), 200

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception(f"Internal server error: {e}")
        return jsonify({"error": "Internal server error"}), 500

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    # ── Security headers (on all responses) ───────────────────────────────────
    app.after_request(apply_security_headers)

    # ── Apply rate limits to auth routes ──────────────────────────────────────
    from .auth import auth_bp
    limiter.limit(app.config.get("RATE_LIMIT_AUTH", "5 per minute"))(
        auth_bp.view_functions["auth.login"]
    )
    limiter.limit("3 per minute")(auth_bp.view_functions["auth.register"])

    from .scan import scan_bp
    limiter.limit(app.config.get("RATE_LIMIT_SCAN", "10 per hour"))(
        scan_bp.view_functions["scan.run_scan"]
    )

    # ── Register blueprints ───────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)

    # ── Serve Frontend ────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return send_from_directory(str(FRONTEND_DIR), "index.html")

    @app.route("/login")
    def login_page():
        return send_from_directory(str(FRONTEND_DIR), "login.html")

    @app.route("/dashboard")
    def dashboard_page():
        return send_from_directory(str(FRONTEND_DIR), "dashboard.html")

    @app.route("/report")
    def report_page():
        return send_from_directory(str(FRONTEND_DIR), "report.html")

    # ── DB Init ───────────────────────────────────────────────────────────────
    with app.app_context():
        db.create_all()
        _log_startup_warnings(app)

    return app


def request_is_api():
    from flask import request
    return request.path.startswith("/api/")


def _log_startup_warnings(app: Flask):
    warnings = Config.warn_missing_keys()
    if warnings:
        app.logger.warning("⚠️  Configuration warnings:")
        for w in warnings:
            app.logger.warning(f"   - {w}")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    application = create_app()
    application.run(
        host="127.0.0.1",
        port=5000,
        debug=Config.DEBUG,
        use_reloader=False,  # Disable reloader to prevent double-thread issues
        threaded=True,
    )
