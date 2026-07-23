"""Zero-knowledge encrypted password manager — Flask application factory."""

import logging
import os
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, jsonify

from password_manager.config import Config
from password_manager.database import init_db, close_db
from password_manager.utils.security import add_security_headers


def create_app(config: "Config | None" = None) -> Flask:
    """Build and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "..", "static"),
    )

    if config is None:
        config = Config.from_env()
    app.config.from_object(config)

    # ---- Logging ----
    _setup_logging(app)

    # ---- Security config ----
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=config.SESSION_LIFETIME_HOURS * 3600,
    )
    app.secret_key = config.SECRET_KEY

    # ---- Database ----
    init_db()
    app.teardown_appcontext(close_db)

    # ---- Security headers ----
    app.after_request(add_security_headers)

    # ---- Register blueprints ----
    from password_manager.auth.routes import auth_bp
    from password_manager.vault.routes import vault_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)

    # ---- Global error handlers ----
    @app.errorhandler(404)
    def not_found(_e):
        if request_is_api():
            return jsonify({"error": "Not found"}), 404
        return render_template("index.html", setup_needed=False), 404

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.exception("Internal server error: %s", e)
        if request_is_api():
            return jsonify({"error": "Internal server error"}), 500
        return render_template("index.html", setup_needed=False), 500

    return app


def _setup_logging(app: Flask) -> None:
    log_level = logging.DEBUG if app.debug else logging.INFO
    handler = RotatingFileHandler(
        os.path.join(os.path.dirname(__file__), "..", "vault.log"),
        maxBytes=1_048_576,  # 1 MB
        backupCount=3,
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    handler.setLevel(log_level)
    app.logger.addHandler(handler)
    app.logger.setLevel(log_level)
    app.logger.info("Password Manager starting")


def request_is_api() -> bool:
    """Check if the current request targets an API endpoint."""
    from flask import request as req
    return req.path.startswith("/api/")
