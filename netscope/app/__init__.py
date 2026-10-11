"""NetScope: a Flask dashboard for exploring packet captures."""
from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, render_template, request

from .analyzer import AnalysisCache
from .config import Config


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    app.json.sort_keys = False

    data_dir = Path(app.config["DATA_DIR"])
    data_dir.mkdir(parents=True, exist_ok=True)
    app.config["DATA_DIR"] = data_dir
    app.extensions["analysis_cache"] = AnalysisCache(app.config["CACHE_SIZE"])

    if app.config["AUTO_SAMPLE"] and not any(
            p.suffix.lower() in app.config["ALLOWED_EXTENSIONS"] for p in data_dir.iterdir()):
        from .sample_data import generate
        generate(data_dir / app.config["DEFAULT_PCAP"])

    from .api import bp
    app.register_blueprint(bp)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def json_error(status: int, message: str):
        return jsonify({"error": message}), status

    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api/"):
            return json_error(404, "Not found")
        return "Not found", 404

    @app.errorhandler(405)
    def bad_method(_):
        return json_error(405, "Method not allowed")

    @app.errorhandler(413)
    def too_large(_):
        limit = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return json_error(413, f"File too large (limit {limit} MB)")

    @app.errorhandler(500)
    def server_error(_):
        return json_error(500, "Internal server error")

    return app
