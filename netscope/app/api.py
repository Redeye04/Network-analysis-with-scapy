"""JSON API: file management, analysis, and exports."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, Response, current_app, jsonify, request
from werkzeug.utils import secure_filename

from .analyzer import AnalysisError, analyze_file

bp = Blueprint("api", __name__, url_prefix="/api")

PCAP_MAGICS = {
    bytes.fromhex("a1b2c3d4"), bytes.fromhex("d4c3b2a1"),   # pcap (us / swapped)
    bytes.fromhex("a1b23c4d"), bytes.fromhex("4d3cb2a1"),   # pcap (ns / swapped)
    bytes.fromhex("0a0d0d0a"),                              # pcapng
}
SECTIONS = ("meta", "summary", "protocols", "applications", "timeline", "packet_sizes",
            "hosts", "conversations", "communications", "ports", "tcp", "dns", "http",
            "tls", "arp", "icmp", "insecure_services", "security", "graph")

# Tabular exports: section -> (rows getter, columns)
CSV_EXPORTS = {
    "hosts": (lambda r: r["hosts"],
              ["ip", "scope", "os_guess", "macs", "services", "peers", "packets_sent",
               "packets_recv", "bytes_sent", "bytes_recv", "total_bytes", "first_seen",
               "last_seen"]),
    "conversations": (lambda r: r["conversations"],
                      ["a", "b", "protocols", "packets", "bytes", "bytes_a_to_b",
                       "bytes_b_to_a", "duration_seconds", "first_seen"]),
    "findings": (lambda r: r["security"]["findings"],
                 ["id", "severity", "category", "title", "description", "hosts"]),
    "dns": (lambda r: r["dns"]["top_domains"], ["name", "count"]),
    "ports": (lambda r: r["ports"], ["port", "protocol", "service", "packets"]),
}


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


@bp.errorhandler(ApiError)
def handle_api_error(err: ApiError):
    return jsonify({"error": err.message}), err.status


@bp.errorhandler(AnalysisError)
def handle_analysis_error(err: AnalysisError):
    return jsonify({"error": str(err)}), 422


# ------------------------------------------------------------------- helpers
def _data_dir() -> Path:
    return current_app.config["DATA_DIR"]


def _capture_files() -> list[Path]:
    exts = current_app.config["ALLOWED_EXTENSIONS"]
    return sorted((p for p in _data_dir().iterdir()
                   if p.is_file() and p.suffix.lower() in exts),
                  key=lambda p: p.stat().st_mtime, reverse=True)


def _resolve(name: str | None) -> Path:
    """Map a user-supplied file name to a capture inside DATA_DIR (no traversal)."""
    if name:
        safe = secure_filename(name)
        path = _data_dir() / safe
        if not safe or not path.is_file() or path.suffix.lower() not in \
                current_app.config["ALLOWED_EXTENSIONS"]:
            raise ApiError(f"Capture not found: {name}", 404)
        return path
    default = _data_dir() / current_app.config["DEFAULT_PCAP"]
    if default.is_file():
        return default
    files = _capture_files()
    if not files:
        raise ApiError("No capture files yet. Upload a .pcap or .pcapng file.", 404)
    return files[0]


def _analysis(path: Path) -> tuple[dict, bool]:
    cfg = current_app.config
    cache = current_app.extensions["analysis_cache"]
    return cache.get_or_compute(path, lambda: analyze_file(
        path, cfg["THRESHOLDS"], cfg["MAX_PACKETS"]))


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection from attacker-controlled strings."""
    if isinstance(value, (list, tuple)):
        value = "; ".join(str(v) for v in value)
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


# -------------------------------------------------------------------- routes
@bp.get("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat(),
                    "captures": len(_capture_files())})


@bp.get("/files")
def list_files():
    default = current_app.config["DEFAULT_PCAP"]
    files = [{"name": p.name, "size_bytes": p.stat().st_size,
              "modified": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(),
              "is_default": p.name == default} for p in _capture_files()]
    return jsonify({"files": files, "default": default})


@bp.post("/upload")
def upload():
    upload_file = request.files.get("file")
    if upload_file is None or not upload_file.filename:
        raise ApiError("No file was uploaded (expected form field 'file').")
    name = secure_filename(upload_file.filename)
    ext = Path(name).suffix.lower()
    if not name or ext not in current_app.config["ALLOWED_EXTENSIONS"]:
        allowed = ", ".join(sorted(current_app.config["ALLOWED_EXTENSIONS"]))
        raise ApiError(f"Unsupported file type. Allowed: {allowed}")
    if upload_file.stream.read(4) not in PCAP_MAGICS:
        raise ApiError("That file does not look like a pcap or pcapng capture.")
    upload_file.stream.seek(0)

    target = _data_dir() / name
    counter = 1
    while target.exists():
        target = _data_dir() / f"{Path(name).stem}-{counter}{ext}"
        counter += 1
    upload_file.save(target)
    try:  # fail fast on corrupt captures instead of leaving junk behind
        _analysis(target)
    except AnalysisError as err:
        target.unlink(missing_ok=True)
        raise ApiError(str(err), 422)
    return jsonify({"file": target.name, "size_bytes": target.stat().st_size}), 201


@bp.delete("/files/<name>")
def delete_file(name: str):
    path = _resolve(name)
    if path.name == current_app.config["DEFAULT_PCAP"]:
        raise ApiError("The default capture cannot be deleted.", 403)
    path.unlink()
    return jsonify({"deleted": path.name})


@bp.get("/analysis")
def full_analysis():
    result, hit = _analysis(_resolve(request.args.get("file")))
    resp = jsonify(result)
    resp.headers["X-Cache"] = "HIT" if hit else "MISS"
    return resp


@bp.get("/analysis/<section>")
def analysis_section(section: str):
    if section not in SECTIONS:
        raise ApiError(f"Unknown section '{section}'. Choose from: {', '.join(SECTIONS)}", 404)
    result, _ = _analysis(_resolve(request.args.get("file")))
    return jsonify(result[section])


@bp.get("/network-data")
def network_data():
    """Original endpoint, kept backwards compatible and extended."""
    result, _ = _analysis(_resolve(request.args.get("file")))
    by_name = {p["name"]: p["packets"] for p in result["protocols"]}
    known = {k: by_name.get(k, 0) for k in ("TCP", "UDP", "ARP")}
    known["Other"] = result["summary"]["packets"] - sum(known.values())
    return jsonify({
        "protocols": known,
        "communications": {f"{c['src']} -> {c['dst']}": c["packets"]
                           for c in result["communications"][:10]},
        "summary": result["summary"],
        "protocol_detail": result["protocols"],
        "top_hosts": result["hosts"][:10],
    })


@bp.get("/export/<fmt>")
def export(fmt: str):
    result, _ = _analysis(_resolve(request.args.get("file")))
    stem = Path(result["meta"]["file"]).stem
    if fmt == "json":
        body = current_app.json.dumps(result, indent=2)
        return Response(body, mimetype="application/json", headers={
            "Content-Disposition": f'attachment; filename="{stem}-analysis.json"'})
    if fmt == "csv":
        section = request.args.get("section", "hosts")
        if section not in CSV_EXPORTS:
            raise ApiError(f"CSV sections: {', '.join(CSV_EXPORTS)}")
        getter, columns = CSV_EXPORTS[section]
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(columns)
        for row in getter(result):
            writer.writerow([_csv_safe(row.get(c)) for c in columns])
        return Response(buf.getvalue(), mimetype="text/csv", headers={
            "Content-Disposition": f'attachment; filename="{stem}-{section}.csv"'})
    raise ApiError("Export format must be 'json' or 'csv'.", 404)
