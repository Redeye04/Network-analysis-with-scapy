import io

from app.api import PCAP_MAGICS


def test_health_and_index(client):
    assert client.get("/api/health").json["captures"] == 1
    page = client.get("/")
    assert page.status_code == 200 and b"NetScope" in page.data
    assert "script-src 'self'" in page.headers["Content-Security-Policy"]


def test_files_listing(client):
    body = client.get("/api/files").json
    assert body["files"][0]["name"] == "network_traffic.pcap"
    assert body["files"][0]["is_default"] is True


def test_full_analysis_is_cached(client):
    first = client.get("/api/analysis")
    second = client.get("/api/analysis")
    assert first.status_code == 200
    assert first.headers["X-Cache"] == "MISS" and second.headers["X-Cache"] == "HIT"
    assert first.json["summary"]["packets"] > 0


def test_sections(client):
    assert client.get("/api/analysis/summary").json["packets"] > 0
    assert isinstance(client.get("/api/analysis/hosts").json, list)
    bad = client.get("/api/analysis/nope")
    assert bad.status_code == 404 and "error" in bad.json


def test_legacy_network_data_shape(client):
    body = client.get("/api/network-data").json
    assert set(body["protocols"]) == {"TCP", "UDP", "ARP", "Other"}
    assert sum(body["protocols"].values()) == body["summary"]["packets"]
    assert 0 < len(body["communications"]) <= 10
    assert all(" -> " in k for k in body["communications"])


def test_path_traversal_is_rejected(client):
    for name in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd", "/etc/passwd"):
        assert client.get(f"/api/analysis?file={name}").status_code == 404


def test_csv_export_and_formula_injection_guard(client):
    resp = client.get("/api/export/csv?section=findings")
    assert resp.status_code == 200 and resp.mimetype == "text/csv"
    assert resp.data.decode().splitlines()[0].startswith("id,severity")
    from app.api import _csv_safe
    assert _csv_safe("=HYPERLINK(\"x\")").startswith("'")
    assert _csv_safe(["a", "b"]) == "a; b"
    assert client.get("/api/export/csv?section=bogus").status_code == 400
    assert client.get("/api/export/xml").status_code == 404


def test_json_export_is_download(client):
    resp = client.get("/api/export/json")
    assert "attachment" in resp.headers["Content-Disposition"]
    assert resp.json["summary"]["packets"] > 0


def test_upload_valid_capture(client, sample_pcap):
    data = {"file": (io.BytesIO(sample_pcap.read_bytes()), "My Capture.pcap")}
    resp = client.post("/api/upload", data=data, content_type="multipart/form-data")
    assert resp.status_code == 201
    name = resp.json["file"]
    assert name == "My_Capture.pcap"
    assert client.get(f"/api/analysis?file={name}").status_code == 200
    assert client.delete(f"/api/files/{name}").status_code == 200
    assert client.get(f"/api/analysis?file={name}").status_code == 404


def test_upload_rejections(client):
    def post(content, name):
        return client.post("/api/upload", data={"file": (io.BytesIO(content), name)},
                           content_type="multipart/form-data")
    assert post(b"MZ\x90\x00", "evil.exe").status_code == 400
    assert post(b"not a pcap", "fake.pcap").status_code == 400
    # right magic number, but garbage afterwards -> rejected and not left behind
    corrupt = post(sorted(PCAP_MAGICS)[0] + b"\x00" * 10, "corrupt.pcap")
    assert corrupt.status_code == 422
    assert [f["name"] for f in client.get("/api/files").json["files"]] == ["network_traffic.pcap"]
    assert client.post("/api/upload").status_code == 400


def test_default_capture_cannot_be_deleted(client):
    assert client.delete("/api/files/network_traffic.pcap").status_code == 403


def test_empty_data_dir_gives_helpful_error(tmp_path):
    from app import create_app
    app = create_app({"DATA_DIR": tmp_path, "AUTO_SAMPLE": False, "TESTING": True})
    resp = app.test_client().get("/api/analysis")
    assert resp.status_code == 404 and "Upload" in resp.json["error"]


def test_auto_sample_creates_demo_capture(tmp_path):
    from app import create_app
    create_app({"DATA_DIR": tmp_path / "fresh", "AUTO_SAMPLE": True, "TESTING": True})
    assert (tmp_path / "fresh" / "network_traffic.pcap").exists()
