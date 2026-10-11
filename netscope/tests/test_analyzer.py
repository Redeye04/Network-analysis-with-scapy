import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from app.analyzer import AnalysisError, analyze_file
from app.sample_data import ATTACKER, GATEWAY, LAPTOP, SERVER


def titles(result):
    return {f["title"] for f in result["security"]["findings"]}


def test_no_malformed_packets_and_totals_consistent(analysis):
    assert analysis["meta"]["malformed_packets"] == 0
    s = analysis["summary"]
    assert s["packets"] == sum(p["packets"] for p in analysis["protocols"])
    assert s["bytes"] == sum(p["bytes"] for p in analysis["protocols"])
    assert s["packets"] == sum(b["count"] for b in analysis["packet_sizes"])
    assert s["packets"] == sum(p["packets"] for p in analysis["timeline"]["points"])


def test_expected_protocols(analysis):
    names = {p["name"] for p in analysis["protocols"]}
    assert {"TCP", "UDP", "ICMP", "ARP"} <= names
    apps = {a["name"] for a in analysis["applications"]}
    assert {"DNS", "HTTP", "HTTPS/TLS", "SSH", "NTP"} <= apps


def test_expected_findings(analysis):
    assert {"Possible ARP spoofing", "TCP port scan", "Internal host sweep",
            "Possible DNS tunnelling", "Burst of NXDOMAIN responses",
            "Credentials sent over plain HTTP", "Cleartext Telnet traffic",
            "Connection to port 4444", "Regular beaconing pattern"} <= titles(analysis)


def test_findings_sorted_by_severity_and_scored(analysis):
    order = ["critical", "high", "medium", "low", "info"]
    ranks = [order.index(f["severity"]) for f in analysis["security"]["findings"]]
    assert ranks == sorted(ranks)
    assert 0 < analysis["security"]["risk_score"] <= 100


def test_port_scan_evidence(analysis):
    scan = next(f for f in analysis["security"]["findings"] if f["title"] == "TCP port scan")
    assert set(scan["hosts"]) == {ATTACKER, SERVER}
    assert scan["evidence"]["ports_probed"] >= 30
    assert scan["evidence"]["open_ports_found"] == [22, 80, 443]


def test_arp_conflict_reported(analysis):
    row = next(r for r in analysis["arp"]["table"] if r["ip"] == GATEWAY)
    assert row["conflict"] and len(row["macs"]) == 2
    gateway = next(h for h in analysis["hosts"] if h["ip"] == GATEWAY)
    assert len(gateway["macs"]) == 2


def test_secrets_never_appear_in_output(analysis):
    blob = str(analysis)
    assert "changeme" not in blob and "session=abc123" not in blob


def test_dns_and_tls_details(analysis):
    dns = analysis["dns"]
    assert dns["queries"] > 0 and dns["nxdomain"] >= 10
    assert dns["suspicious"][0]["domain"] == "exfil-c2.test"
    assert any(r["name"] == "github.com" for r in dns["resolutions"])
    assert "github.com" in {s["name"] for s in analysis["tls"]["server_names"]}
    methods = {(r["method"], r["host"]) for r in analysis["http"]["requests"]}
    assert ("POST", "intranet.local") in methods
    assert {"200", "302", "404"} <= {c["code"] for c in analysis["http"]["status_codes"]}


def test_host_classification(analysis):
    hosts = {h["ip"]: h for h in analysis["hosts"]}
    assert hosts[LAPTOP]["scope"] == "private" and hosts[LAPTOP]["os_guess"] == "Windows"
    assert "SSH" in hosts[SERVER]["services"]
    assert all(h["scope"] not in {"multicast", "broadcast"} for h in hosts.values())


def test_graph_links_reference_nodes(analysis):
    ids = {n["id"] for n in analysis["graph"]["nodes"]}
    assert ids and analysis["graph"]["links"]
    for link in analysis["graph"]["links"]:
        assert link["source"] in ids and link["target"] in ids


def test_timeline_bucket_covers_capture(analysis):
    t = analysis["timeline"]
    assert len(t["points"]) <= 125
    assert t["points"][0]["t"] == t["start"]


def test_large_upload_threshold_is_configurable(sample_pcap):
    default = analyze_file(sample_pcap)
    tuned = analyze_file(sample_pcap, {"exfil_bytes": 1000})
    assert "Large outbound transfer" not in titles(default)
    assert "Large outbound transfer" in titles(tuned)


def test_max_packets_truncates(sample_pcap):
    r = analyze_file(sample_pcap, max_packets=50)
    assert r["summary"]["packets"] == 50 and r["meta"]["truncated"] is True


def test_missing_and_invalid_files(tmp_path):
    with pytest.raises(AnalysisError):
        analyze_file(tmp_path / "nope.pcap")
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture file at all")
    with pytest.raises(AnalysisError):
        analyze_file(junk)
    empty = tmp_path / "empty.pcap"
    wrpcap(str(empty), [])
    with pytest.raises(AnalysisError):
        analyze_file(empty)


def test_clean_capture_has_no_findings(tmp_path):
    pkts = [Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=40000, dport=22, flags="A")
            for _ in range(5)]
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000 + i
    path = tmp_path / "clean.pcap"
    wrpcap(str(path), pkts)
    r = analyze_file(path)
    assert r["security"]["findings"] == [] and r["summary"]["risk_score"] == 0
