import random

from app.analyzer.utils import (
    initial_ttl, ip_scope, looks_like_credentials, os_guess, parse_http_request,
    parse_http_response, parse_tls_sni, server_port, shannon_entropy, size_bucket,
    tcp_flag_label,
)
from app.sample_data import client_hello


def test_ip_scope():
    assert ip_scope("192.168.1.5") == "private"
    assert ip_scope("8.8.8.8") == "public"
    assert ip_scope("224.0.0.251") == "multicast"
    assert ip_scope("255.255.255.255") == "broadcast"
    assert ip_scope("0.0.0.0") == "unspecified"
    assert ip_scope("fe80::1") == "link-local"
    assert ip_scope("not-an-ip") == "unknown"


def test_tcp_flag_labels():
    assert tcp_flag_label(0x02) == "SYN"
    assert tcp_flag_label(0x12) == "SYN-ACK"
    assert tcp_flag_label(0x18) == "PSH-ACK"
    assert tcp_flag_label(0x14) == "RST-ACK"
    assert tcp_flag_label(0) == "NULL"


def test_ttl_os_guess():
    assert initial_ttl(57) == 64
    assert initial_ttl(120) == 128
    assert os_guess(128) == "Windows"
    assert os_guess(None) == "Unknown"


def test_entropy_orders_random_above_words():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("rzauexsbhrxypibsytalcpvaaonqjdp7") > shannon_entropy("wikipedia")


def test_server_port_prefers_well_known():
    assert server_port(51000, 443) == 443
    assert server_port(443, 51000) == 443
    assert server_port(40000, 50000) == 40000


def test_size_bucket_edges():
    assert size_bucket(64) == "0-64"
    assert size_bucket(65) == "65-128"
    assert size_bucket(1518) == "1025-1518"
    assert size_bucket(9000) == "1519+"


def test_tls_sni_roundtrip():
    rng = random.Random(1)
    assert parse_tls_sni(client_hello("github.com", rng)) == "github.com"
    assert parse_tls_sni(client_hello("A.Example.ORG", rng)) == "a.example.org"


def test_tls_sni_rejects_garbage():
    assert parse_tls_sni(b"") is None
    assert parse_tls_sni(b"\x16\x03\x01\x00\x05\x01") is None
    assert parse_tls_sni(b"GET / HTTP/1.1\r\n\r\n") is None


def test_http_request_parsing_drops_query_string():
    raw = b"GET /a/b?token=SECRET HTTP/1.1\r\nHost: Example.com\r\nUser-Agent: curl\r\n\r\n"
    req = parse_http_request(raw)
    assert req["method"] == "GET" and req["path"] == "/a/b"
    assert req["host"] == "example.com" and not req["has_credentials"]
    assert "SECRET" not in str(req)


def test_http_credentials_detected_without_storing_value():
    raw = (b"POST /login HTTP/1.1\r\nHost: x\r\n\r\nuser=a&password=hunter2")
    req = parse_http_request(raw)
    assert req["has_credentials"] is True
    assert "hunter2" not in str(req)


def test_basic_auth_flag_and_non_http():
    raw = b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic abc\r\n\r\n"
    assert parse_http_request(raw)["basic_auth"] is True
    assert parse_http_request(b"\x16\x03\x01") is None
    assert parse_http_response(b"HTTP/1.1 404 Not Found\r\n") == 404
    assert parse_http_response(b"nope") is None


def test_looks_like_credentials():
    assert looks_like_credentials("a=1&passwd=x")
    assert not looks_like_credentials("username=bob&city=paris")
