"""Small, dependency-free helpers shared by the analyzer modules."""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from functools import lru_cache
from typing import Optional

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1883: "MQTT", 1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
    5353: "mDNS", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Normalise service names into the application buckets shown on the dashboard.
APP_ALIASES = {"HTTPS": "HTTPS/TLS", "HTTPS-Alt": "HTTPS/TLS", "HTTP-Alt": "HTTP",
               "mDNS": "DNS", "SMTPS": "SMTP", "DHCP": "DHCP"}

# Ports frequently associated with backdoors, reverse shells or C2 channels.
SUSPICIOUS_PORTS = {
    1337: "common backdoor / 'leet' port",
    4444: "default Metasploit / reverse-shell listener",
    5555: "Android Debug Bridge / common RAT port",
    6667: "IRC (sometimes used for botnet C2)",
    9001: "Tor relay (ORPort)",
    12345: "NetBus backdoor",
    31337: "traditional 'Back Orifice' backdoor port",
}

NON_UNICAST_SCOPES = {"multicast", "broadcast", "unspecified"}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ",
                b"PATCH ", b"CONNECT ")

_CRED_RE = re.compile(r"(?:^|[&;?\s])(?:pass(?:word|wd)?|pwd|secret)=", re.I)

_TCP_FLAG_BITS = ((0x02, "SYN"), (0x01, "FIN"), (0x04, "RST"),
                  (0x08, "PSH"), (0x20, "URG"), (0x10, "ACK"))

DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
              16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}
ICMP_TYPES = {0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
              8: "Echo Request", 11: "Time Exceeded"}
ARP_OPS = {1: "who-has (request)", 2: "is-at (reply)"}

SIZE_BUCKETS = ((64, "0-64"), (128, "65-128"), (256, "129-256"), (512, "257-512"),
                (1024, "513-1024"), (1518, "1025-1518"))
SIZE_BUCKET_LABELS = [label for _, label in SIZE_BUCKETS] + ["1519+"]


def service_name(port: int) -> str:
    return WELL_KNOWN_PORTS.get(port, str(port))


def app_label(service: str) -> str:
    return APP_ALIASES.get(service, service)


def server_port(sport: int, dport: int) -> int:
    """Best guess at which side of a connection is the server."""
    if dport in WELL_KNOWN_PORTS:
        return dport
    if sport in WELL_KNOWN_PORTS:
        return sport
    return min(sport, dport)


@lru_cache(maxsize=65536)
def ip_scope(ip: str) -> str:
    """Classify an address: private, public, multicast, broadcast, ..."""
    if ip == "255.255.255.255":
        return "broadcast"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_multicast:
        return "multicast"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    return "public" if addr.is_global else "private"


def is_private(ip: str) -> bool:
    return ip_scope(ip) in {"private", "loopback", "link-local"}


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def initial_ttl(ttl: int) -> int:
    for candidate in (32, 64, 128, 255):
        if ttl <= candidate:
            return candidate
    return 255


def os_guess(ttl: Optional[int]) -> str:
    if not ttl:
        return "Unknown"
    return {32: "Embedded / legacy", 64: "Linux / macOS / Android",
            128: "Windows", 255: "Network device / Solaris"}[initial_ttl(ttl)]


def tcp_flag_label(flags: int) -> str:
    names = [name for bit, name in _TCP_FLAG_BITS if flags & bit]
    return "-".join(names) if names else "NULL"


def size_bucket(size: int) -> str:
    for limit, label in SIZE_BUCKETS:
        if size <= limit:
            return label
    return "1519+"


def to_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def iso_time(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Payload parsers (deliberately forgiving: they return None on anything odd)
# --------------------------------------------------------------------------- #
def looks_like_tls(payload: bytes) -> bool:
    return (len(payload) >= 5 and payload[0] in (0x14, 0x15, 0x16, 0x17)
            and payload[1] == 3 and payload[2] <= 4)


def parse_tls_sni(data: bytes) -> Optional[str]:
    """Extract the Server Name Indication from a TLS ClientHello."""
    try:
        if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
            return None
        pos = 9 + 2 + 32                       # record + handshake hdr, version, random
        pos += 1 + data[pos]                   # session id
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")   # cipher suites
        pos += 1 + data[pos]                   # compression methods
        ext_total = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(pos + ext_total, len(data))
        while pos + 4 <= end:
            etype = int.from_bytes(data[pos:pos + 2], "big")
            elen = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0:                     # server_name
                name_len = int.from_bytes(data[pos + 3:pos + 5], "big")
                name = data[pos + 5:pos + 5 + name_len].decode("ascii", "ignore")
                return name.lower() or None
            pos += elen
    except (IndexError, ValueError):
        return None
    return None


def parse_http_request(payload: bytes) -> Optional[dict]:
    if not payload.startswith(HTTP_METHODS):
        return None
    head, _, body = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(" ")
    if len(parts) < 3 or not parts[2].startswith("HTTP/"):
        return None
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if sep:
            headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
    # Query strings may carry tokens, so they are dropped before anything is stored.
    path = parts[1].split("?", 1)[0][:120]
    return {
        "method": parts[0],
        "path": path,
        "host": (headers.get("host") or "").lower() or None,
        "user_agent": (headers.get("user-agent") or "")[:160] or None,
        "basic_auth": headers.get("authorization", "").lower().startswith("basic "),
        "has_credentials": looks_like_credentials(body.decode("latin-1")),
    }


def parse_http_response(payload: bytes) -> Optional[int]:
    if not payload.startswith(b"HTTP/1."):
        return None
    try:
        return int(payload.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


def looks_like_credentials(text: str) -> bool:
    """True when a form body appears to carry a password field (value never kept)."""
    return bool(_CRED_RE.search(text))
