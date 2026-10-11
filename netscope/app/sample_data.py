"""Synthetic traffic generator.

Builds a ~5 minute capture of a small office LAN: ordinary browsing, plain HTTP,
SSH, NTP and mDNS, plus a handful of deliberately suspicious behaviours so every
detection in NetScope has something to find. Everything is fake: the addresses
are invented and no real credentials are involved.
"""
from __future__ import annotations

import base64
import random
import struct
from datetime import datetime, timezone
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

GATEWAY = "192.168.1.1"
LAPTOP = "192.168.1.10"
PHONE = "192.168.1.23"
SERVER = "192.168.1.50"
PRINTER = "192.168.1.60"
ATTACKER = "192.168.1.66"
C2_HOST = "34.120.55.7"

MACS = {
    GATEWAY: "00:1a:2b:3c:4d:01", LAPTOP: "3c:22:fb:aa:10:10",
    PHONE: "f0:18:98:bb:23:23", SERVER: "b8:27:eb:cc:50:50",
    PRINTER: "00:80:77:dd:60:60", ATTACKER: "de:ad:be:ef:66:66",
}
TTLS = {GATEWAY: 64, LAPTOP: 128, PHONE: 64, SERVER: 64, PRINTER: 255, ATTACKER: 64}

SITES = {
    "www.wikipedia.org": "208.80.154.224", "github.com": "140.82.112.3",
    "cdn.jsdelivr.net": "151.101.1.229", "www.google.com": "142.250.80.46",
    "api.stackexchange.com": "104.18.43.42", "fonts.gstatic.com": "142.250.80.35",
    "news.ycombinator.com": "209.216.230.240", "www.python.org": "151.101.0.223",
}


class _Builder:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.packets = []
        self.base = datetime(2026, 10, 12, 8, 0, 0, tzinfo=timezone.utc).timestamp()

    def mac(self, ip):
        return MACS.get(ip, MACS[GATEWAY])

    def add(self, pkt, t):
        pkt.time = self.base + t
        self.packets.append(pkt)

    def frame(self, src, dst):
        return Ether(src=self.mac(src), dst=self.mac(dst)) / IP(
            src=src, dst=dst, ttl=TTLS.get(src, 56))

    def tcp(self, t, src, dst, sport, dport, flags, payload=b""):
        pkt = self.frame(src, dst) / TCP(sport=sport, dport=dport, flags=flags,
                                         seq=self.rng.randint(1, 2**31))
        if payload:
            pkt = pkt / Raw(load=payload)
        self.add(pkt, t)

    def udp(self, t, src, dst, sport, dport, payload=b"", dns=None):
        pkt = self.frame(src, dst) / UDP(sport=sport, dport=dport)
        pkt = pkt / dns if dns is not None else pkt / Raw(load=payload)
        self.add(pkt, t)

    def session(self, t, client, server, dport, up, down, gap=0.03):
        """Full TCP connection: handshake, alternating payloads, FIN teardown."""
        sport = self.rng.randint(40000, 60000)
        self.tcp(t, client, server, sport, dport, "S")
        self.tcp(t + gap, server, client, dport, sport, "SA")
        self.tcp(t + 2 * gap, client, server, sport, dport, "A")
        t += 3 * gap
        for i in range(max(len(up), len(down))):
            if i < len(up):
                t += gap
                self.tcp(t, client, server, sport, dport, "PA", up[i])
            if i < len(down):
                t += gap
                self.tcp(t, server, client, dport, sport, "PA", down[i])
        self.tcp(t + gap, client, server, sport, dport, "FA")
        self.tcp(t + 2 * gap, server, client, dport, sport, "FA")
        self.tcp(t + 3 * gap, client, server, sport, dport, "A")
        return t + 3 * gap

    def blob(self, n):
        return self.rng.randbytes(n)

    def dns_pair(self, t, client, resolver, name, ip=None, rcode=0, qtype="A"):
        sport, txid = self.rng.randint(40000, 60000), self.rng.randint(0, 65535)
        q = DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype=qtype))
        self.udp(t, client, resolver, sport, 53, dns=q)
        an = DNSRR(rrname=name, type="A", ttl=300, rdata=ip) if ip else None
        r = DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode,
                qd=DNSQR(qname=name, qtype=qtype), an=an)
        self.udp(t + 0.02, resolver, client, 53, sport, dns=r)

    def arp(self, t, op, psrc, hwsrc, pdst, hwdst="00:00:00:00:00:00", eth_dst=None):
        eth_dst = eth_dst or ("ff:ff:ff:ff:ff:ff" if op == 1 else hwdst)
        self.add(Ether(src=hwsrc, dst=eth_dst) / ARP(
            op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst=hwdst), t)


def client_hello(sni: str, rng: random.Random) -> bytes:
    """Minimal but well-formed TLS 1.2 ClientHello carrying an SNI extension."""
    host = sni.encode()
    sni_ext = (b"\x00\x00" + struct.pack("!H", len(host) + 5)
               + struct.pack("!H", len(host) + 3) + b"\x00"
               + struct.pack("!H", len(host)) + host)
    ciphers = bytes.fromhex("130113021303c02bc02f")
    body = (b"\x03\x03" + rng.randbytes(32) + b"\x00"
            + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00"
            + struct.pack("!H", len(sni_ext)) + sni_ext)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _tls_data(b: _Builder, n: int) -> bytes:
    return b"\x17\x03\x03" + struct.pack("!H", n) + b.blob(n)


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #
def _baseline_arp(b):
    b.arp(1.0, 1, LAPTOP, MACS[LAPTOP], GATEWAY)
    b.arp(1.01, 2, GATEWAY, MACS[GATEWAY], LAPTOP, MACS[LAPTOP])
    b.arp(2.0, 1, PHONE, MACS[PHONE], GATEWAY)
    b.arp(2.01, 2, GATEWAY, MACS[GATEWAY], PHONE, MACS[PHONE])
    b.arp(3.0, 2, PRINTER, MACS[PRINTER], PRINTER, "ff:ff:ff:ff:ff:ff")  # gratuitous


def _browsing(b):
    names = list(SITES)
    for _ in range(30):
        t = b.rng.uniform(5, 280)
        name = b.rng.choice(names)
        ip = SITES[name]
        b.dns_pair(t, LAPTOP, GATEWAY, name, ip)
        up = [client_hello(name, b.rng)] + [_tls_data(b, b.rng.randint(80, 400))
                                            for _ in range(b.rng.randint(1, 3))]
        down = [_tls_data(b, 1400) for _ in range(b.rng.randint(3, 9))]
        b.session(t + 0.1, LAPTOP, ip, 443, up, down)
    # phone streaming over UDP/443
    for i in range(160):
        t = 20 + i * 0.6
        b.udp(t, "142.250.80.46", PHONE, 443, 51515, b.blob(1200))
        if i % 4 == 0:
            b.udp(t + 0.01, PHONE, "142.250.80.46", 51515, 443, b.blob(90))


def _plain_http(b):
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetScopeDemo/1.0"
    get = (f"GET /index.html?session=abc123 HTTP/1.1\r\nHost: example.org\r\n"
           f"User-Agent: {ua}\r\n\r\n").encode()
    ok = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hello</html>"
    b.dns_pair(30, LAPTOP, GATEWAY, "example.org", "93.184.215.14")
    b.session(30.2, LAPTOP, "93.184.215.14", 80, [get], [ok])
    status = f"GET /status HTTP/1.1\r\nHost: intranet.local\r\nUser-Agent: {ua}\r\n\r\n".encode()
    b.session(45, LAPTOP, SERVER, 80, [status], [ok])
    body = "username=admin&password=changeme"
    login = (f"POST /login HTTP/1.1\r\nHost: intranet.local\r\nUser-Agent: {ua}\r\n"
             f"Content-Type: application/x-www-form-urlencoded\r\n"
             f"Content-Length: {len(body)}\r\n\r\n{body}").encode()
    redirect = b"HTTP/1.1 302 Found\r\nLocation: /dashboard\r\n\r\n"
    b.session(60, LAPTOP, SERVER, 80, [login], [redirect])
    missing = b"HTTP/1.1 404 Not Found\r\n\r\n"
    b.session(75, PHONE, SERVER, 80, [status], [missing])


def _misc_services(b):
    for i in range(3):
        t = 90 + i * 40
        b.udp(t, LAPTOP, "129.6.15.28", 52000 + i, 123, b"\x1b" + b"\x00" * 47)
        b.udp(t + 0.05, "129.6.15.28", LAPTOP, 123, 52000 + i, b"\x1c" + b"\x00" * 47)
    mdns = DNS(qr=1, aa=1, qd=None, an=DNSRR(rrname="printer.local", type="A",
                                              ttl=120, rdata=PRINTER))
    for i in range(3):
        pkt = (Ether(src=MACS[PRINTER], dst="01:00:5e:00:00:fb")
               / IP(src=PRINTER, dst="224.0.0.251", ttl=255)
               / UDP(sport=5353, dport=5353) / mdns)
        b.add(pkt, 100 + i * 30)
    ssh_up = [b"SSH-2.0-OpenSSH_9.6\r\n"] + [b.blob(96) for _ in range(6)]
    ssh_down = [b"SSH-2.0-OpenSSH_9.6\r\n"] + [b.blob(180) for _ in range(6)]
    b.session(110, LAPTOP, SERVER, 22, ssh_up, ssh_down)
    for i in range(4):
        sport = 7000 + i
        t = 130 + i
        b.add(b.frame(LAPTOP, "8.8.8.8") / ICMP(type=8, id=1, seq=i) / Raw(load=b"x" * 32), t)
        b.add(b.frame("8.8.8.8", LAPTOP) / ICMP(type=0, id=1, seq=i) / Raw(load=b"x" * 32), t + 0.02)
    telnet_up = [b"admin\r\n", b"printer123\r\n", b"status\r\n"]
    telnet_down = [b"login: ", b"Password: ", b"Ready.\r\n"]
    b.session(150, LAPTOP, PRINTER, 23, telnet_up, telnet_down)


def _beaconing(b):
    for i in range(9):
        t = 10 + i * 30 + b.rng.uniform(-0.15, 0.15)
        b.session(t, LAPTOP, C2_HOST, 4444, [b.blob(64)], [b.blob(64)], gap=0.05)


def _ping_sweep(b):
    for i in range(1, 31):
        ip = f"192.168.1.{i}"
        t = 140 + i * 0.1
        b.add(b.frame(ATTACKER, ip) / ICMP(type=8, id=9, seq=i), t)
        if ip in (GATEWAY, LAPTOP, PHONE, SERVER, PRINTER):
            b.add(b.frame(ip, ATTACKER) / ICMP(type=0, id=9, seq=i), t + 0.01)


def _port_scan(b):
    ports = [22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433,
             3306, 3389, 5432, 5900, 8080, 8443] + list(range(1000, 1012))
    open_ports = {22, 80, 443}
    for i, port in enumerate(ports):
        t = 150 + i * 0.05
        sport = 50000 + i
        b.tcp(t, ATTACKER, SERVER, sport, port, "S")
        if port in open_ports:
            b.tcp(t + 0.005, SERVER, ATTACKER, port, sport, "SA")
            b.tcp(t + 0.01, ATTACKER, SERVER, sport, port, "R")
        else:
            b.tcp(t + 0.005, SERVER, ATTACKER, port, sport, "RA")


def _arp_spoof(b):
    for i in range(6):
        b.arp(120 + i * 12, 2, GATEWAY, MACS[ATTACKER], LAPTOP, MACS[LAPTOP])


def _dns_tunnel(b):
    for i in range(14):
        raw = base64.b32encode(b.blob(25)).decode().rstrip("=").lower()
        b.dns_pair(200 + i * 4, LAPTOP, GATEWAY, f"{raw}.t.exfil-c2.test", None)


def _dga(b):
    letters = "abcdefghijklmnopqrstuvwxyz"
    for i in range(14):
        name = "".join(b.rng.choice(letters) for _ in range(12)) + ".com"
        b.dns_pair(220 + i * 2, PHONE, GATEWAY, name, None, rcode=3)


def generate(path, seed: int = 7) -> Path:
    """Write the demo capture to *path* and return it."""
    b = _Builder(seed)
    for scenario in (_baseline_arp, _browsing, _plain_http, _misc_services, _beaconing,
                     _ping_sweep, _port_scan, _arp_spoof, _dns_tunnel, _dga):
        scenario(b)
    b.packets.sort(key=lambda p: float(p.time))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), b.packets)
    return path
