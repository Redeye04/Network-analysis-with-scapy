"""Single-pass, streaming PCAP analyzer built on scapy."""
from __future__ import annotations

import struct
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator

from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import NoPayload, Raw
from scapy.utils import PcapReader

from . import detections
from .utils import (
    ARP_OPS, DNS_QTYPES, DNS_RCODES, ICMP_TYPES, NON_UNICAST_SCOPES, SIZE_BUCKET_LABELS,
    WELL_KNOWN_PORTS, app_label, initial_ttl, ip_scope, iso_time, looks_like_tls,
    os_guess, parse_http_request, parse_http_response, parse_tls_sni, server_port,
    service_name, shannon_entropy, size_bucket, tcp_flag_label, to_text,
)

BUCKET_CHOICES = (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200,
                  14400, 43200, 86400)
INSECURE_LABELS = {"Telnet", "FTP", "TFTP", "POP3", "IMAP", "SMTP", "SNMP", "HTTP"}
MAX_TIMES_PER_KEY = 1000


class AnalysisError(Exception):
    """Raised when a capture cannot be read or contains nothing to analyze."""


class HostStats:
    __slots__ = ("pkts_sent", "pkts_recv", "bytes_sent", "bytes_recv", "macs", "ttls",
                 "first_seen", "last_seen", "peers", "services")

    def __init__(self):
        self.pkts_sent = self.pkts_recv = self.bytes_sent = self.bytes_recv = 0
        self.macs: set[str] = set()
        self.ttls: Counter = Counter()
        self.first_seen = self.last_seen = None
        self.peers: set[str] = set()
        self.services: Counter = Counter()

    def touch(self, ts: float) -> None:
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


class FlowStats:
    __slots__ = ("a", "b", "pkts", "bytes", "bytes_ab", "protos", "first", "last")

    def __init__(self, a: str, b: str, ts: float):
        self.a, self.b = a, b
        self.pkts = self.bytes = self.bytes_ab = 0
        self.protos: set[str] = set()
        self.first = self.last = ts


def iter_records(field) -> Iterator[Any]:
    """Yield DNS question/answer records across scapy versions (chain or list)."""
    if field is None:
        return
    if isinstance(field, (list, tuple)):
        yield from field
        return
    node, guard = field, 0
    while node is not None and not isinstance(node, NoPayload) and guard < 64:
        if getattr(node, "qname", None) is None and getattr(node, "rrname", None) is None:
            break
        yield node
        node = node.payload
        guard += 1


class PcapAnalyzer:
    def __init__(self, path, thresholds: dict | None = None, max_packets: int = 0):
        self.path = Path(path)
        self.thresholds = {**detections.DEFAULT_THRESHOLDS, **(thresholds or {})}
        self.max_packets = max_packets
        self._reset()

    # ------------------------------------------------------------------ state
    def _reset(self) -> None:
        self.total_packets = self.total_bytes = 0
        self.first_ts = self.last_ts = None
        self.min_size = self.max_size = None
        self.truncated = False
        self.malformed = 0
        self.first_error = None
        self.broadcast_pkts = self.multicast_pkts = 0

        self.proto_pkts: Counter = Counter()
        self.proto_bytes: Counter = Counter()
        self.app_pkts: Counter = Counter()
        self.app_bytes: Counter = Counter()
        self.size_hist: Counter = Counter()
        self.timeline: dict[int, list[int]] = defaultdict(lambda: [0, 0, 0, 0, 0])
        self.port_pkts: Counter = Counter()

        self.hosts: dict[str, HostStats] = defaultdict(HostStats)
        self.flows: dict[tuple, FlowStats] = {}
        self.comm_pkts: Counter = Counter()
        self.comm_bytes: Counter = Counter()

        self.tcp_flags: Counter = Counter()
        self.syn_count = self.synack_count = self.rst_count = self.fin_count = 0
        self.scan_ports: dict[tuple, set] = defaultdict(set)
        self.open_ports: dict[str, set] = defaultdict(set)
        self.syn_sweep: dict[str, set] = defaultdict(set)
        self.icmp_sweep: dict[str, set] = defaultdict(set)
        self.syn_dst_ports: Counter = Counter()
        self.syn_times: dict[tuple, list] = defaultdict(list)
        self.rst_sent: Counter = Counter()
        self.tcp_sent: Counter = Counter()

        self.dns_names: Counter = Counter()
        self.dns_qtypes: Counter = Counter()
        self.dns_rcodes: Counter = Counter()
        self.dns_clients: Counter = Counter()
        self.dns_servers: Counter = Counter()
        self.dns_resolved: dict[str, set] = {}
        self.dns_queries = self.dns_responses = 0
        self.nxdomain_by_client: Counter = Counter()
        self.suspicious_dns: dict[str, Counter] = defaultdict(Counter)
        self.suspicious_dns_clients: dict[str, set] = defaultdict(set)

        self.http_requests: Counter = Counter()
        self.http_req_clients: dict[tuple, set] = defaultdict(set)
        self.http_hosts: Counter = Counter()
        self.http_agents: Counter = Counter()
        self.http_status: Counter = Counter()
        self.http_cred_events: dict[tuple, dict] = {}

        self.tls_sni: Counter = Counter()
        self.tls_clients: dict[str, set] = defaultdict(set)
        self.tls_records = 0

        self.arp_map: dict[str, set] = defaultdict(set)
        self.arp_pairs: Counter = Counter()
        self.arp_ops: Counter = Counter()
        self.arp_gratuitous = 0

        self.icmp_types: Counter = Counter()
        self.insecure: dict[str, Counter] = defaultdict(Counter)

    # ------------------------------------------------------------------- run
    def analyze(self) -> dict:
        started = time.perf_counter()
        if not self.path.exists():
            raise AnalysisError(f"File not found: {self.path.name}")
        self._reset()
        try:
            with PcapReader(str(self.path)) as reader:
                for pkt in reader:
                    if self.max_packets and self.total_packets >= self.max_packets:
                        self.truncated = True
                        break
                    try:
                        self._process(pkt)
                    except Exception as exc:  # one bad packet must not sink the file
                        self.malformed += 1
                        self.first_error = self.first_error or repr(exc)
        except (Scapy_Exception, OSError, struct.error, EOFError) as exc:
            raise AnalysisError(f"Could not read capture: {exc}") from exc
        if not self.total_packets:
            raise AnalysisError("The capture contains no readable packets")
        return self._build(time.perf_counter() - started)

    # --------------------------------------------------------------- packets
    def _process(self, pkt) -> None:
        ts = float(pkt.time)
        size = getattr(pkt, "wirelen", None) or len(pkt)
        self.total_packets += 1
        self.total_bytes += size
        self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        self.min_size = size if self.min_size is None else min(self.min_size, size)
        self.max_size = size if self.max_size is None else max(self.max_size, size)
        self.size_hist[size_bucket(size)] += 1

        eth = pkt.getlayer(Ether)
        if eth is not None:
            dst_mac = eth.dst.lower()
            if dst_mac == "ff:ff:ff:ff:ff:ff":
                self.broadcast_pkts += 1
            elif int(dst_mac[:2], 16) & 1:
                self.multicast_pkts += 1

        ip4 = pkt.getlayer(IP)
        ip6 = None if ip4 is not None else pkt.getlayer(IPv6)
        src_ip = dst_ip = ttl = l4 = None
        if ip4 is not None:
            src_ip, dst_ip, ttl, l4 = ip4.src, ip4.dst, ip4.ttl, ip4.proto
        elif ip6 is not None:
            src_ip, dst_ip, ttl, l4 = ip6.src, ip6.dst, ip6.hlim, ip6.nh

        tcp = pkt.getlayer(TCP) if l4 == 6 else None
        udp = pkt.getlayer(UDP) if l4 == 17 else None
        arp = pkt.getlayer(ARP) if src_ip is None else None
        if tcp is not None:
            proto = "TCP"
        elif udp is not None:
            proto = "UDP"
        elif arp is not None:
            proto = "ARP"
        elif l4 == 1:
            proto = "ICMP"
        elif l4 == 58:
            proto = "ICMPv6"
        else:
            proto = "Other"
        self.proto_pkts[proto] += 1
        self.proto_bytes[proto] += size

        row = self.timeline[int(ts)]
        row[0] += 1
        row[1] += size
        row[2 if proto == "TCP" else 3 if proto == "UDP" else 4] += 1

        if arp is not None:
            self._arp(arp)
        if src_ip is None:
            return

        src_scope, dst_scope = ip_scope(src_ip), ip_scope(dst_ip)
        self.comm_pkts[(src_ip, dst_ip)] += 1
        self.comm_bytes[(src_ip, dst_ip)] += size
        uni_src = src_scope not in NON_UNICAST_SCOPES
        uni_dst = dst_scope not in NON_UNICAST_SCOPES
        if uni_src:
            h = self.hosts[src_ip]
            h.pkts_sent += 1
            h.bytes_sent += size
            h.touch(ts)
            h.peers.add(dst_ip)
            if ttl:
                h.ttls[ttl] += 1
            if eth is not None and src_scope in ("private", "link-local"):
                h.macs.add(eth.src.lower())
        if uni_dst:
            h = self.hosts[dst_ip]
            h.pkts_recv += 1
            h.bytes_recv += size
            h.touch(ts)
            h.peers.add(src_ip)
        if uni_src and uni_dst:
            key = (src_ip, dst_ip) if src_ip <= dst_ip else (dst_ip, src_ip)
            flow = self.flows.get(key)
            if flow is None:
                flow = self.flows[key] = FlowStats(src_ip, dst_ip, ts)
            flow.pkts += 1
            flow.bytes += size
            flow.protos.add(proto)
            flow.first, flow.last = min(flow.first, ts), max(flow.last, ts)
            if src_ip == flow.a:
                flow.bytes_ab += size

        if tcp is not None:
            self._tcp(pkt, tcp, src_ip, dst_ip, ts, size)
        elif udp is not None:
            self._udp(pkt, udp, src_ip, dst_ip, size)
        else:
            self.app_pkts[proto] += 1
            self.app_bytes[proto] += size
            if proto == "ICMP":
                self._icmp(pkt, src_ip, dst_ip)

    # -------------------------------------------------------------- protocols
    def _arp(self, arp) -> None:
        op = int(arp.op)
        self.arp_ops[op] += 1
        psrc, hwsrc = arp.psrc, arp.hwsrc.lower()
        if psrc and psrc != "0.0.0.0":
            self.arp_map[psrc].add(hwsrc)
            self.arp_pairs[(psrc, hwsrc)] += 1
            if ip_scope(psrc) in ("private", "link-local"):
                self.hosts[psrc].macs.add(hwsrc)
        if psrc == arp.pdst:
            self.arp_gratuitous += 1

    def _icmp(self, pkt, src_ip: str, dst_ip: str) -> None:
        icmp = pkt.getlayer(ICMP)
        if icmp is None:
            return
        kind = int(icmp.type)
        self.icmp_types[ICMP_TYPES.get(kind, f"Type {kind}")] += 1
        # Sweeps are only counted against internal targets: browsers legitimately
        # touch hundreds of public hosts, but rarely probe many LAN machines.
        if kind == 8 and ip_scope(dst_ip) == "private":
            self.icmp_sweep[src_ip].add(dst_ip)

    def _tcp(self, pkt, tcp, src_ip, dst_ip, ts, size) -> None:
        sport, dport, flags = int(tcp.sport), int(tcp.dport), int(tcp.flags)
        self.tcp_flags[tcp_flag_label(flags)] += 1
        self.tcp_sent[src_ip] += 1
        syn, ack = flags & 0x02, flags & 0x10
        if syn and not ack:
            self.syn_count += 1
            self.scan_ports[(src_ip, dst_ip)].add(dport)
            self.syn_dst_ports[(src_ip, dst_ip, dport)] += 1
            times = self.syn_times[(src_ip, dst_ip, dport)]
            if len(times) < MAX_TIMES_PER_KEY:
                times.append(ts)
            if ip_scope(dst_ip) == "private":
                self.syn_sweep[src_ip].add(dst_ip)
        elif syn and ack:
            self.synack_count += 1
            self.open_ports[src_ip].add(sport)
        if flags & 0x04:
            self.rst_count += 1
            self.rst_sent[src_ip] += 1
        if flags & 0x01:
            self.fin_count += 1

        srv = server_port(sport, dport)
        to_server = dport == srv
        raw = pkt.getlayer(Raw)
        payload = bytes(raw.load) if raw is not None else b""
        service = service_name(srv)
        label = app_label(service) if srv in WELL_KNOWN_PORTS else "Other TCP"

        if payload:
            request = parse_http_request(payload)
            status = None if request else parse_http_response(payload)
            if request:
                label = "HTTP"
                self._http_request(request, src_ip, dst_ip)
            elif status is not None:
                label = "HTTP"
                self.http_status[str(status)] += 1
            elif looks_like_tls(payload):
                label = "HTTPS/TLS"
                self.tls_records += 1
                sni = parse_tls_sni(payload)
                if sni:
                    self.tls_sni[sni] += 1
                    self.tls_clients[sni].add(src_ip)

        self.app_pkts[label] += 1
        self.app_bytes[label] += size
        self.port_pkts[("TCP", srv)] += 1
        if srv in WELL_KNOWN_PORTS:
            self._service(dst_ip if to_server else src_ip, service)
        if to_server and payload and label in INSECURE_LABELS:
            self.insecure[label][f"{src_ip} -> {dst_ip}"] += 1

    def _service(self, server_ip: str, service: str) -> None:
        # Multicast/broadcast addresses are never hosts, so they get no service list.
        if ip_scope(server_ip) not in NON_UNICAST_SCOPES:
            self.hosts[server_ip].services[service] += 1

    def _http_request(self, req: dict, src_ip: str, dst_ip: str) -> None:
        host = req["host"] or dst_ip
        key = (req["method"], host, req["path"])
        self.http_requests[key] += 1
        self.http_req_clients[key].add(src_ip)
        self.http_hosts[host] += 1
        if req["user_agent"]:
            self.http_agents[req["user_agent"]] += 1
        reason = ("password field in request body" if req["has_credentials"]
                  else "HTTP Basic authentication header" if req["basic_auth"] else None)
        if reason and (src_ip, host) not in self.http_cred_events \
                and len(self.http_cred_events) < 50:
            self.http_cred_events[(src_ip, host)] = {
                "dst": dst_ip, "path": req["path"], "method": req["method"],
                "reason": reason}

    def _udp(self, pkt, udp, src_ip, dst_ip, size) -> None:
        sport, dport = int(udp.sport), int(udp.dport)
        srv = server_port(sport, dport)
        service = service_name(srv)
        dns = pkt.getlayer(DNS)
        if dns is not None:
            label = "DNS"
            self._dns(dns, src_ip, dst_ip)
        else:
            label = app_label(service) if srv in WELL_KNOWN_PORTS else "Other UDP"
        self.app_pkts[label] += 1
        self.app_bytes[label] += size
        self.port_pkts[("UDP", srv)] += 1
        if srv in WELL_KNOWN_PORTS:
            self._service(dst_ip if dport == srv else src_ip, service)
        if dport == srv and label in INSECURE_LABELS:
            self.insecure[label][f"{src_ip} -> {dst_ip}"] += 1

    def _dns(self, dns, src_ip: str, dst_ip: str) -> None:
        questions = list(iter_records(dns.qd))
        name = to_text(questions[0].qname).rstrip(".").lower() if questions else None
        if int(dns.qr) == 0:
            self.dns_queries += 1
            self.dns_clients[src_ip] += 1
            if not name:
                return
            self.dns_names[name] += 1
            qtype = int(questions[0].qtype)
            self.dns_qtypes[DNS_QTYPES.get(qtype, f"TYPE{qtype}")] += 1
            if self._suspicious_name(name):
                base = ".".join(name.split(".")[-2:])
                self.suspicious_dns[base][name] += 1
                self.suspicious_dns_clients[base].add(src_ip)
            return
        self.dns_responses += 1
        self.dns_servers[src_ip] += 1
        rcode = int(dns.rcode)
        self.dns_rcodes[DNS_RCODES.get(rcode, f"RCODE{rcode}")] += 1
        if rcode == 3:
            self.nxdomain_by_client[dst_ip] += 1
        for rr in iter_records(dns.an):
            try:
                if int(rr.type) in (1, 28) and len(self.dns_resolved) < 2000:
                    self.dns_resolved.setdefault(
                        to_text(rr.rrname).rstrip(".").lower(), set()).add(to_text(rr.rdata))
            except (AttributeError, TypeError, ValueError):
                continue

    def _suspicious_name(self, name: str) -> bool:
        t = self.thresholds
        labels = name.split(".")
        longest = max(labels, key=len)
        if len(name) >= t["dns_name_length"]:
            return True
        return (len(longest) >= t["dns_label_length"]
                and shannon_entropy(longest) >= t["dns_label_entropy"])

    # ---------------------------------------------------------------- results
    def _timeline(self) -> dict:
        start = int(self.first_ts)
        span = max(int(self.last_ts) - start + 1, 1)
        bucket = next((b for b in BUCKET_CHOICES if span / b <= 120), BUCKET_CHOICES[-1])
        rows = [[0] * 5 for _ in range(span // bucket + 1)]
        for sec, vals in self.timeline.items():
            target = rows[(sec - start) // bucket]
            for i, v in enumerate(vals):
                target[i] += v
        return {"bucket_seconds": bucket, "start": start,
                "points": [{"t": start + i * bucket, "packets": r[0], "bytes": r[1],
                            "tcp": r[2], "udp": r[3], "other": r[4]}
                           for i, r in enumerate(rows)]}

    def _hosts_out(self) -> list[dict]:
        out = []
        for ip, h in self.hosts.items():
            ttl = h.ttls.most_common(1)[0][0] if h.ttls else None
            out.append({
                "ip": ip, "scope": ip_scope(ip), "os_guess": os_guess(ttl),
                "ttl": initial_ttl(ttl) if ttl else None,
                "macs": sorted(h.macs), "peers": len(h.peers),
                "services": [s for s, _ in h.services.most_common(6)],
                "packets_sent": h.pkts_sent, "packets_recv": h.pkts_recv,
                "bytes_sent": h.bytes_sent, "bytes_recv": h.bytes_recv,
                "total_bytes": h.bytes_sent + h.bytes_recv,
                "first_seen": iso_time(h.first_seen) if h.first_seen else None,
                "last_seen": iso_time(h.last_seen) if h.last_seen else None,
            })
        out.sort(key=lambda r: r["total_bytes"], reverse=True)
        return out[:300]

    def _build(self, elapsed: float) -> dict:
        duration = self.last_ts - self.first_ts
        secs = max(duration, 1.0)
        findings = detections.detect_all(self, self.thresholds)
        score = detections.risk_score(findings)
        counts = Counter(f["severity"] for f in findings)
        hosts = self._hosts_out()
        flagged = {h for f in findings for h in f["hosts"]}

        flows = sorted(self.flows.values(), key=lambda f: f.bytes, reverse=True)
        conversations = [{
            "a": f.a, "b": f.b, "protocols": sorted(f.protos), "packets": f.pkts,
            "bytes": f.bytes, "bytes_a_to_b": f.bytes_ab,
            "bytes_b_to_a": f.bytes - f.bytes_ab,
            "duration_seconds": round(f.last - f.first, 3),
            "first_seen": iso_time(f.first)} for f in flows[:300]]

        node_ips = [h["ip"] for h in hosts[:60]]
        node_set = set(node_ips)
        by_ip = {h["ip"]: h for h in hosts}
        graph = {
            "nodes": [{"id": ip, "scope": by_ip[ip]["scope"],
                       "bytes": by_ip[ip]["total_bytes"], "os": by_ip[ip]["os_guess"],
                       "flagged": ip in flagged} for ip in node_ips],
            "links": [{"source": f.a, "target": f.b, "packets": f.pkts, "bytes": f.bytes,
                       "protocols": sorted(f.protos)}
                      for f in flows if f.a in node_set and f.b in node_set][:300],
        }

        protocols = [{"name": k, "packets": v, "bytes": self.proto_bytes[k]}
                     for k, v in self.proto_pkts.most_common()]
        apps = [{"name": k, "packets": v, "bytes": self.app_bytes[k]}
                for k, v in self.app_pkts.most_common()]
        ports = [{"port": p, "protocol": proto, "service": service_name(p), "packets": n}
                 for (proto, p), n in self.port_pkts.most_common(25)]

        web_requests = [{
            "method": m, "host": h, "path": p, "count": n,
            "clients": sorted(self.http_req_clients[(m, h, p)])[:5]}
            for (m, h, p), n in self.http_requests.most_common(100)]

        arp_table = [{"ip": ip, "macs": sorted(macs), "conflict": len(macs) > 1,
                      "packets": sum(self.arp_pairs[(ip, m)] for m in macs)}
                     for ip, macs in sorted(self.arp_map.items())]

        suspicious = [{"domain": base, "distinct_names": len(names),
                       "queries": sum(names.values()),
                       "sample": next(iter(names))[:80]}
                      for base, names in self.suspicious_dns.items()]
        suspicious.sort(key=lambda r: r["queries"], reverse=True)

        return {
            "meta": {"file": self.path.name, "size_bytes": self.path.stat().st_size,
                     "analysis_seconds": round(elapsed, 3), "truncated": self.truncated,
                     "malformed_packets": self.malformed},
            "summary": {
                "packets": self.total_packets, "bytes": self.total_bytes,
                "start": iso_time(self.first_ts), "end": iso_time(self.last_ts),
                "duration_seconds": round(duration, 3),
                "avg_packet_size": round(self.total_bytes / self.total_packets, 1),
                "min_packet_size": self.min_size, "max_packet_size": self.max_size,
                "avg_packets_per_second": round(self.total_packets / secs, 2),
                "avg_bits_per_second": round(self.total_bytes * 8 / secs, 1),
                "peak_packets_per_second": max(r[0] for r in self.timeline.values()),
                "peak_bytes_per_second": max(r[1] for r in self.timeline.values()),
                "unique_hosts": len(self.hosts), "unique_conversations": len(self.flows),
                "unique_domains": len(self.dns_names),
                "broadcast_packets": self.broadcast_pkts,
                "multicast_packets": self.multicast_pkts,
                "risk_score": score, "risk_level": detections.risk_level(score),
                "findings": len(findings)},
            "protocols": protocols,
            "applications": apps,
            "timeline": self._timeline(),
            "packet_sizes": [{"range": label, "count": self.size_hist.get(label, 0)}
                             for label in SIZE_BUCKET_LABELS],
            "hosts": hosts,
            "conversations": conversations,
            "communications": [{"src": s, "dst": d, "packets": n,
                                "bytes": self.comm_bytes[(s, d)]}
                               for (s, d), n in self.comm_pkts.most_common(25)],
            "ports": ports,
            "tcp": {"flags": [{"name": k, "packets": v}
                              for k, v in self.tcp_flags.most_common()],
                    "syn": self.syn_count, "syn_ack": self.synack_count,
                    "rst": self.rst_count, "fin": self.fin_count,
                    "rst_ratio": round(self.rst_count / max(self.proto_pkts["TCP"], 1), 4)},
            "dns": {
                "queries": self.dns_queries, "responses": self.dns_responses,
                "unique_domains": len(self.dns_names),
                "nxdomain": self.dns_rcodes.get("NXDOMAIN", 0),
                "top_domains": [{"name": n, "count": c}
                                for n, c in self.dns_names.most_common(25)],
                "query_types": [{"name": n, "count": c}
                                for n, c in self.dns_qtypes.most_common()],
                "response_codes": [{"name": n, "count": c}
                                   for n, c in self.dns_rcodes.most_common()],
                "servers": [{"ip": ip, "responses": c}
                            for ip, c in self.dns_servers.most_common(10)],
                "resolutions": [{"name": n, "addresses": sorted(a)[:6]}
                                for n, a in list(self.dns_resolved.items())[:100]],
                "suspicious": suspicious},
            "http": {"requests": web_requests,
                     "total_requests": sum(self.http_requests.values()),
                     "hosts": [{"host": h, "count": c}
                               for h, c in self.http_hosts.most_common(25)],
                     "user_agents": [{"agent": a, "count": c}
                                     for a, c in self.http_agents.most_common(15)],
                     "status_codes": [{"code": k, "count": v}
                                      for k, v in sorted(self.http_status.items())]},
            "tls": {"records": self.tls_records,
                    "server_names": [{"name": n, "hellos": c,
                                      "clients": sorted(self.tls_clients[n])[:5]}
                                     for n, c in self.tls_sni.most_common(50)]},
            "arp": {"operations": [{"name": ARP_OPS.get(k, f"op {k}"), "count": v}
                                   for k, v in self.arp_ops.items()],
                    "gratuitous": self.arp_gratuitous, "table": arp_table},
            "icmp": {"types": [{"name": k, "count": v}
                               for k, v in self.icmp_types.most_common()]},
            "insecure_services": [{"service": label, "packets": sum(c.values()),
                                   "connections": [{"pair": p, "packets": n}
                                                   for p, n in c.most_common(5)]}
                                  for label, c in self.insecure.items()],
            "security": {"risk_score": score, "risk_level": detections.risk_level(score),
                         "counts": {k: counts.get(k, 0)
                                    for k in ("critical", "high", "medium", "low", "info")},
                         "findings": findings},
            "graph": graph,
        }


def analyze_file(path, thresholds: dict | None = None, max_packets: int = 0) -> dict:
    return PcapAnalyzer(path, thresholds, max_packets).analyze()
