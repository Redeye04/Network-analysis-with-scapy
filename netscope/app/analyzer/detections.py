"""Heuristic security detections run over the analyzer's accumulated state."""
from __future__ import annotations

import statistics
from typing import Any

from .utils import SUSPICIOUS_PORTS, ip_scope, is_private

DEFAULT_THRESHOLDS: dict[str, Any] = {
    "port_scan_ports": 15,       # distinct SYN destination ports on one host
    "host_sweep_hosts": 10,      # distinct internal hosts probed by one source
    "dns_tunnel_names": 5,       # suspicious names under a single base domain
    "dns_name_length": 60,       # whole-name length considered suspicious
    "dns_label_length": 24,      # label length considered suspicious (with entropy)
    "dns_label_entropy": 3.5,
    "nxdomain_burst": 10,        # NXDOMAIN answers received by one client
    "rst_burst": 20,             # resets sent by one host
    "rst_ratio": 0.3,
    "exfil_bytes": 10_000_000,   # private -> public bytes in a single direction
    "beacon_min_events": 8,
    "beacon_max_cv": 0.1,        # coefficient of variation of the interval
    "beacon_min_interval": 1.0,  # seconds
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 35, "high": 20, "medium": 10, "low": 3, "info": 1}

_RISKY_CLEARTEXT = {"Telnet", "FTP", "TFTP"}


def _finding(severity: str, category: str, title: str, description: str,
             hosts: list[str], evidence: dict) -> dict:
    return {"severity": severity, "category": category, "title": title,
            "description": description, "hosts": sorted(set(hosts)),
            "evidence": evidence}


def risk_score(findings: list[dict]) -> int:
    return min(100, sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))


def risk_level(score: int) -> str:
    if score < 20:
        return "Low"
    if score < 50:
        return "Moderate"
    if score < 80:
        return "High"
    return "Critical"


def detect_all(a, thresholds: dict | None = None) -> list[dict]:
    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    findings: list[dict] = []
    for fn in (_arp_spoofing, _port_scans, _host_sweeps, _dns_tunneling, _nxdomain,
               _cleartext_credentials, _insecure_services, _suspicious_ports,
               _beaconing, _large_uploads, _rst_bursts):
        findings.extend(fn(a, t))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["title"]))
    for i, f in enumerate(findings, 1):
        f["id"] = i
    return findings


def _arp_spoofing(a, t):
    for ip, macs in a.arp_map.items():
        if len(macs) < 2:
            continue
        claims = {m: a.arp_pairs.get((ip, m), 0) for m in macs}
        yield _finding(
            "critical", "Man-in-the-middle", "Possible ARP spoofing",
            f"{ip} was claimed by {len(macs)} different MAC addresses. This is the "
            "classic signature of ARP poisoning (it can also be a failover or a "
            "duplicate address).",
            [ip], {"mac_addresses": sorted(macs), "arp_packets_per_mac": claims})


def _port_scans(a, t):
    for (src, dst), ports in a.scan_ports.items():
        if len(ports) < t["port_scan_ports"]:
            continue
        open_ports = sorted(ports & a.open_ports.get(dst, set()))
        yield _finding(
            "high", "Reconnaissance", "TCP port scan",
            f"{src} sent SYN probes to {len(ports)} distinct ports on {dst}.",
            [src, dst], {"ports_probed": len(ports),
                         "sample_ports": sorted(ports)[:12],
                         "open_ports_found": open_ports})


def _host_sweeps(a, t):
    for src in set(a.syn_sweep) | set(a.icmp_sweep):
        targets = a.syn_sweep.get(src, set()) | a.icmp_sweep.get(src, set())
        if len(targets) < t["host_sweep_hosts"]:
            continue
        yield _finding(
            "medium", "Reconnaissance", "Internal host sweep",
            f"{src} probed {len(targets)} different internal hosts "
            "(ICMP echo / TCP SYN), which looks like network discovery.",
            [src], {"hosts_probed": len(targets),
                    "icmp_targets": len(a.icmp_sweep.get(src, ())),
                    "syn_targets": len(a.syn_sweep.get(src, ()))})


def _dns_tunneling(a, t):
    for base, names in a.suspicious_dns.items():
        if len(names) < t["dns_tunnel_names"]:
            continue
        clients = sorted(a.suspicious_dns_clients.get(base, ()))
        yield _finding(
            "high", "Exfiltration / C2", "Possible DNS tunnelling",
            f"{len(names)} unusually long or high-entropy DNS names were queried "
            f"under {base}. Tunnelling tools encode data into sub-domain labels.",
            clients, {"base_domain": base, "distinct_names": len(names),
                      "queries": sum(names.values()),
                      "samples": [n[:80] for n in list(names)[:3]]})


def _nxdomain(a, t):
    for client, count in a.nxdomain_by_client.items():
        if count >= t["nxdomain_burst"]:
            yield _finding(
                "medium", "Malware indicator", "Burst of NXDOMAIN responses",
                f"{client} received {count} 'no such domain' answers, a pattern "
                "seen with domain-generation-algorithm malware or broken software.",
                [client], {"nxdomain_responses": count})


def _cleartext_credentials(a, t):
    for (src, host), info in a.http_cred_events.items():
        yield _finding(
            "high", "Credential exposure", "Credentials sent over plain HTTP",
            f"{src} submitted a password field or Basic-auth header to "
            f"{host or 'an HTTP server'} without encryption. Values are never stored.",
            [src, info["dst"]], {"host": host, "path": info["path"],
                                 "method": info["method"], "reason": info["reason"]})


def _insecure_services(a, t):
    for label, pairs in a.insecure.items():
        sev = "medium" if label in _RISKY_CLEARTEXT else "low"
        yield _finding(
            sev, "Unencrypted protocol", f"Cleartext {label} traffic",
            f"{label} does not encrypt its payload; anyone on the path can read it.",
            [h for pair in pairs for h in pair.split(" -> ")],
            {"connections": dict(pairs.most_common(5)), "packets": sum(pairs.values())})


def _suspicious_ports(a, t):
    seen = set()
    for (src, dst, port), count in a.syn_dst_ports.items():
        if port in SUSPICIOUS_PORTS and is_private(src) and (src, dst, port) not in seen:
            seen.add((src, dst, port))
            yield _finding(
                "medium", "Suspicious connection",
                f"Connection to port {port}",
                f"{src} connected to {dst}:{port}, {SUSPICIOUS_PORTS[port]}.",
                [src, dst], {"port": port, "connection_attempts": count})


def _beaconing(a, t):
    for (src, dst, port), times in a.syn_times.items():
        if len(times) < t["beacon_min_events"]:
            continue
        times = sorted(times)
        gaps = [b - c for b, c in zip(times[1:], times)]
        mean = statistics.fmean(gaps)
        if mean < t["beacon_min_interval"]:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv <= t["beacon_max_cv"]:
            yield _finding(
                "medium", "Malware indicator", "Regular beaconing pattern",
                f"{src} opened {len(times)} connections to {dst}:{port} at a very "
                f"steady interval of about {mean:.1f}s, typical of C2 check-ins.",
                [src, dst], {"port": port, "connections": len(times),
                             "mean_interval_seconds": round(mean, 2),
                             "interval_variation": round(cv, 3)})


def _large_uploads(a, t):
    for (src, dst), size in a.comm_bytes.items():
        if size >= t["exfil_bytes"] and is_private(src) and ip_scope(dst) == "public":
            yield _finding(
                "medium", "Exfiltration / C2", "Large outbound transfer",
                f"{src} sent {size / 1e6:.1f} MB to the public address {dst}.",
                [src, dst], {"bytes": size})


def _rst_bursts(a, t):
    for host, rsts in a.rst_sent.items():
        total = a.tcp_sent.get(host, 0) or 1
        if rsts >= t["rst_burst"] and rsts / total >= t["rst_ratio"]:
            yield _finding(
                "low", "Anomaly", "Many TCP resets",
                f"{host} sent {rsts} RST packets ({rsts / total:.0%} of its TCP "
                "traffic), often the target of a scan or a failing service.",
                [host], {"rst_packets": rsts, "tcp_packets": total})
