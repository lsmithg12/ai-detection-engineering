"""
simulator/generators/network.py — Network (Zeek) event generator.

Generates ECS-formatted Zeek connection/DNS/SSL events for network-layer
attack techniques mapped to MITRE ATT&CK.
"""
from __future__ import annotations

import random
import uuid

from simulator.generators import (
    PlatformGenerator,
    _now_iso,
    _random_port,
)

_INTERNAL_HOSTS = [f"10.0.{s}.{h}" for s in range(1, 4) for h in range(10, 60)]
_CORPORATE_DOMAINS = [
    "corp.internal", "sharepoint.corp.com", "outlook.office365.com",
    "teams.microsoft.com", "github.com", "pypi.org",
]
_C2_IP = "203.0.113.50"
_ATTACKER_IP = "198.51.100.200"


def _generate_zeek_conn(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str,
    duration: float,
    orig_bytes: int,
    resp_bytes: int,
    technique_id: str,
) -> dict:
    return {
        "@timestamp": _now_iso(),
        "event": {
            "category": "network",
            "type": "connection",
            "kind": "event",
            "dataset": "zeek.conn",
            "module": "zeek",
        },
        "source": {"ip": src_ip, "port": _random_port(), "bytes": orig_bytes},
        "destination": {"ip": dst_ip, "port": dst_port, "bytes": resp_bytes},
        "network": {
            "transport": proto,
            "bytes": orig_bytes + resp_bytes,
            "direction": "outbound",
        },
        "zeek": {
            "connection": {
                "uid": f"C{uuid.uuid4().hex[:16]}",
                "state": "SF",
                "history": "ShADadfF",
                "duration": duration,
            },
        },
        "_simulation": {
            "type": "attack",
            "technique": technique_id,
            "platform": "network",
        },
    }


class NetworkGenerator(PlatformGenerator):
    """Generates Zeek network ECS events for attack simulation and baselines."""

    platform = "network"
    event_types = ["conn", "http", "ssl", "dns"]

    def generate_attack(self, technique_id: str, **kwargs) -> list[dict]:
        if technique_id == "T1071.001":
            return self._t1071_001()
        elif technique_id == "T1090.001":
            return self._t1090_001()
        elif technique_id == "T1048.001":
            return self._t1048_001()
        elif technique_id == "T1573.002":
            return self._t1573_002()
        else:
            return []

    def generate_benign(self, event_type: str = "conn", count: int = 5) -> list[dict]:
        events = []
        for _ in range(count):
            src = random.choice(_INTERNAL_HOSTS)
            dst = f"142.250.{random.randint(1,254)}.{random.randint(1,254)}"
            ev = _generate_zeek_conn(
                src_ip=src,
                dst_ip=dst,
                dst_port=443,
                proto="tcp",
                duration=round(random.uniform(0.1, 5.0), 3),
                orig_bytes=random.randint(500, 5000),
                resp_bytes=random.randint(1000, 50000),
                technique_id="baseline",
            )
            ev["_simulation"] = {
                "type": "baseline",
                "platform": "network",
                "expected_match": False,
            }
            events.append(ev)
        return events

    # ── Technique implementations ──────────────────────────────────────

    def _t1071_001(self) -> list[dict]:
        """T1071.001 — Application Layer Protocol: Web Protocols (C2 HTTPS beaconing)."""
        events = []
        src_ip = random.choice(_INTERNAL_HOSTS)
        # Simulate 5 regular-interval HTTPS beacon connections
        for _ in range(5):
            ev = _generate_zeek_conn(
                src_ip=src_ip,
                dst_ip=_C2_IP,
                dst_port=443,
                proto="tcp",
                duration=round(random.uniform(0.05, 0.3), 3),
                orig_bytes=random.randint(200, 800),
                resp_bytes=random.randint(100, 500),
                technique_id="T1071.001",
            )
            # Add SSL/JA3 info to indicate unusual TLS fingerprint
            ev["tls"] = {
                "version": "1.2",
                "cipher": "TLS_RSA_WITH_RC4_128_SHA",
                "ja3": {
                    "hash": "e7d705a3286e19ea42f587b344ee6865",
                    "string": "769,47,0-65281-35,23-65281",
                },
            }
            ev["_simulation"]["expected_match"] = True
            ev["_simulation"]["description"] = (
                "HTTPS beacon to C2 at 203.0.113.50 every ~60s with unusual JA3 hash"
            )
            events.append(ev)
        return events

    def _t1090_001(self) -> list[dict]:
        """T1090.001 — Proxy: Internal Proxy / SOCKS5 fan-out."""
        events = []
        src_ip = "10.0.1.100"
        # Simulate connections from single source to 50+ unique internal destinations
        target_ips = random.sample(_INTERNAL_HOSTS, min(50, len(_INTERNAL_HOSTS)))
        for dst_ip in target_ips:
            ev = _generate_zeek_conn(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=random.choice([445, 3389, 22, 80, 443]),
                proto="tcp",
                duration=round(random.uniform(0.01, 2.0), 3),
                orig_bytes=random.randint(50, 500),
                resp_bytes=random.randint(0, 200),
                technique_id="T1090.001",
            )
            ev["_simulation"]["expected_match"] = True
            ev["_simulation"]["description"] = (
                "SOCKS5 proxy — single source 10.0.1.100 scanning 50+ internal hosts"
            )
            events.append(ev)
        return events

    def _t1048_001(self) -> list[dict]:
        """T1048.001 — Exfiltration Over Alternative Protocol: DNS exfiltration."""
        events = []
        src_ip = random.choice(_INTERNAL_HOSTS)
        # Simulate DNS queries with long base64-encoded subdomains
        b64_chunks = [
            "dXNlcm5hbWU9YWRtaW4mcGFzc3dvcmQ9c2VjcmV0MTIz",
            "c3NudW1iZXI9MTIzLTQ1LTY3ODkmZG9iP",
            "bGlzdGVuaW5nX3BvcnQ9NDQ0MyZhZ2VudF9pZD1hYmNkZWYxMjM0NTY",
            "Y3JlZGVudGlhbHM9dXNlcjpwYXNz",
            "aG9zdG5hbWU9V1MtRklOQU5DRS0wMQ",
        ]
        resolver_ip = "8.8.8.8"
        for chunk in b64_chunks:
            subdomain = f"{chunk}.exfil.attacker-c2.net"
            ev = {
                "@timestamp": _now_iso(),
                "event": {
                    "category": "network",
                    "type": "protocol",
                    "kind": "event",
                    "dataset": "zeek.dns",
                    "module": "zeek",
                },
                "source": {"ip": src_ip, "port": _random_port()},
                "destination": {"ip": resolver_ip, "port": 53},
                "network": {"transport": "udp", "protocol": "dns"},
                "dns": {
                    "question": {
                        "name": subdomain,
                        "type": "A",
                        "class": "IN",
                        "subdomain": subdomain,
                        "registered_domain": "attacker-c2.net",
                    },
                    "response_code": "NOERROR",
                },
                "zeek": {
                    "dns": {
                        "uid": f"C{uuid.uuid4().hex[:16]}",
                        "query": subdomain,
                        "qtype_name": "A",
                    },
                },
                "_simulation": {
                    "type": "attack",
                    "technique": "T1048.001",
                    "platform": "network",
                    "expected_match": True,
                    "description": "DNS exfiltration — base64 data encoded in subdomain labels (>60 chars)",
                },
            }
            events.append(ev)
        return events

    def _t1573_002(self) -> list[dict]:
        """T1573.002 — Encrypted Channel: Asymmetric Cryptography (self-signed cert, non-standard port)."""
        src_ip = random.choice(_INTERNAL_HOSTS)
        ev = _generate_zeek_conn(
            src_ip=src_ip,
            dst_ip=_C2_IP,
            dst_port=8443,
            proto="tcp",
            duration=round(random.uniform(30.0, 300.0), 3),
            orig_bytes=random.randint(5000, 50000),
            resp_bytes=random.randint(5000, 50000),
            technique_id="T1573.002",
        )
        ev["tls"] = {
            "version": "1.2",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "established": True,
            "resumed": False,
            "certificate": {
                "subject": "CN=localhost",
                "issuer": "CN=localhost",
                "not_before": "2024-01-01T00:00:00Z",
                "not_after": "2099-12-31T23:59:59Z",
                "serial_number": "deadbeef",
                "is_self_signed": True,
            },
            "ja3": {
                "hash": "ada70206e40642a3e4461f35503241d5",
                "string": "771,49200-49196,0-65281-10-11,23-24,0",
            },
        }
        ev["_simulation"]["expected_match"] = True
        ev["_simulation"]["description"] = (
            "Encrypted C2 channel on non-standard port 8443 with self-signed TLS cert"
        )
        return [ev]
