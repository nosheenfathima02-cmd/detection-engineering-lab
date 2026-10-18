"""Alert enrichment for the detection lab.

Takes a Wazuh alert, pulls out IPs and file hashes, looks them up in VirusTotal and
AbuseIPDB, scores the result, and opens an alert in TheHive with the observables attached.

Every external call goes through `requests`, so the logic is unit-tested with mocks
(see tests/test_enrich.py) and never needs real API keys in CI.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

import requests

VT_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 10

HASH_RE = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Observable:
    data_type: str  # "ip" or "hash"
    value: str
    vt_malicious: int | None = None
    abuse_score: int | None = None
    tags: list[str] = field(default_factory=list)


def _walk_strings(obj):
    """Yield every string value nested anywhere inside a JSON-like object."""
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)
    elif isinstance(obj, str):
        yield obj


def extract_observables(alert: dict) -> list[Observable]:
    """Find public IPs and file hashes anywhere in the alert's data section."""
    ips: set[str] = set()
    hashes: set[str] = set()
    for text in _walk_strings(alert.get("data", {})):
        for candidate in IP_RE.findall(text):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_global:  # private/lab addresses are not worth a lookup
                ips.add(candidate)
        for h in HASH_RE.findall(text):
            hashes.add(h.lower())
    return [Observable("ip", v) for v in sorted(ips)] + [Observable("hash", v) for v in sorted(hashes)]


def vt_lookup(obs: Observable, api_key: str, session=requests) -> None:
    path = "ip_addresses" if obs.data_type == "ip" else "files"
    resp = session.get(f"{VT_URL}/{path}/{obs.value}", headers={"x-apikey": api_key}, timeout=TIMEOUT)
    if resp.status_code == 404:
        obs.vt_malicious = 0
        obs.tags.append("vt:unknown")
        return
    resp.raise_for_status()
    stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    obs.vt_malicious = int(stats.get("malicious", 0))
    obs.tags.append(f"vt:malicious={obs.vt_malicious}")


def abuseipdb_lookup(obs: Observable, api_key: str, session=requests) -> None:
    if obs.data_type != "ip":
        return
    resp = session.get(
        ABUSEIPDB_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": obs.value, "maxAgeInDays": 90},
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    obs.abuse_score = int(resp.json()["data"]["abuseConfidenceScore"])
    obs.tags.append(f"abuseipdb:{obs.abuse_score}")


def score(alert: dict, observables: list[Observable]) -> int:
    """Map to TheHive severity: 1 low, 2 medium, 3 high, 4 critical."""
    rule_level = int(alert.get("rule", {}).get("level", 0))
    sev = 1 if rule_level < 7 else 2 if rule_level < 12 else 3
    worst_vt = max((o.vt_malicious or 0 for o in observables), default=0)
    worst_abuse = max((o.abuse_score or 0 for o in observables), default=0)
    if worst_vt >= 10 or worst_abuse >= 90:
        sev += 1
    elif worst_vt >= 3 or worst_abuse >= 50:
        sev = max(sev, 2)
    return min(sev, 4)


def build_thehive_alert(alert: dict, observables: list[Observable], severity: int) -> dict:
    rule = alert.get("rule", {})
    mitre_ids = rule.get("mitre", {}).get("id", [])
    agent = alert.get("agent", {}).get("name", "unknown")
    lines = [
        f"**Rule:** {rule.get('id')} - {rule.get('description')}",
        f"**Host:** {agent}",
        f"**ATT&CK:** {', '.join(mitre_ids) or 'n/a'}",
        "",
        "| Observable | VT malicious | AbuseIPDB |",
        "| --- | --- | --- |",
    ]
    for o in observables:
        lines.append(f"| {o.value} | {o.vt_malicious if o.vt_malicious is not None else '-'} | "
                     f"{o.abuse_score if o.abuse_score is not None else '-'} |")
    return {
        "type": "wazuh",
        "source": "detection-lab",
        "sourceRef": str(alert.get("id", "")),
        "title": f"[{agent}] {rule.get('description', 'Wazuh alert')}",
        "description": "\n".join(lines),
        "severity": severity,
        "tags": [f"rule:{rule.get('id')}"] + [f"attack:{m}" for m in mitre_ids],
        "observables": [
            {"dataType": o.data_type, "data": o.value, "tags": o.tags} for o in observables
        ],
    }


def enrich_and_forward(alert: dict, *, vt_key: str | None, abuse_key: str | None,
                       thehive_url: str, thehive_key: str, session=requests) -> dict:
    observables = extract_observables(alert)
    for obs in observables:
        if vt_key:
            vt_lookup(obs, vt_key, session)
        if abuse_key:
            abuseipdb_lookup(obs, abuse_key, session)
    payload = build_thehive_alert(alert, observables, score(alert, observables))
    resp = session.post(
        f"{thehive_url.rstrip('/')}/api/v1/alert",
        headers={"Authorization": f"Bearer {thehive_key}"},
        json=payload,
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    return payload
