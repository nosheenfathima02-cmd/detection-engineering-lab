#!/usr/bin/env python3
"""Wazuh integration entry point.

Wazuh calls custom integrations as:  custom-enrich <alert_file> <api_key> <hook_url>
  - api_key  -> TheHive API key
  - hook_url -> TheHive base URL, e.g. http://10.10.10.20:9000
VirusTotal and AbuseIPDB keys come from environment variables VT_API_KEY and ABUSEIPDB_API_KEY
(or /var/ossec/etc/enrich.env, loaded below).

ossec.conf:
  <integration>
    <name>custom-enrich</name>
    <hook_url>http://10.10.10.20:9000</hook_url>
    <api_key>THEHIVE_API_KEY</api_key>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>
"""

import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from enrich import enrich_and_forward  # noqa: E402

ENV_FILE = Path("/var/ossec/etc/enrich.env")
LOG_FILE = "/var/ossec/logs/integrations.log"


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def main(argv: list[str]) -> int:
    logging.basicConfig(filename=LOG_FILE if os.access(os.path.dirname(LOG_FILE), os.W_OK) else None,
                        level=logging.INFO, format="%(asctime)s custom-enrich %(levelname)s %(message)s")
    if len(argv) < 4:
        logging.error("usage: custom-enrich <alert_file> <thehive_api_key> <thehive_url>")
        return 1
    load_env_file(ENV_FILE)
    alert = json.loads(Path(argv[1]).read_text())
    try:
        payload = enrich_and_forward(
            alert,
            vt_key=os.environ.get("VT_API_KEY"),
            abuse_key=os.environ.get("ABUSEIPDB_API_KEY"),
            thehive_url=argv[3],
            thehive_key=argv[2],
        )
    except Exception as exc:  # never crash the Wazuh integrator
        logging.exception("enrichment failed for alert %s: %s", alert.get("id"), exc)
        return 1
    logging.info("forwarded alert %s severity=%s observables=%d",
                 alert.get("id"), payload["severity"], len(payload["observables"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
