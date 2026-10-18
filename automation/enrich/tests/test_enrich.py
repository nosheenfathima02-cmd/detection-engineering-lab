import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import enrich  # noqa: E402

SHA256 = "a" * 64

ALERT = {
    "id": "1729170000.12345",
    "rule": {"id": "100140", "level": 12, "description": "Possible credential dumping",
             "mitre": {"id": ["T1003.001"]}},
    "agent": {"name": "WIN11-01"},
    "data": {"win": {"eventdata": {
        "sourceIp": "185.220.101.5",
        "destinationIp": "10.10.10.5",
        "hashes": f"SHA256={SHA256}",
    }}},
}


def _resp(status=200, payload=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload or {}
    r.raise_for_status.return_value = None
    return r


def test_extracts_public_ip_and_hash_but_skips_private_ip():
    obs = enrich.extract_observables(ALERT)
    values = {(o.data_type, o.value) for o in obs}
    assert ("ip", "185.220.101.5") in values
    assert ("hash", SHA256) in values
    assert all(o.value != "10.10.10.5" for o in obs)


def test_vt_404_marks_unknown():
    obs = enrich.Observable("hash", SHA256)
    session = MagicMock(get=MagicMock(return_value=_resp(404)))
    enrich.vt_lookup(obs, "key", session)
    assert obs.vt_malicious == 0
    assert "vt:unknown" in obs.tags


def test_score_escalates_on_bad_reputation():
    clean = [enrich.Observable("ip", "1.1.1.1", vt_malicious=0, abuse_score=0)]
    bad = [enrich.Observable("ip", "1.1.1.1", vt_malicious=15, abuse_score=95)]
    assert enrich.score(ALERT, clean) == 3
    assert enrich.score(ALERT, bad) == 4


def test_score_low_rule_with_moderate_reputation_becomes_medium():
    alert = {"rule": {"level": 5}}
    obs = [enrich.Observable("ip", "1.1.1.1", vt_malicious=4)]
    assert enrich.score(alert, obs) == 2


def test_enrich_and_forward_posts_to_thehive():
    vt = _resp(payload={"data": {"attributes": {"last_analysis_stats": {"malicious": 12}}}})
    abuse = _resp(payload={"data": {"abuseConfidenceScore": 100}})

    def fake_get(url, **kwargs):
        return abuse if "abuseipdb" in url else vt

    session = MagicMock(get=MagicMock(side_effect=fake_get), post=MagicMock(return_value=_resp(201)))
    payload = enrich.enrich_and_forward(ALERT, vt_key="vt", abuse_key="ab",
                                        thehive_url="http://thehive:9000/", thehive_key="th",
                                        session=session)

    url = session.post.call_args.args[0]
    assert url == "http://thehive:9000/api/v1/alert"
    assert payload["severity"] == 4
    assert "attack:T1003.001" in payload["tags"]
    assert {o["data"] for o in payload["observables"]} == {"185.220.101.5", SHA256}
