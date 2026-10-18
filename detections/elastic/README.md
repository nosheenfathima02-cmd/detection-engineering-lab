# Elastic Stack detections

Elastic/Kibana versions of the lab's network and endpoint detections, so the repo works whether you run
Splunk or the Elastic Stack. Queries are written for the Elastic Common Schema (ECS), which Elastic Agent,
Filebeat (Zeek/Suricata modules) and Winlogbeat all populate.

## How to use

**Kibana → Security → Rules → Create new rule.**
- `*.kql` files: paste into a **Custom query** rule (KQL).
- `*.eql` files: create an **Event correlation (EQL)** rule and paste the query. EQL `sequence` is how
  Elastic expresses the multi-event detections that are SPL `stats` searches on the Splunk side.

Set the index pattern to match your data (e.g. `logs-*`, `winlogbeat-*`, `filebeat-*`).

## Rules

| File | Detection | ATT&CK | Splunk equivalent |
| --- | --- | --- | --- |
| `beaconing.kql` | Many connections to one external host | T1071.001 | CD-05 |
| `dns_tunnelling.kql` | Long, high-entropy DNS query names | T1071.004 | CD-06 |
| `port_scan.kql` | One host connecting to many destination ports | T1046 | Suricata 1000001 |
| `encoded_powershell_then_network.eql` | Encoded PowerShell followed by an outbound connection | T1059.001 → T1105 | CD-04 |
| `admin_add_then_remote_logon.eql` | Local admin added, then network logon, then service install | T1098 → T1021.002 | CD-01 |

## Notes on tuning

The KQL rules above find candidates; set the rule's **threshold** and **schedule** in Kibana rather than in
the query. For beaconing, use a threshold rule grouped by `source.ip` + `destination.ip` with a min count,
then review interval regularity in the alert. The EQL `sequence` rules already encode the ordering, so they
only fire when the full chain happens on one host inside the `maxspan`.
