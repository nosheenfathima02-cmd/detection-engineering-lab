# Detection Engineering Lab

A home lab for building, testing, and tuning threat detections mapped to **MITRE ATT&CK**.
Every detection here is written as code, tested against emulated attacker behaviour, and documented
with its data source, expected false positives, and how to reproduce the alert.

**Author:** Nousheen Fathima · [LinkedIn](https://linkedin.com/in/nousheen) · York University PG Certificate, Cybersecurity

---

## What's in this repo

| Folder | What it holds |
| --- | --- |
| [`detections/sigma`](detections/sigma) | 11 vendor-neutral Sigma rules (Windows, Active Directory, AWS) |
| [`detections/splunk`](detections/splunk/correlated_detections.spl) | 6 **correlated** SPL detections: multi-event chains, spraying, beaconing, DNS tunnelling |
| [`detections/wazuh`](detections/wazuh/local_rules.xml) | Custom Wazuh rules, including frequency-based correlation |
| [`detections/suricata`](detections/suricata/local.rules) | Custom Suricata IDS rules (scanning, beaconing, DNS tunnelling, Kerberoasting on the wire) |
| [`detections/elastic`](detections/elastic) | Elastic Stack (KQL + EQL) versions of the network and correlated detections |
| [`emulation`](emulation/emulation-plan.md) | Atomic Red Team / Caldera / Stratus Red Team tests that trigger each detection |
| [`docs/ad-hardening.md`](docs/ad-hardening.md) | How each AD weakness is fixed and verified, with the detection kept in place |
| [`GUIDE.md`](GUIDE.md) | Step-by-step build guide, week by week, with interview talking points |
| [`automation/enrich`](automation/enrich) | Python pipeline: Wazuh alert → VirusTotal + AbuseIPDB → scored case in TheHive (unit-tested) |
| [`lab-setup`](lab-setup) | Build guide and scripts for the lab VMs, Sysmon, logging, and the AD target |
| [`coverage`](coverage/attack-navigator-layer.json) | ATT&CK Navigator layer showing current detection coverage |
| [`results`](results/README.md) | Test evidence: what fired, what was tuned, screenshots |

## Lab architecture

```
                 ┌──────────────── pfSense (segmentation, firewall logs) ────────────────┐
                 │                                                                        │
  ATTACK NET 10.10.20.0/24                                         CORP NET 10.10.10.0/24
  ┌────────────────────┐                     ┌───────────────────┐  ┌───────────────────┐  ┌──────────────────┐
  │ Kali Linux         │ ── attacks ──────►  │ DC01  Win Srv 2022 │  │ WIN11-01 / -02    │  │ UBU-01 Ubuntu    │
  │ Atomic Red Team    │                     │ AD DS, DNS         │  │ Sysmon + agent    │  │ auditd + agent   │
  │ Caldera            │                     └─────────┬──────────┘  └─────────┬─────────┘  └────────┬─────────┘
  └────────────────────┘                               │ logs (Wazuh agent / UF)│                     │
                                                       ▼                        ▼                     ▼
                                      ┌──────────────────────────────────────────────────────────────┐
                                      │ SIEM-01: Wazuh manager + indexer · Splunk Free · Zeek/Suricata │
                                      │ TheHive (cases) ◄── automation/enrich (VirusTotal, AbuseIPDB)   │
                                      └──────────────────────────────────────────────────────────────┘
```

## Detection catalogue

| ID | Detection | ATT&CK | Platform | Type |
| --- | --- | --- | --- | --- |
| SIG-01 | [LSASS memory access](detections/sigma/windows/lsass_memory_access.yml) | T1003.001 | Sigma, Wazuh 100140 | Single event |
| SIG-02 | [Kerberoasting (RC4 TGS)](detections/sigma/windows/kerberoasting_rc4_tgs.yml) | T1558.003 | Sigma, Wazuh 100110/100111 | Single + burst |
| SIG-03 | [AS-REP roasting](detections/sigma/windows/asrep_roasting.yml) | T1558.004 | Sigma, Wazuh 100120 | Single event |
| SIG-04 | [DCSync](detections/sigma/windows/dcsync_replication_rights.yml) | T1003.006 | Sigma, Wazuh 100130 | Single event |
| SIG-05 | [Encoded PowerShell](detections/sigma/windows/powershell_encoded_command.yml) | T1059.001 | Sigma | Single event |
| SIG-06 | [Scheduled task from user-writable path](detections/sigma/windows/schtasks_create_suspicious_path.yml) | T1053.005 | Sigma | Single event |
| SIG-07 | [PsExec service install](detections/sigma/windows/psexec_service_install.yml) | T1021.002, T1569.002 | Sigma | Single event |
| SIG-08 | [User added to local Administrators](detections/sigma/windows/user_added_to_local_admins.yml) | T1098 | Sigma | Single event |
| SIG-09 | [AWS root console login](detections/sigma/cloud/aws_root_console_login.yml) | T1078.004 | Sigma | Single event |
| SIG-10 | [CloudTrail stopped/deleted](detections/sigma/cloud/aws_cloudtrail_disabled.yml) | T1562.008 | Sigma | Single event |
| SIG-11 | [Access key created for another user](detections/sigma/cloud/aws_iam_access_key_created.yml) | T1098.001 | Sigma | Single event |
| CD-01 | Admin added → network logon → service install (10 min, same host) | T1098 → T1021.002 | Splunk | **Correlated** |
| CD-02 | Password spraying | T1110.003 | Splunk, Wazuh 100150 | **Correlated** |
| CD-03 | Successful logon after spray | T1110.003 → T1078 | Splunk | **Correlated** |
| CD-04 | Encoded PowerShell + outbound connection, same process | T1059.001 → T1105 | Splunk | **Correlated** |
| CD-05 | C2 beaconing (low-jitter intervals) | T1071.001 | Splunk + Zeek | Behavioural |
| CD-06 | DNS tunnelling (long, high-entropy subdomains) | T1071.004 | Splunk + Zeek | Behavioural |

## How each detection is built

1. **Pick a technique** from ATT&CK and read how real attackers use it.
2. **Find the data source** (Sysmon EID 10, Security 4769, CloudTrail…) and confirm the lab logs it.
3. **Write the rule** in Sigma first, then the platform version (Wazuh / SPL).
4. **Emulate** the technique ([emulation plan](emulation/emulation-plan.md)) and confirm the alert fires.
5. **Tune** against a baseline of normal activity; document every filter and why it's safe.
6. **Record evidence** in [`results/`](results/README.md) and update the [coverage layer](coverage/attack-navigator-layer.json).

## Run the tests

```bash
cd automation/enrich
pip install -r requirements.txt
pytest -q
```

GitHub Actions also checks every Sigma rule and runs these tests on each push (see `.github/workflows/ci.yml`).

## Reproduce the lab

New to this? Start with [`GUIDE.md`](GUIDE.md), a week-by-week walkthrough. For the machine details,
see [`lab-setup/README.md`](lab-setup/README.md). Hardware used: [your CPU / RAM / disk, e.g. 32 GB RAM, 1 TB SSD]
running [VirtualBox / VMware Workstation / Proxmox].

> ⚠️ The Active Directory target is **deliberately vulnerable**. Keep it on an isolated host-only network,
> never expose it to the internet, and only run attack tools against machines you own.
