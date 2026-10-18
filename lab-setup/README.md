# Lab build guide

## 1. Virtual machines

| VM | OS | vCPU / RAM | Network | Role |
| --- | --- | --- | --- | --- |
| pfSense | pfSense CE | 1 / 1 GB | WAN (NAT), CORP, ATTACK | Router, firewall, segmentation |
| DC01 | Windows Server 2022 (eval) | 2 / 4 GB | CORP 10.10.10.10 | AD DS + DNS for `lab.local` |
| WIN11-01, WIN11-02 | Windows 11 Enterprise (eval) | 2 / 4 GB | CORP (DHCP) | Domain-joined endpoints |
| UBU-01 | Ubuntu Server 24.04 | 1 / 2 GB | CORP | Linux target, auditd |
| SIEM-01 | Ubuntu Server 24.04 | 4 / 12 GB | CORP 10.10.10.20 | Wazuh all-in-one, Splunk Free, TheHive |
| KALI | Kali Linux | 2 / 4 GB | ATTACK 10.10.20.0/24 | Attacker |

Microsoft evaluation ISOs (180-day) are free from the Microsoft Evaluation Center.

## 2. SIEM

```bash
# Wazuh all-in-one (manager + indexer + dashboard)
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# Custom rules from this repo
sudo cp detections/wazuh/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

Splunk Free: install the `.deb`, add indexes `wineventlog`, `sysmon`, `zeek`, `aws_cloudtrail`,
and install the Splunk Add-on for Microsoft Windows and Splunk Add-on for Sysmon.

## 3. Endpoint logging

Run on each Windows VM as Administrator:

```powershell
.\lab-setup\scripts\Install-Sysmon.ps1
.\lab-setup\scripts\Enable-AuditPolicy.ps1
```

Then install the Wazuh agent pointing at `10.10.10.20` and add the Sysmon channel to the agent's
`ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

## 4. Vulnerable AD target

On DC01, after promoting it to a domain controller:

```powershell
.\lab-setup\scripts\New-VulnerableADLab.ps1
```

This creates a Kerberoastable service account, an AS-REP roastable user, weak-password users for
spraying, and a non-admin account with DCSync rights. **Lab use only.**

## 5. Network sensors

Mirror the CORP interface on pfSense to SIEM-01, then install Zeek and Suricata (Emerging Threats Open
rules) and ship `conn.log`, `dns.log`, and `eve.json` to Splunk.

## 6. Cloud

Use a personal AWS account with a budget alarm. Enable a CloudTrail trail for all regions and GuardDuty,
then pull CloudTrail into Splunk with the Splunk Add-on for AWS (SQS-based S3 input).

## 7. Alert enrichment

```bash
sudo cp automation/enrich/enrich.py /var/ossec/integrations/
sudo cp automation/enrich/custom-enrich.py /var/ossec/integrations/custom-enrich
sudo chmod 750 /var/ossec/integrations/custom-enrich
sudo chown root:wazuh /var/ossec/integrations/custom-enrich /var/ossec/integrations/enrich.py
echo -e "VT_API_KEY=...\nABUSEIPDB_API_KEY=..." | sudo tee /var/ossec/etc/enrich.env
sudo chmod 640 /var/ossec/etc/enrich.env && sudo chown root:wazuh /var/ossec/etc/enrich.env
```

Add the `<integration>` block shown at the top of `custom-enrich.py` to `/var/ossec/etc/ossec.conf`
and restart the manager.
