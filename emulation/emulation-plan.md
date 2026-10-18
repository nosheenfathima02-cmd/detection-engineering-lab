# Emulation plan

Each detection is proven by running the technique in the lab and checking that the alert fires.
Run Windows tests from an elevated PowerShell on WIN11-01 with
[Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) installed; AD tests from Kali.

Always run `-CheckPrereqs` first and `-Cleanup` afterwards.

| Detection | Technique | How to trigger it | Expected alert |
| --- | --- | --- | --- |
| SIG-01 LSASS access | T1003.001 | `Invoke-AtomicTest T1003.001 -ShowDetailsBrief`, then run the comsvcs.dll MiniDump or ProcDump test | Sysmon EID 10 → Wazuh 100140 |
| SIG-02 Kerberoasting | T1558.003 | Kali: `impacket-GetUserSPNs lab.local/spray01:'Autumn2026!' -dc-ip 10.10.10.10 -request` | 4769 RC4 → Wazuh 100110 (100111 if repeated) |
| SIG-03 AS-REP roasting | T1558.004 | Kali: `impacket-GetNPUsers lab.local/ -usersfile users.txt -dc-ip 10.10.10.10 -no-pass` | 4768 PreAuthType 0 → Wazuh 100120 |
| SIG-04 DCSync | T1003.006 | Kali: `impacket-secretsdump lab.local/r.replicator:'Autumn2026!'@10.10.10.10 -just-dc-user krbtgt` | 4662 replication GUIDs → Wazuh 100130 |
| SIG-05 Encoded PowerShell | T1059.001 | `Invoke-AtomicTest T1059.001 -ShowDetailsBrief`, run an encoded-command test | Sysmon EID 1 match |
| SIG-06 Scheduled task | T1053.005 | `Invoke-AtomicTest T1053.005 -ShowDetailsBrief`, run a schtasks /create test | Sysmon EID 1 / 4698 |
| SIG-07 PsExec | T1021.002 | Kali: `impacket-psexec lab.local/<admin>@10.10.10.11` | System 7045 |
| SIG-08 + CD-01 chain | T1098 → T1021.002 | `net localgroup Administrators lab\spray01 /add` on WIN11-01, then PsExec to it as spray01 | 4732, 4624 type 3, 7045 → CD-01 |
| CD-02 / CD-03 spraying | T1110.003 | Kali: `nxc smb 10.10.10.10 -u users.txt -p 'Autumn2026!' --continue-on-success` | 4625 burst → Wazuh 100150, CD-02, CD-03 |
| CD-04 PowerShell + network | T1059.001 → T1105 | Encoded `Invoke-WebRequest` to a lab web server | Sysmon EID 1 + EID 3, same ProcessGuid |
| CD-05 Beaconing | T1071.001 | Caldera Sandcat agent on WIN11-02 with a fixed sleep | Low jitter_ratio in CD-05 |
| CD-06 DNS tunnelling | T1071.004 | `dnscat2` client to a lab server, or replay a public DNS-tunnel PCAP | CD-06 |
| SIG-09/10/11 AWS | T1078.004, T1562.008, T1098.001 | [Stratus Red Team](https://github.com/DataDog/stratus-red-team): `stratus detonate aws.defense-evasion.cloudtrail-stop`, `aws.persistence.iam-create-admin-user` | CloudTrail events in Splunk |

## Recording a test

For each run, add a row to [`results/README.md`](../results/README.md): date, test, fired yes/no,
time to alert, false positives seen, tuning change made. Screenshots go in `results/screenshots/`.
