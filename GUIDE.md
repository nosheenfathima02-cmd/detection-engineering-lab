# Step-by-step guide

This guide takes you from an empty machine to a repo full of real evidence you can talk through in an
interview. It assumes you've used a computer and a terminal but are new to building a detection lab.
Work through it in order. Expect roughly **four weekends**.

The repo already has all the rules and docs. Your job is to stand the lab up, run the attacks, and
capture proof that your detections fired. That proof is what makes this project convincing.

---

## Before you start

- A host machine with **32 GB RAM** and **~200 GB free disk** is comfortable; 16 GB works if you run
  fewer VMs at once.
- Install a hypervisor: **VirtualBox** (free) or **VMware Workstation**.
- Make a free **GitHub** account if you don't have one.
- Keep everything on an **isolated host-only network**. The AD machine is deliberately insecure, so it
  must never touch the internet or your home network.

> One rule that matters: only ever run attack tools against the lab machines you built. Nothing else.

---

## Week 1 — Stand up the lab and get logs flowing

1. Follow [`lab-setup/README.md`](lab-setup/README.md) to build the VMs: pfSense, DC01, two Windows 11
   endpoints, an Ubuntu box, the SIEM, and Kali.
2. On DC01, promote it to a domain controller for `lab.local`, then join the Windows 11 machines to it.
3. On SIEM-01, install Wazuh with the one-line installer. Log into the dashboard.
4. On each Windows machine, run `Install-Sysmon.ps1` and `Enable-AuditPolicy.ps1`, then install the
   Wazuh agent pointing at the SIEM.
5. **Checkpoint:** in the Wazuh dashboard you should see events arriving from every agent. If you don't,
   fix this before moving on. No logs means no detections.

Capture a screenshot of agents reporting in. That's your first piece of evidence.

## Week 2 — Load the detections and fire the first alerts

1. Copy [`detections/wazuh/local_rules.xml`](detections/wazuh/local_rules.xml) onto the manager and
   restart it (commands are in the lab-setup guide).
2. On DC01, run `New-VulnerableADLab.ps1` to create the weak accounts.
3. From Kali, install Impacket and work through the Active Directory tests in the
   [emulation plan](emulation/emulation-plan.md): Kerberoasting, AS-REP roasting, DCSync.
4. After each attack, find the matching alert in Wazuh. Screenshot it.
5. **Checkpoint:** you have alerts for at least Kerberoasting (rule 100110) and DCSync (100130).

Record each run in [`results/README.md`](results/README.md): what you ran, whether it fired, how long it
took. Empty cells are fine; fill them as you go.

## Week 3 — Network, cloud, and correlation

1. Add Splunk Free (or the Elastic Stack — see [`detections/elastic`](detections/elastic)) alongside
   Wazuh and bring in Windows logs.
2. Load the [Splunk correlated searches](detections/splunk/correlated_detections.spl). Run the password
   spray test from the emulation plan and watch CD-02 and CD-03 fire.
3. Set up Zeek and Suricata on the SIEM, add [`detections/suricata/local.rules`](detections/suricata/local.rules),
   and test a port scan and a DNS-tunnel replay.
4. Create a personal **AWS** account with a budget alarm, turn on CloudTrail, and run the
   [Stratus Red Team](https://github.com/DataDog/stratus-red-team) tests for the three cloud rules.
5. **Checkpoint:** you can show at least one correlated detection (a chain of events, not a single alert)
   firing. This is the single most important thing to demonstrate for a detection engineer role.

## Week 4 — Harden, re-test, and automate

1. Work through [`docs/ad-hardening.md`](docs/ad-hardening.md). Apply each fix, then re-run the matching
   attack and confirm it now **fails** while the detection still fires. Record both outcomes.
2. Set up the [enrichment pipeline](automation/enrich): install it as a Wazuh integration, add free
   VirusTotal and AbuseIPDB API keys, and stand up TheHive. Trigger an alert and show the enriched case.
3. Fill in the tuning log in `results/README.md`: every filter you added and why it's safe.

---

## Push it to GitHub

Once you've added your screenshots and filled in the results:

```bash
# from inside the detection-engineering-lab folder
git add -A
git commit -m "Add lab evidence and tuning notes"

# create an empty public repo named detection-engineering-lab on github.com first, then:
git remote add origin https://github.com/YOUR-USERNAME/detection-engineering-lab.git
git branch -M main
git push -u origin main
```

Then replace `[your-handle]` in the README and on your resume with your real username.

**Never commit:** API keys, real passwords, or anything from a work environment. The `.gitignore` already
blocks `*.env`; keep it that way.

---

## How to talk about this in an interview

Detection engineer interviews almost always include "walk me through a detection you built." Prepare two:

- **One single-event rule** — e.g. Kerberoasting (SIG-02). Be ready to say: the technique, the exact log
  source and event ID, why RC4 is the signal, and the one false positive you tuned out.
- **One correlated detection** — e.g. CD-01, the lateral-movement chain. Explain why three events together
  mean more than any one alone, and how the time window keeps it from being noisy. This shows you can go
  "beyond 1:1 alerting", which is the exact phrase in the CIBC posting.

Also be ready for: "a rule is too noisy — what do you do?" Your tuning log is the answer. Walk them through
a real filter you added and how you confirmed it didn't hide a real attack.

Keep your answers concrete. "I detected Kerberoasting by alerting on event 4769 with RC4 encryption for
non-machine accounts, and filtered out our one legacy app after checking it" beats any amount of theory.
