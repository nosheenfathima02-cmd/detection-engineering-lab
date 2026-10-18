# Active Directory hardening

The lab domain is weakened on purpose by
[`New-VulnerableADLab.ps1`](../lab-setup/scripts/New-VulnerableADLab.ps1). This guide covers the other half:
how each weakness is **fixed**, how to **prove** the fix worked, and why the detection stays in place anyway.

Detection and hardening work together. Hardening makes most attacks fail. Detection catches the attempt
and anything hardening missed. Apply each fix by hand on DC01 so you understand what it changes.

## Summary

| Weakness | Attack | Fix | Verify | Detection kept |
| --- | --- | --- | --- | --- |
| Service account with SPN, RC4 allowed, weak password | Kerberoasting (T1558.003) | gMSA or 25+ char password; AES only | `GetUserSPNs` returns AES (etype 18) ticket that won't crack | SIG-02, Wazuh 100110/100111 |
| Pre-authentication disabled | AS-REP roasting (T1558.004) | Re-enable pre-auth | `GetNPUsers` returns no hashes | SIG-03, Wazuh 100120 |
| Weak shared password | Password spraying (T1110.003) | Lockout policy, banned-password list, MFA | `nxc` spray locks out or fails | CD-02, CD-03, Wazuh 100150 |
| Replication rights on a normal user | DCSync (T1003.006) | Remove the ACEs; review regularly | `secretsdump -just-dc` gets access denied | SIG-04, Wazuh 100130 |
| LSASS readable by admins | Credential dumping (T1003.001) | LSA protection (RunAsPPL), Credential Guard, ASR rule | `comsvcs.dll MiniDump` fails | SIG-01, Wazuh 100140 |
| Shared local admin password, SMB open between PCs | PsExec lateral movement (T1021.002) | Windows LAPS, deny network logon for local admins, host firewall | PsExec from one PC to another fails | SIG-07, CD-01 |
| Admins log on to workstations | Credential theft, privilege escalation | Tiered admin model, Protected Users group | Tier 0 accounts refused on workstations | SIG-08 |

## 1. Kerberoasting

**Why it works:** any domain user can request a service ticket for any SPN. If the ticket is RC4-encrypted
with a weak password, it cracks offline in minutes.

**Fix**
- Best: replace the account with a **group Managed Service Account** (gMSA). Its 120-character password
  rotates automatically, so cracking is not realistic.
- If a gMSA isn't possible: set a random password of 25+ characters and allow **AES only**:

```powershell
Set-ADUser svc_sql -Replace @{'msDS-SupportedEncryptionTypes' = 24}   # 0x18 = AES128 + AES256
Set-ADAccountPassword svc_sql -Reset -NewPassword (Read-Host -AsSecureString 'New 25+ char password')
```

- Remove SPNs that aren't needed: `Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName`.

**Verify:** run `impacket-GetUserSPNs ... -request` again. The hash should now start `$krb5tgs$18$` (AES) and
should not crack against your wordlist.

## 2. AS-REP roasting

**Why it works:** without pre-authentication, the DC returns encrypted data for that user to anyone who asks.

**Fix**

```powershell
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' |
    Set-ADAccountControl -DoesNotRequirePreAuth $false
```

**Verify:** `impacket-GetNPUsers` reports that no users have pre-auth disabled.

## 3. Password spraying

**Why it works:** many users pick passwords like `Season+Year!`, and one guess per account avoids lockout.

**Fix**
- Account lockout: 10 attempts, 15-minute window and duration. High enough to avoid helpdesk overload,
  low enough to stop a spray.
- Minimum length 14+ and a **banned-password list** (Microsoft Entra Password Protection for on-prem AD).
- MFA on every remote entry point (VPN, webmail, remote desktop gateways).

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) -MinPasswordLength 14 `
    -LockoutThreshold 10 -LockoutObservationWindow 00:15:00 -LockoutDuration 00:15:00
```

**Verify:** re-run the spray. Watch CD-02 still fire, and confirm no logon succeeds (CD-03 stays empty).

## 4. DCSync

**Why it works:** the replication extended rights let any holder ask a DC for every password hash,
including `krbtgt`.

**Fix:** only domain controllers (and an Entra Connect sync account, if used) should hold these rights.

```powershell
$dn    = (Get-ADDomain).DistinguishedName
$guids = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'
(Get-Acl "AD:\$dn").Access |
    Where-Object { $_.ObjectType.Guid -in $guids } |
    Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
```

Review the output, then remove any identity that isn't expected (in the lab, `r.replicator`) using
Active Directory Users and Computers → domain root → Properties → Security → Advanced.

**Verify:** `impacket-secretsdump ... -just-dc-user krbtgt` fails with access denied.

## 5. LSASS credential dumping

**Fix (each endpoint, via GPO in production)**
- **LSA protection:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` → `RunAsPPL` = `1` (DWORD), then reboot.
- **Credential Guard:** enable through Group Policy (Device Guard → Turn On Virtualization Based Security)
  on hardware that supports it.
- **Defender ASR rule** "Block credential stealing from the Windows local security authority subsystem":

```powershell
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 `
                 -AttackSurfaceReductionRules_Actions Enabled
```

**Verify:** re-run the Atomic T1003.001 tests. The dump fails or returns an empty file, and Sysmon EID 10
still shows the attempt.

## 6. Lateral movement with local admin accounts

**Fix**
- **Windows LAPS** gives every computer a unique, rotating local admin password:

```powershell
Update-LapsADSchema
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,$((Get-ADDomain).DistinguishedName)"
# Then enable the "Configure password backup directory" GPO setting -> Active Directory
```

- GPO: **Deny access to this computer from the network** for `Local account and member of Administrators group`
  (SID `S-1-5-114`).
- Windows Firewall: block inbound SMB (445) between workstations; allow it only from admin jump hosts.

**Verify:** PsExec from WIN11-01 to WIN11-02 with a local admin account fails. Get the rotated password with
`Get-LapsADPassword -Identity WIN11-02 -AsPlainText`.

## 7. Tiered administration

- **Tier 0:** domain controllers and AD admins. These accounts never log on to workstations or servers.
- **Tier 1:** server admins. **Tier 2:** workstation and helpdesk admins.
- Enforce it with GPO "Deny log on locally / through Remote Desktop" for higher-tier accounts on lower tiers.
- Add Tier 0 accounts to the **Protected Users** group (no NTLM, no RC4, no credential caching).

## Before and after

After applying the fixes, run the whole [emulation plan](../emulation/emulation-plan.md) again and
record the results in [`results/README.md`](../results/README.md) in two columns: *attack succeeded?* and
*detection fired?*. The goal is **No** and **Yes**: the attack fails, but you still see it.
