#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Seeds a LAB domain with deliberate weaknesses so each AD detection can be tested.

.DESCRIPTION
    WARNING: makes the domain insecure on purpose. Run ONLY on an isolated lab domain controller.

    Creates:
      svc_sql      - service account with an SPN and RC4 enabled        -> Kerberoasting (T1558.003)
      j.noprauth   - user with pre-authentication disabled              -> AS-REP roasting (T1558.004)
      spray01..20  - users sharing a weak seasonal password             -> password spraying (T1110.003)
      r.replicator - normal user granted replication rights on domain   -> DCSync (T1003.006)
#>
[CmdletBinding()]
param(
    [string]$OU = 'LabUsers',
    [string]$WeakPassword = 'Autumn2026!'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domain  = Get-ADDomain
$dn      = $domain.DistinguishedName
$ouPath  = "OU=$OU,$dn"
$secure  = ConvertTo-SecureString $WeakPassword -AsPlainText -Force

if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$OU'" -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $OU -Path $dn -ProtectedFromAccidentalDeletion $false
}

function New-LabUser([string]$Sam) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $Sam -SamAccountName $Sam -Path $ouPath -AccountPassword $secure `
                   -Enabled $true -PasswordNeverExpires $true
    }
    Get-ADUser $Sam
}

# Kerberoastable service account (RC4 = encryption type 4)
$svc = New-LabUser 'svc_sql'
Set-ADUser $svc -ServicePrincipalNames @{Add = "MSSQLSvc/sql01.$($domain.DNSRoot):1433"} `
                -Replace @{'msDS-SupportedEncryptionTypes' = 4}

# AS-REP roastable user
$asrep = New-LabUser 'j.noprauth'
Set-ADAccountControl $asrep -DoesNotRequirePreAuth $true

# Password spraying targets
1..20 | ForEach-Object { New-LabUser ('spray{0:D2}' -f $_) | Out-Null }

# DCSync rights for a regular user
$rep = New-LabUser 'r.replicator'
$acl = Get-Acl "AD:\$dn"
$sid = New-Object System.Security.Principal.SecurityIdentifier $rep.SID
foreach ($guid in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid, 'ExtendedRight', 'Allow', [Guid]$guid)
    $acl.AddAccessRule($rule)
}
Set-Acl "AD:\$dn" $acl

Write-Host "Lab weaknesses created in $ouPath." -ForegroundColor Yellow
Write-Host 'Enable "Directory Service Access" auditing and a SACL on the domain root for 4662 events.'
