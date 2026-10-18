#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Turns on the Windows audit subcategories and PowerShell logging the lab detections depend on.
#>
$ErrorActionPreference = 'Stop'

$subcategories = @(
    'Credential Validation',            # 4776
    'Kerberos Authentication Service',  # 4768  (AS-REP roasting)
    'Kerberos Service Ticket Operations', # 4769 (Kerberoasting)
    'Logon',                            # 4624 / 4625
    'Security Group Management',        # 4732 (local admin added)
    'User Account Management',          # 4720 etc.
    'Process Creation',                 # 4688
    'Other Object Access Events',       # 4698 (scheduled task created)
    'Directory Service Access',         # 4662 (DCSync) - DCs only
    'Security System Extension'         # 4697 (service installed)
)
foreach ($s in $subcategories) {
    auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null
    Write-Host "Auditing enabled: $s"
}

# Include the command line in 4688 events
New-Item -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord

# PowerShell script block and module logging
$ps = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
New-Item -Path "$ps\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$ps\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
New-Item -Path "$ps\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$ps\ModuleLogging" -Name 'EnableModuleLogging' -Value 1 -Type DWord
Set-ItemProperty -Path "$ps\ModuleLogging\ModuleNames" -Name '*' -Value '*'

Write-Host 'Audit policy and PowerShell logging configured.' -ForegroundColor Green
