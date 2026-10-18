#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs Sysmon with the SwiftOnSecurity community config (or updates the config if already installed).
#>
[CmdletBinding()]
param(
    [string]$WorkDir = "$env:TEMP\sysmon-install"
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$zip    = Join-Path $WorkDir 'Sysmon.zip'
$config = Join-Path $WorkDir 'sysmonconfig.xml'

Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip
Expand-Archive $zip -DestinationPath $WorkDir -Force
Invoke-WebRequest 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile $config

$exe = Join-Path $WorkDir 'Sysmon64.exe'

if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
    Write-Host 'Sysmon already installed - updating configuration.'
    & $exe -c $config
} else {
    & $exe -accepteula -i $config
}

Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 | Format-List TimeCreated, Id, Message
Write-Host 'Sysmon is logging.' -ForegroundColor Green
