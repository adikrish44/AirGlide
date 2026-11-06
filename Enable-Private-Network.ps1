#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$program = Join-Path $PSScriptRoot 'AirGlide.exe'
if (-not (Test-Path $program)) { throw 'Keep this script beside AirGlide.exe.' }
$privateProfiles = @(Get-NetConnectionProfile | Where-Object NetworkCategory -eq 'Private')
if ($privateProfiles.Count -eq 0) { throw 'Your home connection is not marked Private. In Windows Settings, open Network & Internet, select your home network and choose Private, then run this again. Do not do this for a public Wi-Fi network.' }
$hasher = [System.Security.Cryptography.SHA256]::Create()
$hash = [System.BitConverter]::ToString($hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($program))).Replace('-', '').Substring(0, 12)
$name = 'AirGlide-Local-' + $hash
if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {
    Write-Host 'The AirGlide private-network rule already exists.'
} else {
    New-NetFirewallRule -Name $name -DisplayName 'AirGlide - private local network' -Direction Inbound -Action Allow -Program $program -Protocol TCP -LocalPort 43110,43111 -RemoteAddress LocalSubnet -Profile Private | Out-Null
    Write-Host 'Allowed this AirGlide executable on private local networks only.'
}
Write-Host ('To remove this rule later, run in Administrator PowerShell: Remove-NetFirewallRule -Name ' + $name)
