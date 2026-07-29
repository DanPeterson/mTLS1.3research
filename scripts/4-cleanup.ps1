# Requires ELEVATION. Undoes everything 1-setup.ps1 did.
[CmdletBinding()]
param()
$ErrorActionPreference = "Continue"

$p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "Run this script from an ELEVATED PowerShell (Run as Administrator)."
}

$certDir  = Resolve-Path (Join-Path $PSScriptRoot "..\certs")
$manifest = Get-Content (Join-Path $certDir "manifest.json") | ConvertFrom-Json
$hostsFile= "$env:SystemRoot\System32\drivers\etc\hosts"
$marker   = "mTLS1.3research-demo"

Write-Host "== Removing netsh sslcert bindings ==" -ForegroundColor Cyan
netsh http delete sslcert hostnameport=certauth.local:443 2>$null
netsh http delete sslcert hostnameport=delay.local:443    2>$null
netsh http delete sslcert hostnameport=nocert.local:443   2>$null
netsh http delete sslcert ipport=0.0.0.0:443              2>$null

Write-Host "== Removing hosts entries ==" -ForegroundColor Cyan
(Get-Content $hostsFile) | Where-Object { $_ -notmatch $marker } | Set-Content $hostsFile

Write-Host "== Removing certificates ==" -ForegroundColor Cyan
Remove-Item "Cert:\LocalMachine\My\$($manifest.serverThumbprint)"   -ErrorAction SilentlyContinue
Remove-Item "Cert:\LocalMachine\Root\$($manifest.serverThumbprint)" -ErrorAction SilentlyContinue
Remove-Item "Cert:\LocalMachine\Root\$($manifest.clientThumbprint)" -ErrorAction SilentlyContinue
Remove-Item "Cert:\CurrentUser\My\$($manifest.clientThumbprint)"    -ErrorAction SilentlyContinue

Write-Host "`nCleanup complete." -ForegroundColor Green
