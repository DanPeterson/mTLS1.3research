# Requires ELEVATION. Configures this machine to run the mTLS-on-443 demo:
#   - imports the server cert (private key) for HTTP.sys, and trusts it for browsers
#   - imports the client cert so a browser will offer it
#   - adds hosts entries for the demo hostnames (no DNS needed)
#   - creates three netsh sslcert bindings on :443 that differ ONLY by clientcertnegotiation
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Run this script from an ELEVATED PowerShell (Run as Administrator)."
    }
}
Assert-Admin

$certDir  = Resolve-Path (Join-Path $PSScriptRoot "..\certs")
$manifest = Get-Content (Join-Path $certDir "manifest.json") | ConvertFrom-Json
$pwd      = ConvertTo-SecureString $manifest.pfxPassword -AsPlainText -Force
$hostsFile= "$env:SystemRoot\System32\drivers\etc\hosts"
$marker   = "# mTLS1.3research-demo"

Write-Host "== Importing server cert -> LocalMachine\My (for HTTP.sys) ==" -ForegroundColor Cyan
Import-PfxCertificate -FilePath (Join-Path $certDir "server.pfx") -CertStoreLocation "Cert:\LocalMachine\My" -Password $pwd | Out-Null

Write-Host "== Trusting server cert -> LocalMachine\Root (so browsers show no TLS warning) ==" -ForegroundColor Cyan
Import-Certificate -FilePath (Join-Path $certDir "server.cer") -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null

Write-Host "== Trusting client cert -> LocalMachine\Root (so the server fully validates the mTLS client chain) ==" -ForegroundColor Cyan
Import-Certificate -FilePath (Join-Path $certDir "client.cer") -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null

Write-Host "== Importing client cert -> CurrentUser\My (so a browser will offer it) ==" -ForegroundColor Cyan
Import-PfxCertificate -FilePath (Join-Path $certDir "client.pfx") -CertStoreLocation "Cert:\CurrentUser\My" -Password $pwd | Out-Null

Write-Host "== Adding hosts entries ==" -ForegroundColor Cyan
$lines = Get-Content $hostsFile
if ($lines -notmatch [regex]::Escape($marker)) {
    foreach ($h in $manifest.hostnames) { Add-Content $hostsFile "127.0.0.1 $h $marker" }
    Write-Host "  $($manifest.hostnames -join ', ') -> 127.0.0.1"
} else { Write-Host "  hosts entries already present" }

Write-Host "== Creating netsh sslcert bindings on :443 ==" -ForegroundColor Cyan
$hash = $manifest.serverThumbprint
$app  = $manifest.appid
netsh http delete sslcert hostnameport=certauth.local:443 2>$null | Out-Null
netsh http delete sslcert hostnameport=delay.local:443    2>$null | Out-Null
netsh http delete sslcert ipport=0.0.0.0:443              2>$null | Out-Null
# certauth.local => request the client cert IN the handshake (opt-in mTLS)
netsh http add sslcert hostnameport=certauth.local:443 certhash=$hash appid=$app certstorename=MY clientcertnegotiation=enable
# delay.local => NO in-handshake request (ordinary primary traffic)
netsh http add sslcert hostnameport=delay.local:443    certhash=$hash appid=$app certstorename=MY clientcertnegotiation=disable
# IP / wildcard fallback => NO in-handshake request
netsh http add sslcert ipport=0.0.0.0:443              certhash=$hash appid=$app certstorename=MY clientcertnegotiation=disable

Write-Host "`n== Bindings now on :443 ==" -ForegroundColor Cyan
netsh http show sslcert | Select-String -Pattern "Hostname:port|IP:port|Negotiate Client Certificate" |
    Where-Object { $_ -match "certauth.local|delay.local|0.0.0.0:443" -or $_ -match "Negotiate" }

Write-Host "`nSetup complete." -ForegroundColor Green
Write-Host "Next (ELEVATED): .\2-run-server.ps1     then browse to https://certauth.local/" -ForegroundColor Yellow
