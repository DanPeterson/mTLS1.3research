# Automated probe (no elevation needed). Presents the client cert to each endpoint on :443
# and prints what the server reports back. The ONLY difference between endpoints is the
# netsh clientcertnegotiation flag on the binding each SNI / IP resolves to.
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"

$certDir  = Resolve-Path (Join-Path $PSScriptRoot "..\certs")
$manifest = Get-Content (Join-Path $certDir "manifest.json") | ConvertFrom-Json

# Prefer the client cert from the store (persisted key Schannel can use for client auth);
# fall back to the PFX with a persisted key set.
$client = Get-Item "Cert:\CurrentUser\My\$($manifest.clientThumbprint)" -ErrorAction SilentlyContinue
if (-not $client) {
    $pwd = ConvertTo-SecureString $manifest.pfxPassword -AsPlainText -Force
    $client = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Join-Path $certDir "client.pfx"), $pwd,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
}

function Probe($url, [bool]$withCert) {
    $h = [System.Net.Http.HttpClientHandler]::new()
    $h.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
    if ($withCert) { [void]$h.ClientCertificates.Add($client) }
    $c = [System.Net.Http.HttpClient]::new($h)
    Write-Host "`n### $url   (client offers cert: $withCert)" -ForegroundColor Cyan
    try {
        $html = $c.GetStringAsync($url).GetAwaiter().GetResult()
        $banner = ([regex]::Match($html, '<div class="banner">(.*?)</div>')).Groups[1].Value -replace '&mdash;','-'
        $cert   = ([regex]::Match($html, 'Client cert</td><td>(.*?)</td>')).Groups[1].Value -replace '<[^>]+>',''
        Write-Host ("  {0}" -f $banner)
        Write-Host ("  client cert : {0}" -f ($cert.Trim()))
    } catch {
        Write-Host "  REQUEST FAILED: $($_.Exception.Message)" -ForegroundColor Red
    } finally { $c.Dispose(); $h.Dispose() }
}

Probe "https://certauth.local/" $true    # enable  -> expect client cert: CN=demo-client
Probe "https://delay.local/"    $true    # disable -> expect not requested
Probe "https://127.0.0.1/"      $true    # ipport  -> expect not requested
Probe "https://certauth.local/" $false   # enable, no cert offered -> expect no client cert presented

Write-Host "`n(For the visual proof, browse to https://certauth.local/ in Edge/Chrome: you get a" -ForegroundColor DarkGray
Write-Host " certificate prompt. https://delay.local/ and https://127.0.0.1/ do not prompt.)" -ForegroundColor DarkGray
