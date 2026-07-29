# Automated probe (no elevation needed). Demonstrates all three client-cert behaviors on :443,
# selected purely by the SNI-scoped netsh binding + one app decision -- and then shows the HTTP/2
# contrast that is the whole point: the IN-HANDSHAKE host works over HTTP/2, the DELAYED (PHA) host
# does not, because HTTP/2 forbids post-handshake authentication.
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"

$certDir  = Resolve-Path (Join-Path $PSScriptRoot "..\certs")
$manifest = Get-Content (Join-Path $certDir "manifest.json") | ConvertFrom-Json

# Client cert from the store (persisted key Schannel can use); fall back to the PFX with PersistKeySet.
$client = Get-Item "Cert:\CurrentUser\My\$($manifest.clientThumbprint)" -ErrorAction SilentlyContinue
if (-not $client) {
    $pwd = ConvertTo-SecureString $manifest.pfxPassword -AsPlainText -Force
    $client = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Join-Path $certDir "client.pfx"), $pwd,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
}

function Probe($url, [bool]$withCert, [string]$httpVersion) {
    $h = [System.Net.Http.HttpClientHandler]::new()
    $h.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
    if ($withCert) { [void]$h.ClientCertificates.Add($client) }
    $c = [System.Net.Http.HttpClient]::new($h)
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $url)
    $req.Version = [Version]$httpVersion
    $req.VersionPolicy = [System.Net.Http.HttpVersionPolicy]::RequestVersionExact
    Write-Host ("### {0}  (HTTP/{1}, client offers cert: {2})" -f $url, $httpVersion, $withCert) -ForegroundColor Cyan
    try {
        $resp = $c.SendAsync($req).GetAwaiter().GetResult()
        $html = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $banner = ([regex]::Match($html, '<div class="banner">(.*?)</div>')).Groups[1].Value -replace '&mdash;','-'
        $cert   = ([regex]::Match($html, 'Client cert</td><td>(.*?)</td>')).Groups[1].Value -replace '<[^>]+>',''
        Write-Host ("  {0}" -f $banner)
        Write-Host ("  client cert : {0}" -f ($cert.Trim() -replace '&mdash;','-'))
    } catch {
        $msg = $_.Exception.InnerException?.Message; if (-not $msg) { $msg = $_.Exception.Message }
        Write-Host ("  REQUEST FAILED: {0}" -f $msg) -ForegroundColor Red
    } finally { $c.Dispose(); $h.Dispose() }
}

Write-Host "`n=========================================================================" -ForegroundColor DarkGray
Write-Host " HTTP/1.1 -- all three behaviors succeed (PHA-capable client)" -ForegroundColor White
Write-Host "=========================================================================" -ForegroundColor DarkGray
Probe "https://certauth.local/" $true  "1.1"   # enable  -> in-handshake mTLS  -> CN=demo-client
Probe "https://delay.local/"    $true  "1.1"   # disable -> delayed / PHA      -> CN=demo-client (via renegotiation)
Probe "https://nocert.local/"   $true  "1.1"   # disable -> app never asks     -> no client cert
Probe "https://127.0.0.1/"      $true  "1.1"   # ipport  -> no in-handshake    -> no client cert

Write-Host "`n=========================================================================" -ForegroundColor DarkGray
Write-Host " HTTP/2 -- the contrast that proves the binding problem" -ForegroundColor White
Write-Host " in-handshake WORKS over HTTP/2; delayed/PHA CANNOT (HTTP/2 forbids PHA)" -ForegroundColor White
Write-Host "=========================================================================" -ForegroundColor DarkGray
Probe "https://certauth.local/" $true  "2.0"   # in-handshake -> succeeds, CN=demo-client
Probe "https://delay.local/"    $true  "2.0"   # delayed/PHA  -> EXPECTED to fail over HTTP/2

Write-Host "`nTakeaway: TLS 1.3 client-cert auth works on 443 for EVERY client when the cert is" -ForegroundColor DarkGray
Write-Host "requested IN the handshake (certauth.local). The delayed/PHA path (delay.local) is what" -ForegroundColor DarkGray
Write-Host "breaks HTTP/2 and TLS 1.3 async clients -- the real reason behind the 7443 proposal --" -ForegroundColor DarkGray
Write-Host "and it is fixed by an SNI-scoped in-handshake binding, no second port required." -ForegroundColor DarkGray
Write-Host "`n(Visual proof: browse https://certauth.local/ in Edge/Chrome -> certificate prompt;" -ForegroundColor DarkGray
Write-Host " https://nocert.local/ -> no prompt; https://delay.local/ -> may error in a browser," -ForegroundColor DarkGray
Write-Host " which is exactly the post-handshake regression this demonstrates.)" -ForegroundColor DarkGray
