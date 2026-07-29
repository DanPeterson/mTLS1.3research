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

# Minimal request helper for the clean-design flow: optional client cert, optional bearer token.
# Returns the HTTP status code and raw body so we can show cert-once -> bearer-thereafter.
function Send($url, [bool]$withCert, [string]$bearer) {
    $h = [System.Net.Http.HttpClientHandler]::new()
    $h.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
    if ($withCert) { [void]$h.ClientCertificates.Add($client) }
    $c = [System.Net.Http.HttpClient]::new($h)
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $url)
    if ($bearer) { $req.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new("Bearer", $bearer) }
    try {
        $resp = $c.SendAsync($req).GetAwaiter().GetResult()
        $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return [pscustomobject]@{ Status = [int]$resp.StatusCode; Body = $body }
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
Write-Host " in-handshake authenticates over HTTP/2; delayed/PHA gets NO cert (HTTP/2 forbids PHA)" -ForegroundColor White
Write-Host "=========================================================================" -ForegroundColor DarkGray
Probe "https://certauth.local/" $true  "2.0"   # in-handshake -> succeeds, CN=demo-client
Probe "https://delay.local/"    $true  "2.0"   # delayed/PHA  -> server gets NO cert over HTTP/2 (auth fails)

Write-Host "`n=========================================================================" -ForegroundColor DarkGray
Write-Host " CLEAN DESIGN -- authenticate once with the cert, then use a bearer token" -ForegroundColor White
Write-Host " same cert SNI (certauth.local), cert required ONLY at /token; /api/whoami is bearer-only" -ForegroundColor White
Write-Host "=========================================================================" -ForegroundColor DarkGray

# 1. Present the client cert IN the handshake to the token endpoint -> receive a simulated bearer.
$r1 = Send "https://certauth.local/token" $true $null
Write-Host ("### /token  WITH client cert           -> HTTP {0}" -f $r1.Status) -ForegroundColor Cyan
$token = $null
if ($r1.Status -eq 200) { $token = ($r1.Body | ConvertFrom-Json).access_token }
Write-Host ("  issued access_token : {0}" -f $token)

# 2. THE POINT: call the SAME cert-SNI host with NO client cert, carrying only the bearer -> 200.
$r2 = Send "https://certauth.local/api/whoami" $false $token
Write-Host ("### /api/whoami  NO cert + bearer       -> HTTP {0}" -f $r2.Status) -ForegroundColor Cyan
Write-Host ("  {0}" -f $r2.Body)

# 3. Negative: token endpoint enforces the cert requirement (no cert -> 403).
$r3 = Send "https://certauth.local/token" $false $null
Write-Host ("### /token  WITHOUT cert (negative)     -> HTTP {0}  (expect 403)" -f $r3.Status) -ForegroundColor Cyan

# 4. Negative: resource endpoint enforces the bearer (no token -> 401).
$r4 = Send "https://certauth.local/api/whoami" $false $null
Write-Host ("### /api/whoami  WITHOUT bearer (neg)   -> HTTP {0}  (expect 401)" -f $r4.Status) -ForegroundColor Cyan

Write-Host "`nTakeaway: TLS 1.3 client-cert auth works on 443 for EVERY client when the cert is" -ForegroundColor DarkGray
Write-Host "requested IN the handshake (certauth.local). The delayed/PHA path (delay.local) is what" -ForegroundColor DarkGray
Write-Host "breaks HTTP/2 and TLS 1.3 async clients -- the real reason behind the 7443 proposal --" -ForegroundColor DarkGray
Write-Host "and it is fixed by an SNI-scoped in-handshake binding, no second port required." -ForegroundColor DarkGray
Write-Host "`nClean design: the cert is required only to MINT a token (/token). Every API call after that" -ForegroundColor DarkGray
Write-Host "carries a bearer and needs no client cert -- on the SAME cert-SNI hostname. So SafeguardJava" -ForegroundColor DarkGray
Write-Host "et al. keep 'authenticate once, then bearer' with no hostname switch (enable + allow)." -ForegroundColor DarkGray
Write-Host "`n(Visual proof: browse https://certauth.local/ in Edge/Chrome -> certificate prompt;" -ForegroundColor DarkGray
Write-Host " https://nocert.local/ -> no prompt; https://delay.local/ -> over HTTP/2 the browser gets" -ForegroundColor DarkGray
Write-Host " NO client cert (auth silently fails) -- exactly the post-handshake regression shown here.)" -ForegroundColor DarkGray
