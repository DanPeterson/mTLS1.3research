# Generates the demo certificates used by this package and writes them to .\certs.
# These are THROWAWAY self-signed certs for a local proof-of-concept only -- never production.
# Re-run this any time to regenerate; 1-setup.ps1 imports whatever is here.
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $PSScriptRoot "."),
    [string]$PfxPassword = "demo"
)
$ErrorActionPreference = "Stop"

$pwd = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
$appid = "{7b1e4c2a-9d3f-4a5b-8c6d-0e1f2a3b4c5d}"

Write-Host "Generating server certificate (CN=demo-server; SAN dns=delay.local, dns=certauth.local, ip=127.0.0.1)..."
$srv = New-SelfSignedCertificate `
    -Subject "CN=demo-server" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeyUsage DigitalSignature,KeyEncipherment `
    -TextExtension @(
        "2.5.29.37={text}1.3.6.1.5.5.7.3.1",
        "2.5.29.17={text}dns=delay.local&dns=certauth.local&ipaddress=127.0.0.1"
    ) `
    -NotAfter (Get-Date).AddYears(5)

Write-Host "Generating client certificate (CN=demo-client)..."
$cli = New-SelfSignedCertificate `
    -Subject "CN=demo-client" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeyUsage DigitalSignature `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
    -NotAfter (Get-Date).AddYears(5)

Export-PfxCertificate -Cert $srv -FilePath (Join-Path $OutDir "server.pfx") -Password $pwd | Out-Null
Export-Certificate    -Cert $srv -FilePath (Join-Path $OutDir "server.cer") | Out-Null   # public, for Trusted Root
Export-PfxCertificate -Cert $cli -FilePath (Join-Path $OutDir "client.pfx") -Password $pwd | Out-Null
Export-Certificate    -Cert $cli -FilePath (Join-Path $OutDir "client.cer") | Out-Null   # public, for Trusted Root (server-side mTLS validation)

$manifest = [ordered]@{
    serverThumbprint = $srv.Thumbprint
    clientThumbprint = $cli.Thumbprint
    serverSubject    = "CN=demo-server"
    clientSubject    = "CN=demo-client"
    pfxPassword      = $PfxPassword
    appid            = $appid
    hostnames        = @("delay.local","certauth.local")
    generatedUtc     = (Get-Date).ToUniversalTime().ToString("o")
}
$manifest | ConvertTo-Json | Set-Content (Join-Path $OutDir "manifest.json")

# Remove from the local store -- the exported files are the source of truth.
Remove-Item "Cert:\CurrentUser\My\$($srv.Thumbprint)" -ErrorAction SilentlyContinue
Remove-Item "Cert:\CurrentUser\My\$($cli.Thumbprint)" -ErrorAction SilentlyContinue

Write-Host "Done. Files in $OutDir :"
Get-ChildItem $OutDir -File | Select-Object Name,Length | Format-Table -AutoSize
Write-Host "server thumbprint: $($srv.Thumbprint)"
Write-Host "client thumbprint: $($cli.Thumbprint)"
Write-Host "pfx password     : $PfxPassword"
