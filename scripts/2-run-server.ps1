# Requires ELEVATION (binding to :443 via HTTP.sys needs admin).
# Starts the demo web server. Leave it running; Ctrl+C to stop.
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"

$p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "Run this script from an ELEVATED PowerShell (Run as Administrator)."
}

$src = Resolve-Path (Join-Path $PSScriptRoot "..\src")
Write-Host "Starting server from $src (https://+:443/). Ctrl+C to stop." -ForegroundColor Cyan
Push-Location $src
try { dotnet run -c Release } finally { Pop-Location }
