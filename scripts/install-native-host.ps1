# Register Chrome native messaging host for KeyVault (current user).
# Usage:
#   cargo build -p vault-native-host --release
#   .\scripts\install-native-host.ps1 -ExtensionId <chrome-extension-id>

param(
    [Parameter(Mandatory = $true)]
    [string]$ExtensionId,
    [string]$HostExe = "",
    [string]$Browser = "Chrome"  # Chrome | Chromium | Edge
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

if (-not $HostExe) {
    $HostExe = Join-Path $Root "target\release\vault_native_host.exe"
}
if (-not (Test-Path $HostExe)) {
    throw "Host binary not found: $HostExe — run: cargo build -p vault-native-host --release"
}

$HostExe = (Resolve-Path $HostExe).Path
$InstallDir = Join-Path $env:LOCALAPPDATA "KeyVault"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$ManifestPath = Join-Path $InstallDir "app.keyvault.native.json"
$origin = "chrome-extension://$ExtensionId/"
$manifest = @{
    name            = "app.keyvault.native"
    description     = "KeyVault native messaging host — proxies to loopback vault_daemon"
    path            = $HostExe
    type            = "stdio"
    allowed_origins = @($origin)
} | ConvertTo-Json -Depth 4

Set-Content -Path $ManifestPath -Value $manifest -Encoding UTF8

$regPaths = @{
    Chrome   = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\app.keyvault.native"
    Chromium = "HKCU:\Software\Chromium\NativeMessagingHosts\app.keyvault.native"
    Edge     = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\app.keyvault.native"
}

$key = $regPaths[$Browser]
if (-not $key) { throw "Unknown browser: $Browser (Chrome|Chromium|Edge)" }

New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name "(default)" -Value $ManifestPath

Write-Host "Installed native host manifest: $ManifestPath"
Write-Host "Registered: $key"
Write-Host "Host: $HostExe"
Write-Host "Origin: $origin"
Write-Host "Restart the browser, then ensure vault_daemon is running on 127.0.0.1:8080."
