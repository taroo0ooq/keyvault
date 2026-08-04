# Measure release binary sizes and optional daemon idle RSS (Windows).
# Usage (repo root):
#   cargo build -p vault-daemon -p vault-ffi --release
#   cargo build -p keyvault-desktop --release   # optional
#   .\scripts\measure-footprint.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$targets = @(
    @{ Name = "vault_daemon"; Path = "target\release\vault_daemon.exe"; LimitMB = 15 },
    @{ Name = "vault_ffi"; Path = "target\release\vault_ffi.dll"; LimitMB = 15 },
    @{ Name = "vault_native_host"; Path = "target\release\vault_native_host.exe"; LimitMB = 15 },
    @{ Name = "keyvault-desktop"; Path = "target\release\keyvault-desktop.exe"; LimitMB = 15 }
)

$report = [ordered]@{
    measured_at = (Get-Date).ToString("o")
    platform    = "$([System.Environment]::OSVersion.VersionString) $($env:PROCESSOR_ARCHITECTURE)"
    rustc       = (rustc --version 2>$null)
    targets     = @()
    constraints = @{
        desktop_binary_mb = 15
        idle_ram_mb       = 15
    }
    daemon_idle = $null
}

Write-Host "== Binary sizes =="
foreach ($t in $targets) {
    $p = Join-Path $Root $t.Path
    if (-not (Test-Path $p)) {
        Write-Host "SKIP $($t.Name) (missing $p)"
        $report.targets += @{
            name     = $t.Name
            path     = $t.Path
            present  = $false
        }
        continue
    }
    $item = Get-Item $p
    $mb = [math]::Round($item.Length / 1MB, 3)
    $ok = $mb -lt $t.LimitMB
    Write-Host ("{0,-20} {1,8:N3} MB  {2}" -f $t.Name, $mb, $(if ($ok) { "OK" } else { "OVER LIMIT" }))
    $report.targets += @{
        name       = $t.Name
        path       = $t.Path
        present    = $true
        bytes      = $item.Length
        megabytes  = $mb
        limit_mb   = $t.LimitMB
        under_limit = $ok
    }
}

# Idle RSS: start daemon briefly
$daemon = Join-Path $Root "target\release\vault_daemon.exe"
if (Test-Path $daemon) {
    Write-Host ""
    Write-Host "== Daemon idle RSS (approx) =="
    $bind = "127.0.0.1:18099"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $daemon
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.Environment["VAULT_DAEMON_BIND"] = $bind
    $proc = [System.Diagnostics.Process]::Start($psi)
    try {
        $healthy = $false
        for ($i = 0; $i -lt 40; $i++) {
            Start-Sleep -Milliseconds 100
            try {
                $null = Invoke-WebRequest -Uri "http://$bind/health" -UseBasicParsing -TimeoutSec 1
                $healthy = $true
                break
            } catch {}
        }
        Start-Sleep -Milliseconds 500
        $proc.Refresh()
        $ws = $proc.WorkingSet64
        $mb = [math]::Round($ws / 1MB, 3)
        $ok = $mb -lt 15
        Write-Host ("vault_daemon WorkingSet {0:N3} MB  healthy={1}  {2}" -f $mb, $healthy, $(if ($ok) { "OK" } else { "OVER LIMIT" }))
        $report.daemon_idle = @{
            working_set_bytes = $ws
            working_set_mb    = $mb
            healthy           = $healthy
            under_limit       = $ok
            note              = "WorkingSet64 after /health; not full product idle with UI"
        }
    } finally {
        if (-not $proc.HasExited) { $proc.Kill() }
        $proc.Dispose()
    }
}

$outDir = Join-Path $Root "docs"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$outJson = Join-Path $outDir "footprint-report.json"
$report | ConvertTo-Json -Depth 6 | Set-Content -Path $outJson -Encoding utf8
Write-Host ""
Write-Host "Wrote $outJson"
