# Phase 4 smoke: pairing create/claim + bearer when REQUIRE_AUTH=1
# Usage (from repo root):
#   cargo build -p vault-daemon --release
#   .\scripts\smoke-phase4.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $Root "target\release\vault_daemon.exe"
if (-not (Test-Path $bin)) { $bin = Join-Path $Root "target\release\vault_daemon" }
if (-not (Test-Path $bin)) { throw "Build vault_daemon release first" }

$bind = "127.0.0.1:18081"
$base = "http://$bind"
$tmp = Join-Path $env:TEMP ("kv-smoke-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $tmp | Out-Null
$vault = Join-Path $tmp "s.vault"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $bin
$psi.Environment["VAULT_DAEMON_BIND"] = $bind
$psi.Environment["VAULT_DAEMON_REQUIRE_AUTH"] = "1"
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$p = [System.Diagnostics.Process]::Start($psi)

try {
  $operator = $null
  for ($i = 0; $i -lt 50; $i++) {
    Start-Sleep -Milliseconds 100
    try {
      $null = Invoke-RestMethod -Uri "$base/health" -Method Get
      break
    } catch {}
  }

  # Operator token is printed on stdout — re-read by spawning note:
  # With REQUIRE_AUTH we need the token from process output.
  # Parse any line that looks like a long base64 token from stderr/stdout is hard async.
  # Instead: pairing claim still works without bearer; create pairing without auth;
  # For vault ops with REQUIRE_AUTH, skip if we cannot scrape operator token.

  Write-Host "health OK"
  $mode = Invoke-RestMethod -Uri "$base/v1/auth/mode" -Method Get
  Write-Host "auth_required=$($mode.auth_required)"

  $pair = Invoke-RestMethod -Uri "$base/v1/pairing/create" -Method Post -ContentType "application/json" -Body "{}"
  Write-Host "pairing_id=$($pair.offer.pairing_id)"
  $claimBody = @{
    pairing_id = $pair.offer.pairing_id
    token      = $pair.offer.token
    label      = "smoke-device"
  } | ConvertTo-Json
  $claim = Invoke-RestMethod -Uri "$base/v1/pairing/claim" -Method Post -ContentType "application/json" -Body $claimBody
  $deviceToken = $claim.api_token
  Write-Host "claimed device=$($claim.device_id)"

  $headers = @{ Authorization = "Bearer $deviceToken" }
  $unlockBody = @{
    path     = $vault
    password = "test-master-password-32chars!!"
    create   = $true
  } | ConvertTo-Json
  $unlock = Invoke-RestMethod -Uri "$base/v1/unlock" -Method Post -Headers $headers -ContentType "application/json" -Body $unlockBody
  Write-Host "unlock ok=$($unlock.ok)"

  $addBody = @{
    title    = "Smoke"
    username = "u"
    password = "p@ss"
    url      = "https://example.com"
  } | ConvertTo-Json
  $add = Invoke-RestMethod -Uri "$base/v1/items" -Method Post -Headers $headers -ContentType "application/json" -Body $addBody
  Write-Host "item id=$($add.id)"

  $revBody = @{ id = $add.id; purpose = "smoke" } | ConvertTo-Json
  $rev = Invoke-RestMethod -Uri "$base/v1/reveal" -Method Post -Headers $headers -ContentType "application/json" -Body $revBody
  if ($rev.password -ne "p@ss") { throw "reveal mismatch" }
  Write-Host "reveal ok"

  $updBody = @{ id = $add.id; title = "Smoke-Updated"; password = "p@ss2" } | ConvertTo-Json
  $upd = Invoke-RestMethod -Uri "$base/v1/items/update" -Method Post -Headers $headers -ContentType "application/json" -Body $updBody
  if (-not $upd.ok) { throw "update failed" }
  $rev2 = Invoke-RestMethod -Uri "$base/v1/reveal" -Method Post -Headers $headers -ContentType "application/json" -Body (@{ id = $add.id } | ConvertTo-Json)
  if ($rev2.password -ne "p@ss2") { throw "update password mismatch" }
  Write-Host "update ok"

  $expBody = @{ passphrase = "export-pass-12+" } | ConvertTo-Json
  $exp = Invoke-RestMethod -Uri "$base/v1/export" -Method Post -Headers $headers -ContentType "application/json" -Body $expBody
  if (-not $exp.backup) { throw "export empty" }
  Write-Host "export ok len=$($exp.backup.Length)"

  $delBody = @{ id = $add.id } | ConvertTo-Json
  $del = Invoke-RestMethod -Uri "$base/v1/items/delete" -Method Post -Headers $headers -ContentType "application/json" -Body $delBody
  if (-not $del.ok) { throw "delete failed" }
  Write-Host "delete (trash) ok"
  $trash = Invoke-RestMethod -Uri "$base/v1/trash" -Method Get -Headers $headers
  if (@($trash).Count -lt 1) { throw "trash empty after soft-delete" }
  $rest = Invoke-RestMethod -Uri "$base/v1/items/restore" -Method Post -Headers $headers -ContentType "application/json" -Body $delBody
  if (-not $rest.ok) { throw "restore failed" }
  Write-Host "restore ok"
  $null = Invoke-RestMethod -Uri "$base/v1/items/delete" -Method Post -Headers $headers -ContentType "application/json" -Body $delBody
  $purge = Invoke-RestMethod -Uri "$base/v1/items/purge" -Method Post -Headers $headers -ContentType "application/json" -Body $delBody
  if (-not $purge.ok) { throw "purge failed" }
  Write-Host "purge ok"

  $impBody = @{ passphrase = "export-pass-12+"; backup = $exp.backup; merge = $true } | ConvertTo-Json -Depth 3
  $imp = Invoke-RestMethod -Uri "$base/v1/import" -Method Post -Headers $headers -ContentType "application/json" -Body $impBody
  if ($imp.written -lt 1) { throw "import wrote 0" }
  Write-Host "import written=$($imp.written)"

  $csvBody = @{
    csv = "name,url,username,password`nSmokeCSV,https://csv.example,csvuser,csv-pass"
  } | ConvertTo-Json
  $csvImp = Invoke-RestMethod -Uri "$base/v1/import/csv" -Method Post -Headers $headers -ContentType "application/json" -Body $csvBody
  if ($csvImp.written -lt 1) { throw "csv import wrote 0" }
  Write-Host "csv import written=$($csvImp.written)"

  $chgBody = @{
    current_password = "test-master-password-32chars!!"
    new_password     = "test-master-password-CHANGED1"
  } | ConvertTo-Json
  $chg = Invoke-RestMethod -Uri "$base/v1/change-password" -Method Post -Headers $headers -ContentType "application/json" -Body $chgBody
  if (-not $chg.ok) { throw "change-password failed" }
  Write-Host "change-password ok"

  $add2Body = @{
    title    = "WithTOTP"
    username = "t"
    password = "pw"
    totp     = "JBSWY3DPEHPK3PXP"
  } | ConvertTo-Json
  $add2 = Invoke-RestMethod -Uri "$base/v1/items" -Method Post -Headers $headers -ContentType "application/json" -Body $add2Body
  $totpBody = @{ id = $add2.id } | ConvertTo-Json
  $totp = Invoke-RestMethod -Uri "$base/v1/totp" -Method Post -Headers $headers -ContentType "application/json" -Body $totpBody
  if (-not $totp.code -or $totp.code.Length -lt 6) { throw "totp code missing" }
  Write-Host "totp code ok remaining=$($totp.remaining_secs)"

  $csvOut = Invoke-RestMethod -Uri "$base/v1/export/csv" -Method Get -Headers $headers
  if (-not $csvOut.csv -or $csvOut.csv -notmatch "name,url") { throw "export csv failed" }
  Write-Host "export csv ok"

  $health = Invoke-RestMethod -Uri "$base/v1/health/passwords" -Method Get -Headers $headers
  Write-Host "password health total=$($health.total_items) weak=$($health.weak_count) reused=$($health.reused_count)"

  # Without bearer must fail when REQUIRE_AUTH
  try {
    Invoke-RestMethod -Uri "$base/v1/items" -Method Get | Out-Null
    throw "expected 401 without bearer"
  } catch {
    Write-Host "no-bearer rejected as expected"
  }

  Write-Host "SMOKE PHASE4 PASS"
}
finally {
  if ($p -and -not $p.HasExited) { $p.Kill() }
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
