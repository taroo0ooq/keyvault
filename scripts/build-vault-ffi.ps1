# Build vault_ffi for host and (optionally) Android targets.
# Usage:
#   .\scripts\build-vault-ffi.ps1
#   .\scripts\build-vault-ffi.ps1 -Android
#   .\scripts\build-vault-ffi.ps1 -Android -CopyToFlutter

param(
    [switch]$Android,
    [switch]$CopyToFlutter,
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$profile = if ($Release) { "release" } else { "release" }
$cargoArgs = @("build", "-p", "vault-ffi", "--release")

Write-Host "==> Host vault_ffi ($profile)"
& cargo @cargoArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$hostLib = if ($IsWindows -or $env:OS -match "Windows") {
    Join-Path $Root "target\release\vault_ffi.dll"
} elseif ($IsMacOS) {
    Join-Path $Root "target/release/libvault_ffi.dylib"
} else {
    Join-Path $Root "target/release/libvault_ffi.so"
}
Write-Host "Host library: $hostLib"

if ($Android) {
    $targets = @(
        "aarch64-linux-android",
        "armv7-linux-androideabi",
        "x86_64-linux-android"
    )
    $installed = & rustup target list --installed
    foreach ($t in $targets) {
        if ($installed -notcontains $t) {
            Write-Host "Installing Rust target $t"
            rustup target add $t
        }
    }

    if (-not $env:ANDROID_NDK_HOME -and $env:ANDROID_HOME) {
        $ndkRoot = Join-Path $env:ANDROID_HOME "ndk"
        if (Test-Path $ndkRoot) {
            $latest = Get-ChildItem $ndkRoot | Sort-Object Name -Descending | Select-Object -First 1
            if ($latest) { $env:ANDROID_NDK_HOME = $latest.FullName }
        }
    }
    if (-not $env:ANDROID_NDK_HOME) {
        Write-Warning "ANDROID_NDK_HOME not set — Android cross-compile may fail. Install NDK and re-run."
    }

    foreach ($t in $targets) {
        Write-Host "==> Android target $t"
        & cargo build -p vault-ffi --release --target $t
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Failed building $t (install cargo-ndk / NDK linker if needed)"
        }
    }
}

if ($CopyToFlutter) {
    $jni = Join-Path $Root "apps\mobile\android\app\src\main\jniLibs"
    $map = @{
        "aarch64-linux-android"   = "arm64-v8a"
        "armv7-linux-androideabi" = "armeabi-v7a"
        "x86_64-linux-android"    = "x86_64"
    }
    foreach ($t in $map.Keys) {
        $src = Join-Path $Root "target\$t\release\libvault_ffi.so"
        if (Test-Path $src) {
            $abi = $map[$t]
            $destDir = Join-Path $jni $abi
            New-Item -ItemType Directory -Force -Path $destDir | Out-Null
            Copy-Item $src (Join-Path $destDir "libvault_ffi.so") -Force
            Write-Host "Copied $src -> $destDir"
        }
    }
    # Host Windows DLL for flutter windows/desktop debug convenience
    $winOut = Join-Path $Root "apps\mobile\windows\runner"
    if ((Test-Path $hostLib) -and (Test-Path $winOut)) {
        Copy-Item $hostLib (Join-Path $winOut "vault_ffi.dll") -Force
        Write-Host "Copied host DLL next to windows runner"
    }
}

Write-Host "Done."
