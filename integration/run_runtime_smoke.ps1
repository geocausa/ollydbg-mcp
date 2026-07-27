[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OllyDir,

    [Parameter(Mandatory = $true)]
    [string]$PluginDir,

    [Parameter(Mandatory = $true)]
    [string]$SdkDir,

    [string]$OutputDir = (Join-Path $PSScriptRoot "..\build\runtime-smoke"),

    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 30,

    [switch]$AllowMutations,
    [switch]$AllowExecution,
    [switch]$RestartOlly,
    [switch]$SkipIniUpdate
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ollyPath = (Resolve-Path -LiteralPath $OllyDir).Path
$sdkPath = (Resolve-Path -LiteralPath $SdkDir).Path
$outputPath = [System.IO.Path]::GetFullPath($OutputDir)
$pluginOutput = Join-Path $outputPath "plugin"
$targetOutput = Join-Path $outputPath "target"
$pluginBuild = Join-Path $root "plugin_stub\build_plugin.ps1"
$targetBuild = Join-Path $root "integration\build_smoke_target.ps1"
$launcher = Join-Path $root "start_olly_bridge.ps1"
$pluginDll = Join-Path $pluginOutput "OllyBridge110.dll"
$targetExe = Join-Path $targetOutput "olly_smoke_target.exe"
$manifest = Join-Path $targetOutput "olly_smoke_manifest.json"
$report = Join-Path $outputPath "olly_smoke_report.json"

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (!(Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    throw "Visual Studio Installer vswhere.exe was not found: $vswhere"
}
$vsInstall = (& $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath | Select-Object -First 1)
if (!$vsInstall) {
    throw "Visual Studio C++ x86 build tools were not found."
}
$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvarsall.bat"
if (!(Test-Path -LiteralPath $vcvars -PathType Leaf)) {
    throw "vcvarsall.bat was not found: $vcvars"
}

New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
$commandFile = Join-Path $outputPath "build_runtime_smoke.cmd"
$commandText = @"
@echo off
call "$vcvars" x86 >nul
if errorlevel 1 exit /b %errorlevel%
powershell -NoProfile -ExecutionPolicy Bypass -File "$pluginBuild" -SdkDir "$sdkPath" -OutputDir "$pluginOutput"
if errorlevel 1 exit /b %errorlevel%
powershell -NoProfile -ExecutionPolicy Bypass -File "$targetBuild" -OutputDir "$targetOutput"
if errorlevel 1 exit /b %errorlevel%
"@
[System.IO.File]::WriteAllText($commandFile, $commandText, [System.Text.Encoding]::ASCII)
try {
    & cmd.exe /D /C $commandFile
    if ($LASTEXITCODE -ne 0) {
        throw "Runtime smoke build failed with exit code $LASTEXITCODE"
    }
}
finally {
    Remove-Item -LiteralPath $commandFile -Force -ErrorAction SilentlyContinue
}

$launcherArgs = @{
    TargetExe = $targetExe
    Workspace = $root
    OllyDir = $ollyPath
    PluginDir = $PluginDir
    PluginDllPath = $pluginDll
    SkipServer = $true
}
if ($RestartOlly) {
    $launcherArgs.RestartOlly = $true
}
if ($SkipIniUpdate) {
    $launcherArgs.SkipIniUpdate = $true
}
& $launcher @launcherArgs

$python = Get-Command python -ErrorAction Stop
$smokeArgs = @(
    "-m",
    "ollydbg_mcp.smoke",
    "--manifest",
    $manifest,
    "--timeout",
    [string]$TimeoutSeconds,
    "--output",
    $report
)
if ($AllowMutations) {
    $smokeArgs += "--allow-mutations"
}
if ($AllowExecution) {
    $smokeArgs += "--allow-execution"
}

Push-Location $root
try {
    & $python.Source @smokeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "OllyDbg runtime smoke test failed. Report: $report"
    }
}
finally {
    Pop-Location
}

Write-Host "Runtime smoke test passed."
Write-Host "Report: $report"
