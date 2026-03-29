param(
    [string]$TargetExe,
    [string]$Workspace = $PSScriptRoot,
    [string]$OllyDir,
    [string]$PluginDir
)

$ErrorActionPreference = "Stop"

$pluginDll = Join-Path $Workspace "OllyBridge110.dll"
$serverPy = Join-Path $Workspace "server.py"

if (!(Test-Path $serverPy)) {
    throw "Could not find server.py under $Workspace"
}

if ([string]::IsNullOrWhiteSpace($OllyDir)) {
    throw "Please provide -OllyDir pointing to your OllyDbg 1.10 folder."
}

if ([string]::IsNullOrWhiteSpace($PluginDir)) {
    throw "Please provide -PluginDir pointing to the plugin directory used by OllyDbg."
}

$iniPath = Join-Path $ollyDir "ollydbg.ini"

if (!(Test-Path $pluginDll)) {
    throw "Could not find OllyBridge110.dll under $Workspace. Build or copy the plugin first."
}

if (!(Test-Path $pluginDir)) {
    New-Item -ItemType Directory -Path $pluginDir | Out-Null
}

(Get-Content $iniPath) `
    -replace '^Warn if not administrator=.*$', 'Warn if not administrator=0' `
    -replace '^Plugin path=.*$', "Plugin path=$pluginDir" |
    Set-Content $iniPath

Copy-Item $pluginDll (Join-Path $pluginDir "OllyBridge110.dll") -Force

Get-Process OLLYDBG -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

if ($TargetExe) {
    Start-Process -FilePath (Join-Path $ollyDir "OLLYDBG.EXE") -ArgumentList ('"{0}"' -f $TargetExe)
} else {
    Start-Process -FilePath (Join-Path $ollyDir "OLLYDBG.EXE")
}
Start-Sleep -Seconds 3

Start-Process -FilePath "powershell.exe" -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$Workspace'; python '.\server.py' --transport stdio"
)

Write-Host "OllyDbg launched with plugin from $pluginDir"
Write-Host "MCP server started in a new PowerShell window."
