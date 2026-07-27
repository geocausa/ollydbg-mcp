[CmdletBinding()]
param(
    [string]$TargetExe,
    [string]$Workspace = $PSScriptRoot,
    [Parameter(Mandatory = $true)]
    [string]$OllyDir,
    [Parameter(Mandatory = $true)]
    [string]$PluginDir,
    [string]$PluginDllPath,
    [switch]$RestartOlly,
    [switch]$SkipIniUpdate,
    [switch]$SkipServer
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspacePath = (Resolve-Path -LiteralPath $Workspace).Path
$ollyPath = (Resolve-Path -LiteralPath $OllyDir).Path
$ollyExe = Join-Path $ollyPath 'OLLYDBG.EXE'
$iniPath = Join-Path $ollyPath 'ollydbg.ini'
$resolvedPluginDll = if ($PluginDllPath) {
    (Resolve-Path -LiteralPath $PluginDllPath).Path
}
else {
    Join-Path $workspacePath 'OllyBridge110.dll'
}
$serverPy = Join-Path $workspacePath 'server.py'

$requiredPaths = @($ollyExe, $iniPath, $resolvedPluginDll)
if (!$SkipServer) {
    $requiredPaths += $serverPy
}
foreach ($requiredPath in $requiredPaths) {
    if (!(Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required file not found: $requiredPath"
    }
}

if ($TargetExe) {
    $targetPath = (Resolve-Path -LiteralPath $TargetExe).Path
    if (!(Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        throw "Target executable not found: $targetPath"
    }
}

if (!(Test-Path -LiteralPath $PluginDir)) {
    New-Item -ItemType Directory -Path $PluginDir | Out-Null
}
$pluginPath = (Resolve-Path -LiteralPath $PluginDir).Path

if (!$SkipIniUpdate) {
    $backupPath = "$iniPath.ollybridge-backup"
    Copy-Item -LiteralPath $iniPath -Destination $backupPath -Force

    $iniContent = Get-Content -LiteralPath $iniPath
    $pluginLine = "Plugin path=$pluginPath"
    $matchedPluginPath = $false
    $updated = foreach ($line in $iniContent) {
        if ($line -match '^Plugin path=') {
            $matchedPluginPath = $true
            $pluginLine
        }
        else {
            $line
        }
    }
    if (!$matchedPluginPath) {
        $updated += $pluginLine
    }
    Set-Content -LiteralPath $iniPath -Value $updated -Encoding Default
    Write-Host "Backed up ollydbg.ini to $backupPath"
}

Copy-Item -LiteralPath $resolvedPluginDll `
    -Destination (Join-Path $pluginPath 'OllyBridge110.dll') `
    -Force

$runningOlly = Get-Process -Name OLLYDBG -ErrorAction SilentlyContinue
if ($runningOlly) {
    if (!$RestartOlly) {
        throw 'OllyDbg is already running. Close it or pass -RestartOlly explicitly.'
    }
    $runningOlly | Stop-Process -Force
    Start-Sleep -Milliseconds 500
}

$ollyArguments = @()
if ($TargetExe) {
    $ollyArguments += ('"{0}"' -f $targetPath)
}
Start-Process -FilePath $ollyExe -ArgumentList $ollyArguments

if (!$SkipServer) {
    $python = Get-Command python -ErrorAction Stop
    $serverArguments = @(('"{0}"' -f $serverPy), '--transport', 'stdio')
    Start-Process -FilePath $python.Source `
        -ArgumentList $serverArguments `
        -WorkingDirectory $workspacePath
}

Write-Host "OllyDbg launched with plugin from $pluginPath"
if ($SkipServer) {
    Write-Host 'MCP server launch skipped.'
}
else {
    Write-Host 'MCP server launched with stdio transport.'
}
