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
    [switch]$SkipServer,
    [switch]$EnableNativeMutations
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

# Refuse or stop OllyDbg before changing its configuration or replacing a DLL
# that may still be mapped into the running process.
$runningOlly = Get-Process -Name OLLYDBG -ErrorAction SilentlyContinue
if ($runningOlly) {
    if (!$RestartOlly) {
        throw 'OllyDbg is already running. Close it or pass -RestartOlly explicitly.'
    }
    $runningOlly | Stop-Process -Force
    $stopDeadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 100
        $stillRunning = Get-Process -Name OLLYDBG -ErrorAction SilentlyContinue
    } while ($stillRunning -and [DateTime]::UtcNow -lt $stopDeadline)
    if ($stillRunning) {
        throw 'OllyDbg did not stop within 10 seconds; no configuration or plugin files were changed.'
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

$ollyArguments = @()
if ($TargetExe) {
    $ollyArguments += ('"{0}"' -f $targetPath)
}

$mutationVariable = 'OLLYBRIDGE_ALLOW_MUTATIONS'
$previousMutationSetting = [System.Environment]::GetEnvironmentVariable(
    $mutationVariable,
    'Process'
)
try {
    [System.Environment]::SetEnvironmentVariable(
        $mutationVariable,
        $(if ($EnableNativeMutations) { '1' } else { '0' }),
        'Process'
    )
    Start-Process -FilePath $ollyExe -ArgumentList $ollyArguments
}
finally {
    [System.Environment]::SetEnvironmentVariable(
        $mutationVariable,
        $previousMutationSetting,
        'Process'
    )
}

if (!$SkipServer) {
    $python = Get-Command python -ErrorAction Stop
    $serverArguments = @(('"{0}"' -f $serverPy), '--transport', 'stdio')
    Start-Process -FilePath $python.Source `
        -ArgumentList $serverArguments `
        -WorkingDirectory $workspacePath
}

Write-Host "OllyDbg launched with plugin from $pluginPath"
Write-Host $(if ($EnableNativeMutations) {
    'Native debugger mutations are enabled for this OllyDbg process.'
}
else {
    'Native debugger mutations are disabled (read-only gate).'
})
if ($SkipServer) {
    Write-Host 'MCP server launch skipped.'
}
else {
    Write-Host 'MCP server launched with stdio transport.'
}
