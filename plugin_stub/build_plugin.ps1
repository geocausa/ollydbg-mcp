[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SdkDir,

    [string]$OutputDir = (Join-Path $PSScriptRoot "..\build\native"),

    [switch]$AllowTestSdk
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$sourceDir = [System.IO.Path]::GetFullPath($PSScriptRoot)
$sdkPath = [System.IO.Path]::GetFullPath($SdkDir)
$outputPath = [System.IO.Path]::GetFullPath($OutputDir)
$pluginHeader = Join-Path $sdkPath "Plugin.h"
$sourceFile = Join-Path $sourceDir "ollydbg110_bridge.c"
$definitionFile = Join-Path $sourceDir "OllyBridge110.def"
$objectFile = Join-Path $outputPath "ollydbg110_bridge.obj"
$dllFile = Join-Path $outputPath "OllyBridge110.dll"
$pdbFile = Join-Path $outputPath "OllyBridge110.pdb"

foreach ($requiredFile in @($pluginHeader, $sourceFile, $definitionFile)) {
    if (!(Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required build file not found: $requiredFile"
    }
}

$headerText = Get-Content -LiteralPath $pluginHeader -Raw
$isTestSdk = $headerText.Contains("OLLYDBG_TEST_PLUGIN_H")
if ($isTestSdk -and !$AllowTestSdk) {
    throw "The test-only SDK shim cannot be used for a real plugin build. Pass the genuine OllyDbg 1.10 SDK directory."
}

foreach ($tool in @("cl.exe", "link.exe", "dumpbin.exe")) {
    if (!(Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool was not found. Run this script from a 32-bit Visual Studio Native Tools environment."
    }
}

New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
Remove-Item -LiteralPath $objectFile, $dllFile, $pdbFile -Force -ErrorAction SilentlyContinue

$compileArgs = @(
    "/nologo",
    "/c",
    "/TC",
    "/J",
    "/W4",
    "/WX",
    "/O2",
    "/GS",
    "/DWIN32",
    "/D_WINDOWS",
    "/DNDEBUG",
    "/D_CRT_SECURE_NO_WARNINGS",
    "/I$sdkPath",
    "/I$sourceDir",
    "/Fo$objectFile",
    $sourceFile
)

Write-Host "Compiling 32-bit OllyBridge110..."
& cl.exe @compileArgs
if ($LASTEXITCODE -ne 0) {
    throw "Native compilation failed with exit code $LASTEXITCODE"
}

$linkArgs = @(
    "/NOLOGO",
    "/DLL",
    "/MACHINE:X86",
    "/SUBSYSTEM:WINDOWS",
    "/DEF:$definitionFile",
    "/OUT:$dllFile",
    "/PDB:$pdbFile",
    $objectFile,
    "Kernel32.lib",
    "User32.lib",
    "Advapi32.lib"
)

Write-Host "Linking OllyBridge110.dll..."
& link.exe @linkArgs
if ($LASTEXITCODE -ne 0) {
    throw "Native link failed with exit code $LASTEXITCODE"
}

$headers = (& dumpbin.exe /headers $dllFile) -join "`n"
if ($LASTEXITCODE -ne 0 -or $headers -notmatch "(?im)14C machine \(x86\)") {
    throw "The generated DLL is not a 32-bit x86 image."
}

$exports = (& dumpbin.exe /exports $dllFile) -join "`n"
if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect DLL exports."
}

$requiredExports = @(
    "_ODBG_Plugindata",
    "_ODBG_Plugininit",
    "_ODBG_Pluginmenu",
    "_ODBG_Pluginaction",
    "_ODBG_Pluginclose",
    "_ODBG_Paused",
    "_ODBG_Pausedex",
    "_ODBG_Plugindestroy"
)
foreach ($exportName in $requiredExports) {
    if ($exports -notmatch "(?m)\s$([regex]::Escape($exportName))\s*$") {
        throw "Required OllyDbg callback is not exported: $exportName"
    }
}

if ($isTestSdk) {
    Write-Host "CI compile/link validation passed using the test-only SDK shim."
    Write-Host "This DLL must not be distributed or loaded into OllyDbg."
}
else {
    Write-Host "Plugin build completed: $dllFile"
}
