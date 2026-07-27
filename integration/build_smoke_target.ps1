[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path $PSScriptRoot "..\build\runtime-smoke")
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$sourceFile = Join-Path $PSScriptRoot "olly_smoke_target.c"
$outputPath = [System.IO.Path]::GetFullPath($OutputDir)
$objectFile = Join-Path $outputPath "olly_smoke_target.obj"
$targetFile = Join-Path $outputPath "olly_smoke_target.exe"
$mapFile = Join-Path $outputPath "olly_smoke_target.map"
$manifestFile = Join-Path $outputPath "olly_smoke_manifest.json"
$imageBase = [uint32]0x00400000

if (!(Test-Path -LiteralPath $sourceFile -PathType Leaf)) {
    throw "Smoke-target source not found: $sourceFile"
}
foreach ($tool in @("cl.exe", "dumpbin.exe")) {
    if (!(Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool was not found. Run from a 32-bit Visual Studio Native Tools environment."
    }
}

New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
Remove-Item -LiteralPath $objectFile, $targetFile, $mapFile, $manifestFile -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $outputPath "olly_smoke_target.lib"), (Join-Path $outputPath "olly_smoke_target.exp") -Force -ErrorAction SilentlyContinue

$compileArgs = @(
    "/nologo",
    "/TC",
    "/W4",
    "/WX",
    "/Od",
    "/Ob0",
    "/GS",
    "/MT",
    "/Z7",
    "/DWIN32",
    "/D_WINDOWS",
    "/Fo$objectFile",
    "/Fe$targetFile",
    $sourceFile,
    "/link",
    "/NOLOGO",
    "/MACHINE:X86",
    "/SUBSYSTEM:CONSOLE",
    "/DYNAMICBASE:NO",
    "/FIXED",
    "/BASE:0x00400000",
    "/INCREMENTAL:NO",
    "/MAP:$mapFile",
    "/MAPINFO:EXPORTS"
)

Write-Host "Building controlled 32-bit OllyDbg smoke target..."
& cl.exe @compileArgs
if ($LASTEXITCODE -ne 0) {
    throw "Smoke-target build failed with exit code $LASTEXITCODE"
}

$headers = (& dumpbin.exe /headers $targetFile) -join "`n"
if ($LASTEXITCODE -ne 0 -or $headers -notmatch "(?im)14C machine \(x86\)") {
    throw "The generated smoke target is not a 32-bit x86 image."
}
if ($headers -notmatch "(?im)^\s*400000 image base") {
    throw "The generated smoke target does not use the required 0x00400000 image base."
}
if ($headers -match "(?im)Dynamic base") {
    throw "The generated smoke target unexpectedly has ASLR enabled."
}

$exports = (& dumpbin.exe /exports $targetFile) -join "`n"
if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect smoke-target exports."
}

function Get-ExportRva {
    param([Parameter(Mandatory = $true)][string]$Name)

    $pattern = "(?im)^\s+\d+\s+[0-9A-F]+\s+([0-9A-F]{8})\s+$([regex]::Escape($Name))(?:\s|$)"
    $match = [regex]::Match($exports, $pattern)
    if (!$match.Success) {
        throw "Required smoke-target export was not found: $Name"
    }
    return [Convert]::ToUInt32($match.Groups[1].Value, 16)
}

$probeRva = Get-ExportRva -Name "olly_smoke_probe"
$counterRva = Get-ExportRva -Name "olly_smoke_counter"
$probeAddress = [uint32]($imageBase + $probeRva)
$counterAddress = [uint32]($imageBase + $counterRva)

$manifest = [ordered]@{
    schema_version = 1
    module_name = "olly_smoke_target.exe"
    target_path = $targetFile
    image_base = ("0x{0:X8}" -f $imageBase)
    probe_rva = ("0x{0:X8}" -f $probeRva)
    probe_address = ("0x{0:X8}" -f $probeAddress)
    counter_rva = ("0x{0:X8}" -f $counterRva)
    counter_address = ("0x{0:X8}" -f $counterAddress)
    counter_initial_value = "0x11223344"
}
$json = $manifest | ConvertTo-Json
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($manifestFile, $json + "`n", $utf8NoBom)

Write-Host "Smoke target: $targetFile"
Write-Host "Address manifest: $manifestFile"
