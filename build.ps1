#Requires -Version 5.1
param(
    [switch]$Validate,
    [switch]$Package,
    [string]$OutputDir = (Join-Path $PSScriptRoot 'dist')
)

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'AdapterLock.ps1'

Write-Host '--- Validating script metadata ---'
$info = Test-ScriptFileInfo -Path $scriptPath -ErrorAction Stop
Write-Host "  Version : $($info.Version)"
Write-Host "  Author  : $($info.Author)"
Write-Host "  GUID    : $($info.Guid)"
Write-Host '  ScriptFileInfo: OK'

Write-Host '--- Checking comment-based help ---'
$help = Get-Help $scriptPath
if ($help.Synopsis -and $help.Synopsis -notmatch '^\s*$') {
    Write-Host "  Synopsis: $($help.Synopsis)"
} else {
    throw 'Comment-based help missing synopsis'
}

Write-Host '--- Running Pester tests ---'
$testFile = Join-Path $PSScriptRoot 'AdapterLock.Tests.ps1'
if (Test-Path $testFile) {
    $result = Invoke-Pester -Script $testFile -PassThru -Quiet
    if ($result.FailedCount -gt 0) {
        throw "$($result.FailedCount) Pester test(s) failed"
    }
    Write-Host "  Passed: $($result.PassedCount) / $($result.TotalCount)"
} else {
    Write-Host '  (no test file found, skipping)'
}

if ($Validate) {
    Write-Host '--- Validation complete ---'
    exit 0
}

if ($Package) {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }
    $version = $info.Version
    $destScript = Join-Path $OutputDir "AdapterLock-v$version.ps1"
    Copy-Item -Path $scriptPath -Destination $destScript -Force
    Write-Host "--- Packaged: $destScript ---"

    $zipPath = Join-Path $OutputDir "AdapterLock-v$version.zip"
    $filesToZip = @($scriptPath, (Join-Path $PSScriptRoot 'LICENSE'), (Join-Path $PSScriptRoot 'README.md'))
    $filesToZip = $filesToZip | Where-Object { Test-Path $_ }
    Compress-Archive -Path $filesToZip -DestinationPath $zipPath -Force
    Write-Host "--- Archive: $zipPath ---"
}

Write-Host '--- Done ---'
