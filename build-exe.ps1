#Requires -Version 5.1
param(
    [string]$OutputDir = (Join-Path $PSScriptRoot 'dist')
)

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'AdapterLock.ps1'
$info = Test-ScriptFileInfo -Path $scriptPath -ErrorAction Stop
$version = $info.Version

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host 'Installing ps2exe module...'
    Install-Module -Name ps2exe -Scope CurrentUser -Force
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
}

$exePath = Join-Path $OutputDir "AdapterLock-v$version.exe"

Write-Host "Building AdapterLock v$version -> $exePath"
Invoke-PS2EXE -InputFile $scriptPath `
    -OutputFile $exePath `
    -NoConsole `
    -Title 'AdapterLock' `
    -Description 'Per-adapter IP lockdown via registry ACL' `
    -Company 'SysAdminDoc' `
    -Version $version `
    -Copyright "(c) 2026 SysAdminDoc" `
    -RequireAdmin

if (Test-Path $exePath) {
    $size = [math]::Round((Get-Item $exePath).Length / 1KB)
    Write-Host "Built: $exePath ($size KB)"
} else {
    throw 'EXE build failed'
}
