#Requires -Version 5.1
param(
    [string]$OutputDir = (Join-Path $PSScriptRoot 'dist'),
    [version]$MinimumPs2ExeVersion = '1.0.16'
)

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'AdapterLock.ps1'

if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $packageManagement = Get-Module -ListAvailable PackageManagement |
        Where-Object { $_.Path -like '*WindowsPowerShell*' } |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($packageManagement) {
        Import-Module $packageManagement.Path -Force -ErrorAction Stop
    }

    $powerShellGet = Get-Module -ListAvailable PowerShellGet |
        Where-Object { $_.Path -like '*WindowsPowerShell*' } |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if ($powerShellGet) {
        Import-Module $powerShellGet.Path -Force -ErrorAction Stop
    }
}

$info = Test-ScriptFileInfo -Path $scriptPath -ErrorAction Stop
$version = $info.Version

function Get-Sha256Hash {
    param([string]$Path)
    $stream = [System.IO.File]::OpenRead((Resolve-Path -LiteralPath $Path).Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToUpperInvariant()
        } finally {
            $sha.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function New-HashManifest {
    param(
        [string[]]$Path,
        [string]$OutputFile
    )
    $lines = foreach ($p in $Path) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        $hash = Get-Sha256Hash -Path $p
        "{0}  {1}" -f $hash.ToLowerInvariant(), (Split-Path $p -Leaf)
    }
    Set-Content -LiteralPath $OutputFile -Value $lines -Encoding ASCII -ErrorAction Stop
}

$ps2exe = Get-Module -ListAvailable -Name ps2exe |
    Sort-Object Version -Descending |
    Select-Object -First 1

if (-not $ps2exe) {
    throw "ps2exe module is required. Install explicitly with: Install-Module ps2exe -Scope CurrentUser -MinimumVersion $MinimumPs2ExeVersion"
}
if ($ps2exe.Version -lt $MinimumPs2ExeVersion) {
    throw "ps2exe $($ps2exe.Version) is older than required $MinimumPs2ExeVersion. Update explicitly with: Update-Module ps2exe"
}
Import-Module $ps2exe.Path -Force -ErrorAction Stop

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

    $manifestPath = Join-Path $OutputDir "AdapterLock-v$version-exe.sha256.txt"
    New-HashManifest -Path @($scriptPath, $exePath) -OutputFile $manifestPath
    Write-Host "SHA256: $manifestPath"

    $provenancePath = Join-Path $OutputDir "AdapterLock-v$version-exe-provenance.json"
    [pscustomobject]@{
        Project = 'AdapterLock'
        Version = [string]$version
        GeneratedAt = (Get-Date -Format 'o')
        Ps2ExeVersion = [string]$ps2exe.Version
        MinimumPs2ExeVersion = [string]$MinimumPs2ExeVersion
        Signing = 'Unsigned; Authenticode signing is tracked in Roadmap_Blocked.md'
        Artifacts = @(
            foreach ($p in @($scriptPath, $exePath)) {
                $item = Get-Item -LiteralPath $p
                [pscustomobject]@{
                    Name = $item.Name
                    Length = $item.Length
                    SHA256 = Get-Sha256Hash -Path $p
                }
            }
        )
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $provenancePath -Encoding UTF8 -ErrorAction Stop
    Write-Host "Provenance: $provenancePath"
    Write-Warning 'EXE artifact is unsigned until Authenticode signing is configured.'
} else {
    throw 'EXE build failed'
}
