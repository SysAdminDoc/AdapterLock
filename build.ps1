#Requires -Version 5.1
param(
    [switch]$Validate,
    [switch]$Package,
    [string]$OutputDir = (Join-Path $PSScriptRoot 'dist')
)

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'AdapterLock.ps1'

function Write-TextFile {
    param(
        [string]$Path,
        [string]$Content
    )
    Set-Content -LiteralPath $Path -Value $Content.TrimStart() -Encoding ASCII -ErrorAction Stop
}

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

function New-DeploymentKit {
    param(
        [string]$Root,
        [string]$Version
    )

    $kitDir = Join-Path $Root 'deployment'
    New-Item -ItemType Directory -Force -Path $kitDir | Out-Null

    Write-TextFile -Path (Join-Path $kitDir 'intune-detect.ps1') -Content @'
# AdapterLock Intune detection sample.
# Exit 0 = compliant, exit 1 = drift/non-compliant, exit 2 = argument error.
$ErrorActionPreference = 'Stop'
$adapterLock = Join-Path $PSScriptRoot 'AdapterLock.ps1'
if (-not (Test-Path -LiteralPath $adapterLock)) {
    Write-Output 'AdapterLock.ps1 not found next to detection script.'
    exit 1
}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $adapterLock -VerifyLocks -Silent
exit $LASTEXITCODE
'@

    Write-TextFile -Path (Join-Path $kitDir 'intune-remediate.ps1') -Content @'
# AdapterLock Intune remediation sample.
# Exit 0 = remediated or already clean, exit 1 = drift remains.
$ErrorActionPreference = 'Stop'
$adapterLock = Join-Path $PSScriptRoot 'AdapterLock.ps1'
if (-not (Test-Path -LiteralPath $adapterLock)) {
    Write-Output 'AdapterLock.ps1 not found next to remediation script.'
    exit 1
}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $adapterLock -VerifyLocks -Remediate -Silent
exit $LASTEXITCODE
'@

    Write-TextFile -Path (Join-Path $kitDir 'rmm-verify.ps1') -Content @'
# AdapterLock RMM verification sample.
# Writes JSON fleet state to stdout for tools that capture script output.
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME)
)
$ErrorActionPreference = 'Stop'
$adapterLock = Join-Path $PSScriptRoot 'AdapterLock.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $adapterLock -Query -ComputerName $ComputerName -OutputFormat Json -Silent
exit $LASTEXITCODE
'@

    Write-TextFile -Path (Join-Path $kitDir 'install-startup-task.ps1') -Content @'
# AdapterLock startup enforcement task installer sample.
param(
    [string]$PolicyFile = "$env:ProgramData\AdapterLock\policy.json"
)
$ErrorActionPreference = 'Stop'
$adapterLock = Join-Path $PSScriptRoot 'AdapterLock.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $adapterLock -InstallTask -PolicyFile $PolicyFile
exit $LASTEXITCODE
'@

    Write-TextFile -Path (Join-Path $kitDir 'AdapterLock-Enforce.xml') -Content @'
<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>AdapterLock startup enforcement template. Replace __ADAPTERLOCK_SCRIPT_PATH__ and __POLICY_PATH__ before import.</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File "__ADAPTERLOCK_SCRIPT_PATH__" -LoadPolicy "__POLICY_PATH__" -Silent</Arguments>
    </Exec>
  </Actions>
</Task>
'@

    Write-TextFile -Path (Join-Path $kitDir 'deployment-checklist.txt') -Content @"
AdapterLock v$Version deployment checklist

1. Put AdapterLock.ps1 and a validated adapter policy JSON on the endpoint.
2. Run detection with intune-detect.ps1 or: powershell.exe -NoProfile -ExecutionPolicy Bypass -File AdapterLock.ps1 -VerifyLocks -Silent
3. Run remediation with intune-remediate.ps1 or: powershell.exe -NoProfile -ExecutionPolicy Bypass -File AdapterLock.ps1 -VerifyLocks -Remediate -Silent
4. For startup enforcement, run install-startup-task.ps1 -PolicyFile <policy.json> or import AdapterLock-Enforce.xml after replacing placeholders.
5. RMM exit codes: 0 = clean/success, 1 = drift or operation failure, 2 = bad arguments.
6. Unsigned artifacts may still require execution-policy handling, code signing, or your endpoint management trust policy.
"@

    return $kitDir
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

function New-PackageProvenance {
    param(
        [string]$Version,
        [string[]]$Path,
        [string]$OutputFile
    )
    $artifacts = foreach ($p in $Path) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        $item = Get-Item -LiteralPath $p
        [pscustomobject]@{
            Name = $item.Name
            Length = $item.Length
            SHA256 = Get-Sha256Hash -Path $p
        }
    }
    [pscustomobject]@{
        Project = 'AdapterLock'
        Version = $Version
        GeneratedAt = (Get-Date -Format 'o')
        Signing = 'Unsigned; Authenticode signing is tracked in Roadmap_Blocked.md'
        Artifacts = @($artifacts)
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputFile -Encoding UTF8 -ErrorAction Stop
}

function Invoke-AnalyzerGate {
    param(
        [string]$Path,
        [string]$SettingsPath
    )

    if (-not (Test-Path -LiteralPath $SettingsPath -PathType Leaf)) {
        throw "PSScriptAnalyzer settings not found: $SettingsPath"
    }

    $analyzer = Get-Module -ListAvailable PSScriptAnalyzer |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if (-not $analyzer) {
        throw 'PSScriptAnalyzer module is not installed'
    }
    Import-Module $analyzer.Path -Force -ErrorAction Stop

    $results = @(Invoke-ScriptAnalyzer -Path $Path -Settings $SettingsPath -Severity Error,Warning -ErrorAction Stop)
    if ($results.Count -gt 0) {
        $summary = $results |
            Sort-Object Severity,RuleName,Line |
            Select-Object -First 20 |
            ForEach-Object { "{0}:{1} {2} {3}" -f $_.ScriptName, $_.Line, $_.RuleName, $_.Message }
        throw "PSScriptAnalyzer found $($results.Count) warning/error result(s):`n$($summary -join "`n")"
    }

    Write-Host "  PSScriptAnalyzer: OK ($($analyzer.Version))"
}

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

Write-Host '--- Running PSScriptAnalyzer ---'
$settingsPath = Join-Path $PSScriptRoot '.vscode\PSScriptAnalyzer.psd1'
Invoke-AnalyzerGate -Path $scriptPath -SettingsPath $settingsPath

Write-Host '--- Running Pester tests ---'
$testFile = Join-Path $PSScriptRoot 'AdapterLock.Tests.ps1'
if (Test-Path $testFile) {
    $pester = Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $pester) {
        throw 'Pester module is not installed'
    }
    Import-Module $pester.Path -Force -ErrorAction Stop
    if ($pester.Version.Major -ge 5) {
        $config = New-PesterConfiguration
        $config.Run.Path = $testFile
        $config.Run.PassThru = $true
        $config.Output.Verbosity = 'None'
        $result = Invoke-Pester -Configuration $config
    } else {
        $result = Invoke-Pester -Script $testFile -PassThru -Quiet
    }
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

    $deploymentDir = New-DeploymentKit -Root $OutputDir -Version $version
    Write-Host "--- Deployment kit: $deploymentDir ---"

    $zipPath = Join-Path $OutputDir "AdapterLock-v$version.zip"
    $filesToZip = @($scriptPath, (Join-Path $PSScriptRoot 'LICENSE'), (Join-Path $PSScriptRoot 'README.md'), $deploymentDir)
    $filesToZip = $filesToZip | Where-Object { Test-Path $_ }
    Compress-Archive -Path $filesToZip -DestinationPath $zipPath -Force
    Write-Host "--- Archive: $zipPath ---"

    $manifestPaths = @($destScript, $zipPath)
    $manifestPath = Join-Path $OutputDir "AdapterLock-v$version.sha256.txt"
    New-HashManifest -Path $manifestPaths -OutputFile $manifestPath
    Write-Host "--- SHA256: $manifestPath ---"

    $provenancePath = Join-Path $OutputDir "AdapterLock-v$version-provenance.json"
    New-PackageProvenance -Version $version -Path $manifestPaths -OutputFile $provenancePath
    Write-Host "--- Provenance: $provenancePath ---"
}

Write-Host '--- Done ---'
