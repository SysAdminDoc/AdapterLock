Describe 'AdapterLock core functions' {
    BeforeAll {
        $script:RepoRoot = $PSScriptRoot
        $script:AdapterLockScript = Join-Path $script:RepoRoot 'AdapterLock.ps1'

        if (-not (Get-Command Get-Acl -ErrorAction SilentlyContinue)) {
            function global:Get-Acl {
                param([string]$LiteralPath)
                throw "Test shim should be mocked: Get-Acl $LiteralPath"
            }
        }
        if (-not (Get-Command Set-Acl -ErrorAction SilentlyContinue)) {
            function global:Set-Acl {
                param([string]$LiteralPath, $AclObject)
                throw "Test shim should be mocked: Set-Acl $LiteralPath"
            }
        }

        function Import-AdapterLockFunction {
            param([string[]]$Name)

            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:AdapterLockScript, [ref]$tokens, [ref]$errors)
            if ($errors.Count -gt 0) {
                throw "AdapterLock.ps1 parse failed: $($errors[0].Message)"
            }

            foreach ($functionName in $Name) {
                $fn = $ast.Find({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -eq $functionName
                }, $true)
                if (-not $fn) { throw "Function not found: $functionName" }
                $definition = $fn.Extent.Text -replace "function\s+$([regex]::Escape($functionName))", "function global:$functionName"
                . ([scriptblock]::Create($definition))
            }
        }

        function New-FakeAcl {
            param(
                [string]$Identity = 'Authenticated Users',
                [string]$AccessControlType = 'Deny'
            )

            $acl = [pscustomobject]@{
                Access = @(
                    [pscustomobject]@{
                        AccessControlType = $AccessControlType
                        IdentityReference = [pscustomobject]@{ Value = $Identity }
                    }
                )
                Sddl = 'O:BAG:BAD:'
            }
            $acl | Add-Member -MemberType ScriptMethod -Name SetSecurityDescriptorSddlForm -Value {
                param([string]$Value)
                $this.Sddl = $Value
            } -PassThru
        }
    }

    BeforeEach {
        $script:LogMessages = @()
        function Write-AppLog {
            param([string]$Message, [string]$Level = 'INFO')
            $script:LogMessages += [pscustomobject]@{
                Message = $Message
                Level = $Level
            }
        }
    }

    It 'detects deny ACEs in Test-AdapterLockedDetailed' {
        Import-AdapterLockFunction -Name 'Test-AdapterLockedDetailed'
        Mock -CommandName Test-Path -MockWith { $true }
        Mock -CommandName Get-Acl -MockWith { New-FakeAcl }

        $result = Test-AdapterLockedDetailed -Guid '{11111111-1111-1111-1111-111111111111}'

        $result.V4Locked | Should -Be $true
        $result.V6Locked | Should -Be $true
        $result.NetBTLocked | Should -Be $true
        Should -Invoke -CommandName Get-Acl -Times 3
    }

    It 'logs lock dry-run paths without writing ACLs' {
        Import-AdapterLockFunction -Name 'Get-InterfaceKeyPath', 'Get-AdapterDhcpState', 'Lock-Adapter'
        Mock -CommandName Test-Path -MockWith { $true }
        Mock -CommandName Get-ItemPropertyValue -MockWith { 0 }
        Mock -CommandName Get-Acl -MockWith { throw 'Get-Acl should not be called during dry-run' }
        Mock -CommandName Set-Acl -MockWith { throw 'Set-Acl should not be called during dry-run' }

        $result = Lock-Adapter -Guid '{11111111-1111-1111-1111-111111111111}' -Name 'Ethernet' -Preview

        $result | Should -Be $true
        ($script:LogMessages.Message -join "`n") | Should -Match 'DRY-RUN Lock Ethernet'
    }

    It 'logs unlock dry-run paths without writing ACLs' {
        Import-AdapterLockFunction -Name 'Get-InterfaceKeyPath', 'Unlock-Adapter'
        Mock -CommandName Test-Path -MockWith { $true }
        Mock -CommandName Get-Acl -MockWith { throw 'Get-Acl should not be called during dry-run' }
        Mock -CommandName Set-Acl -MockWith { throw 'Set-Acl should not be called during dry-run' }

        $result = Unlock-Adapter -Guid '{11111111-1111-1111-1111-111111111111}' -Name 'Ethernet' -Preview

        $result | Should -Be $true
        ($script:LogMessages.Message -join "`n") | Should -Match 'DRY-RUN Unlock Ethernet'
    }

    It 'finds adapters by name, MAC, and GUID' {
        Import-AdapterLockFunction -Name 'Find-AdapterByIdentifier'
        Mock -CommandName Get-NetAdapter -MockWith {
            @(
                [pscustomobject]@{
                    Name = 'Ethernet'
                    MacAddress = 'AA-BB-CC-DD-EE-FF'
                    InterfaceGuid = '{11111111-1111-1111-1111-111111111111}'
                }
                [pscustomobject]@{
                    Name = 'PACS Link'
                    MacAddress = '11:22:33:44:55:66'
                    InterfaceGuid = '{22222222-2222-2222-2222-222222222222}'
                }
            )
        }

        (Find-AdapterByIdentifier -ByName 'Ethernet').InterfaceGuid | Should -Be '{11111111-1111-1111-1111-111111111111}'
        (Find-AdapterByIdentifier -ByMac '112233445566').Name | Should -Be 'PACS Link'
        (Find-AdapterByIdentifier -ByGuid '{22222222-2222-2222-2222-222222222222}').Name | Should -Be 'PACS Link'
    }

    It 'round-trips exported lock policy JSON' {
        Import-AdapterLockFunction -Name 'Export-LockPolicy', 'Import-LockPolicy', 'ConvertTo-PolicyGuid', 'ConvertTo-PolicyMac', 'Get-PolicyIdentifierKey'
        $script:Version = 'test'
        function Get-AdapterRow {
            @(
                [pscustomobject]@{
                    IsLocked = $true
                    Name = 'Ethernet'
                    MAC = 'AA-BB-CC-DD-EE-FF'
                    Guid = '{11111111-1111-1111-1111-111111111111}'
                    LockBadge = 'LOCKED'
                }
                [pscustomobject]@{
                    IsLocked = $false
                    Name = 'Wi-Fi'
                    MAC = '11-22-33-44-55-66'
                    Guid = '{22222222-2222-2222-2222-222222222222}'
                    LockBadge = 'Unlocked'
                }
            )
        }

        $policyPath = Join-Path $TestDrive 'adapter-policy.json'
        Export-LockPolicy -Path $policyPath
        $adapters = @(Import-LockPolicy -Path $policyPath)

        $adapters.Count | Should -Be 1
        $adapters[0].Name | Should -Be 'Ethernet'
        $adapters[0].State | Should -Be 'locked'
    }

    It 'rejects policy file missing Version field' {
        Import-AdapterLockFunction -Name 'Import-LockPolicy'
        $policyPath = Join-Path $TestDrive 'bad-no-version.json'
        @{ Adapters = @(@{ Name = 'Ethernet' }) } | ConvertTo-Json | Set-Content $policyPath
        $result = @(Import-LockPolicy -Path $policyPath)
        $result.Count | Should -Be 0
    }

    It 'rejects policy file with non-array Adapters' {
        Import-AdapterLockFunction -Name 'Import-LockPolicy'
        $policyPath = Join-Path $TestDrive 'bad-adapters-string.json'
        @{ Version = '0.6.0'; Adapters = 'not-an-array' } | ConvertTo-Json | Set-Content $policyPath
        $result = @(Import-LockPolicy -Path $policyPath)
        $result.Count | Should -Be 0
    }

    It 'rejects adapter entry without any identifier' {
        Import-AdapterLockFunction -Name 'Import-LockPolicy', 'ConvertTo-PolicyGuid', 'ConvertTo-PolicyMac', 'Get-PolicyIdentifierKey'
        $policyPath = Join-Path $TestDrive 'bad-no-id.json'
        @{ Version = '0.6.0'; Adapters = @(@{ State = 'locked' }) } | ConvertTo-Json -Depth 3 | Set-Content $policyPath
        $result = @(Import-LockPolicy -Path $policyPath)
        $result.Count | Should -Be 0
    }

    It 'rejects invalid and duplicate policy entries' {
        Import-AdapterLockFunction -Name 'Import-LockPolicy', 'ConvertTo-PolicyGuid', 'ConvertTo-PolicyMac', 'Get-PolicyIdentifierKey'

        $badStatePath = Join-Path $TestDrive 'bad-state.json'
        @{ Version = '0.8.7'; Adapters = @(@{ Name = 'Ethernet'; State = 'maybe' }) } | ConvertTo-Json -Depth 3 | Set-Content $badStatePath
        @(Import-LockPolicy -Path $badStatePath).Count | Should -Be 0

        $badGuidPath = Join-Path $TestDrive 'bad-guid.json'
        @{ Version = '0.8.7'; Adapters = @(@{ GUID = 'not-a-guid'; State = 'locked' }) } | ConvertTo-Json -Depth 3 | Set-Content $badGuidPath
        @(Import-LockPolicy -Path $badGuidPath).Count | Should -Be 0

        $duplicatePath = Join-Path $TestDrive 'duplicate.json'
        @{
            Version = '0.8.7'
            Adapters = @(
                @{ Name = 'Ethernet'; State = 'locked' }
                @{ Name = 'Ethernet'; State = 'locked' }
            )
        } | ConvertTo-Json -Depth 4 | Set-Content $duplicatePath
        @(Import-LockPolicy -Path $duplicatePath).Count | Should -Be 0
    }

    It 'skips partial policy entries and dry-runs locked entries' {
        Import-AdapterLockFunction -Name 'Invoke-LockPolicy', 'Get-LockPolicySummary', 'Find-AdapterByIdentifier', 'Lock-Adapter'
        $policy = @(
            [pscustomobject]@{ Name = 'Ethernet'; MAC = ''; GUID = ''; State = 'locked' }
            [pscustomobject]@{ Name = 'Wi-Fi'; MAC = ''; GUID = ''; State = 'partial' }
        )
        Mock -CommandName Find-AdapterByIdentifier -MockWith {
            [pscustomobject]@{ Name = 'Ethernet'; InterfaceGuid = '{11111111-1111-1111-1111-111111111111}' }
        }
        Mock -CommandName Lock-Adapter -MockWith { $true }

        $results = @(Invoke-LockPolicy -Policy $policy -Preview)

        $results.Count | Should -Be 2
        $results[0].Status | Should -Be 'DryRun'
        $results[1].Status | Should -Be 'SkippedPartial'
        Should -Invoke -CommandName Lock-Adapter -Times 1
    }

    It 'lists parsed SDDL backup records for an adapter' {
        Import-AdapterLockFunction -Name 'Get-AdapterBackupRecord', 'ConvertFrom-AdapterBackupFile', 'Resolve-BackupFile'
        $script:BackupDir = Join-Path $TestDrive 'Backups'
        New-Item -ItemType Directory -Force -Path $script:BackupDir | Out-Null
        $guid = '{11111111-1111-1111-1111-111111111111}'
        $safeGuid = $guid -replace '[{}]', ''
        Set-Content -LiteralPath (Join-Path $script:BackupDir "${safeGuid}.Tcpip.$guid.20260617-010101.sddl") -Value 'D:AI'
        Set-Content -LiteralPath (Join-Path $script:BackupDir "${safeGuid}.NetBT.Tcpip_$guid.20260617-010102.sddl") -Value 'D:AI'

        $records = @(Get-AdapterBackupRecord -Guid $guid)

        $records.Count | Should -Be 2
        $records.Stack | Should -Contain 'Tcpip'
        $records.Stack | Should -Contain 'NetBT'
        $records[0].Path | Should -Not -BeNullOrEmpty
    }

    It 'restores an exact selected SDDL backup file to its stack key' {
        Import-AdapterLockFunction -Name 'Restore-AdapterSddl', 'Get-InterfaceKeyPath', 'Get-BackupKeyTag', 'Get-AdapterBackupRecord', 'ConvertFrom-AdapterBackupFile', 'Resolve-BackupFile', 'Get-BackupRestorePath', 'Invoke-SddlRestore', 'Write-EvtLog'
        $script:BackupDir = Join-Path $TestDrive 'Backups'
        New-Item -ItemType Directory -Force -Path $script:BackupDir | Out-Null
        $guid = '{11111111-1111-1111-1111-111111111111}'
        $safeGuid = $guid -replace '[{}]', ''
        $backupPath = Join-Path $script:BackupDir "${safeGuid}.NetBT.Tcpip_$guid.20260617-010102.sddl"
        Set-Content -LiteralPath $backupPath -Value 'D:AI'

        Mock -CommandName Test-Path -MockWith { $true }
        Mock -CommandName Get-Acl -MockWith { New-FakeAcl }
        $script:RestoredAcl = @()
        Mock -CommandName Set-Acl -MockWith {
            $script:RestoredAcl += [pscustomobject]@{
                Path = $LiteralPath
                Sddl = $AclObject.Sddl
            }
        }

        $result = Restore-AdapterSddl -Guid $guid -Name 'Ethernet' -BackupFile $backupPath

        $result | Should -Be $true
        $script:RestoredAcl.Count | Should -Be 1
        $script:RestoredAcl[0].Path | Should -Match 'NetBT\\Parameters\\Interfaces'
        $script:RestoredAcl[0].Sddl | Should -Be 'D:AI'
    }

    It 'detects drift when adapter is partially locked' {
        Import-AdapterLockFunction -Name 'Test-AdapterLockedDetailed', 'Test-AdapterLocked', 'Test-LockIntegrity', 'Get-InterfaceKeyPath', 'Import-LockPolicy', 'Write-EvtLog', 'Get-LockBadgeFromDetail', 'Get-LockDetailText'
        Mock -CommandName Get-NetAdapter -MockWith {
            @([pscustomobject]@{
                Name = 'Ethernet'
                InterfaceGuid = '{11111111-1111-1111-1111-111111111111}'
            })
        }
        Mock -CommandName Test-Path -MockWith {
            if ($LiteralPath -and $LiteralPath -like '*policy.json') { return $false }
            return $true
        }
        $script:aclCallCount = 0
        Mock -CommandName Get-Acl -MockWith {
            $script:aclCallCount++
            if ($script:aclCallCount -eq 1) {
                New-FakeAcl
            } else {
                New-FakeAcl -AccessControlType 'Allow'
            }
        }

        $results = @(Test-LockIntegrity)
        $results.Count | Should -Be 1
        $results[0].Status | Should -Be 'DRIFT'
    }

    It 'returns post-remediation lock state after fixing drift' {
        Import-AdapterLockFunction -Name 'Test-LockIntegrity', 'Test-AdapterLocked', 'Test-AdapterLockedDetailed', 'Find-AdapterByIdentifier', 'Lock-Adapter', 'Write-EvtLog', 'Get-LockBadgeFromDetail', 'Get-LockDetailText'
        Mock -CommandName Get-NetAdapter -MockWith {
            @([pscustomobject]@{
                Name = 'Ethernet'
                InterfaceGuid = '{11111111-1111-1111-1111-111111111111}'
            })
        }
        Mock -CommandName Test-Path -MockWith {
            if ($LiteralPath -and $LiteralPath -like '*policy.json') { return $false }
            return $true
        }
        Mock -CommandName Test-AdapterLocked -MockWith { $true }
        Mock -CommandName Find-AdapterByIdentifier -MockWith {
            [pscustomobject]@{
                Name = 'Ethernet'
                InterfaceGuid = '{11111111-1111-1111-1111-111111111111}'
            }
        }
        $script:detailCallCount = 0
        Mock -CommandName Test-AdapterLockedDetailed -MockWith {
            $script:detailCallCount++
            if ($script:detailCallCount -eq 1) {
                return [pscustomobject]@{
                    V4Locked = $true; V4Exists = $true
                    V6Locked = $false; V6Exists = $true
                    NetBTLocked = $false; NetBTExists = $true
                }
            }
            [pscustomobject]@{
                V4Locked = $true; V4Exists = $true
                V6Locked = $true; V6Exists = $true
                NetBTLocked = $true; NetBTExists = $true
            }
        }
        Mock -CommandName Lock-Adapter -MockWith { $true }

        $results = @(Test-LockIntegrity -Fix)

        $results.Count | Should -Be 1
        $results[0].OriginalStatus | Should -Be 'DRIFT'
        $results[0].Status | Should -Be 'OK'
        $results[0].Remediated | Should -Be $true
    }

    It 'covers all three IP stack keys per adapter' {
        Import-AdapterLockFunction -Name 'Get-InterfaceKeyPath'
        $guid = '{11111111-1111-1111-1111-111111111111}'
        $paths = Get-InterfaceKeyPath -Guid $guid

        $paths.Count | Should -Be 3
        ($paths | Where-Object { $_ -match 'Tcpip\\Parameters\\Interfaces' }) | Should -Not -BeNullOrEmpty
        ($paths | Where-Object { $_ -match 'Tcpip6\\Parameters\\Interfaces' }) | Should -Not -BeNullOrEmpty
        ($paths | Where-Object { $_ -match 'NetBT\\Parameters\\Interfaces' }) | Should -Not -BeNullOrEmpty
    }

    It 'marks NetBT mismatch as partial lock state' {
        Import-AdapterLockFunction -Name 'Get-LockBadgeFromDetail', 'Get-LockDetailText'
        $detail = [pscustomobject]@{
            V4Locked    = $true
            V4Exists    = $true
            V6Locked    = $true
            V6Exists    = $true
            NetBTLocked = $false
            NetBTExists = $true
        }

        Get-LockBadgeFromDetail -Detail $detail | Should -Be 'PARTIAL'
        Get-LockDetailText -Detail $detail | Should -Match 'Open: NetBT'
    }

    It 'allows missing optional stack keys when deriving locked state' {
        Import-AdapterLockFunction -Name 'Get-LockBadgeFromDetail', 'Get-LockDetailText'
        $detail = [pscustomobject]@{
            V4Locked    = $true
            V4Exists    = $true
            V6Locked    = $false
            V6Exists    = $false
            NetBTLocked = $false
            NetBTExists = $false
        }

        Get-LockBadgeFromDetail -Detail $detail | Should -Be 'LOCKED'
        Get-LockDetailText -Detail $detail | Should -Be 'Locked: IPv4'
    }

    It 'generates HTML fleet report with correct structure' {
        Import-AdapterLockFunction -Name 'Export-LockReport', 'ConvertTo-ReportHtml'
        $script:Version = 'test'
        $data = @(
            [pscustomobject]@{ Computer = 'HOST1'; Adapter = 'Ethernet'; GUID = '{aaa}'; Mode = 'Static'; Locked = 'LOCKED'; Detail = 'v4+v6' }
            [pscustomobject]@{ Computer = 'HOST2'; Adapter = 'Wi-Fi'; GUID = '{bbb}'; Mode = 'DHCP'; Locked = 'Unlocked'; Detail = '-' }
        )
        $reportPath = Join-Path $TestDrive 'test-report.html'
        Export-LockReport -OutputFile $reportPath -Data $data
        $html = Get-Content $reportPath -Raw
        $html | Should -Match 'AdapterLock Fleet Report'
        $html | Should -Match 'HOST1'
        $html | Should -Match 'HOST2'
        $html | Should -Match 'LOCKED'
        $html | Should -Match 'Unlocked'
    }

    It 'HTML-encodes fleet report values' {
        Import-AdapterLockFunction -Name 'Export-LockReport', 'ConvertTo-ReportHtml'
        $script:Version = 'test'
        $data = @(
            [pscustomobject]@{
                Computer = 'HOST<script>'
                Adapter = 'Ethernet "PACS"'
                GUID = '{aaa}'
                Mode = 'Static'
                Locked = 'LOCKED'
                Detail = '<open>&drift'
            }
        )
        $reportPath = Join-Path $TestDrive 'encoded-report.html'
        Export-LockReport -OutputFile $reportPath -Data $data
        $html = Get-Content $reportPath -Raw

        $html | Should -Match 'HOST&lt;script&gt;'
        $html | Should -Match 'Ethernet &quot;PACS&quot;'
        $html | Should -Match '&lt;open&gt;&amp;drift'
        $html | Should -Not -Match '<script>'
    }

    It 'emits stable JSON and CSV fleet output records' {
        Import-AdapterLockFunction -Name 'Export-LockData', 'Select-LockOutputRecord'
        $data = @(
            [pscustomobject]@{
                Computer = 'HOST1'
                Adapter = 'Ethernet'
                GUID = '{aaa}'
                Locked = 'LOCKED'
                Detail = 'Locked: IPv4'
                Mode = 'Static'
                Extra = 'ignored'
            }
        )

        $json = Export-LockData -Data $data -Format Json
        $parsed = $json | ConvertFrom-Json
        $parsed[0].Computer | Should -Be 'HOST1'
        $parsed[0].PSObject.Properties.Name | Should -Contain 'Mode'
        $parsed[0].PSObject.Properties.Name | Should -Not -Contain 'Extra'

        $csv = Export-LockData -Data $data -Format Csv
        ($csv -join "`n") | Should -Match '"Computer","Adapter","GUID","Locked","Detail","Mode"'
    }

    It 'keeps usable remote query rows when one host fails' {
        Import-AdapterLockFunction -Name 'Invoke-RemoteLockQuery'
        Mock -CommandName Invoke-Command -MockWith {
            if ($ComputerName -eq 'bad-host') { throw 'offline' }
            [pscustomobject]@{
                Computer = $ComputerName
                Adapter = 'Ethernet'
                GUID = '{aaa}'
                Locked = 'LOCKED'
                Detail = 'Locked: IPv4'
                Mode = 'Static'
            }
        }

        $results = @(Invoke-RemoteLockQuery -Targets @('good-host', 'bad-host'))

        $results.Count | Should -Be 1
        $results[0].Computer | Should -Be 'good-host'
    }

    It 'defines WMI tree watchers for every enforced registry surface' {
        Import-AdapterLockFunction -Name 'Get-WmiWatcherDefinition', 'Get-WmiWatcherFilterName'

        $definitions = @(Get-WmiWatcherDefinition)

        $definitions.Count | Should -Be 3
        ($definitions | Where-Object { $_.RootPath -match 'Services\\\\Tcpip\\\\Parameters\\\\Interfaces' }) | Should -Not -BeNullOrEmpty
        ($definitions | Where-Object { $_.RootPath -match 'Services\\\\Tcpip6\\\\Parameters\\\\Interfaces' }) | Should -Not -BeNullOrEmpty
        ($definitions | Where-Object { $_.RootPath -match 'Services\\\\NetBT\\\\Parameters\\\\Interfaces' }) | Should -Not -BeNullOrEmpty
        (Get-WmiWatcherFilterName) | Should -Contain 'AdapterLock_RegistryFilter'
    }

    It 'installs WMI RegistryTreeChangeEvent filters for all stack keys' {
        Import-AdapterLockFunction -Name 'Install-WmiWatcher', 'Get-WmiWatcherDefinition', 'Get-WmiWatcherFilterName', 'Write-EvtLog'
        Mock -CommandName Get-WmiObject -MockWith { @() }
        Mock -CommandName Remove-WmiObject -MockWith {}
        Mock -CommandName Set-WmiInstance -MockWith {
            if ($Class -eq '__EventFilter') {
                [pscustomobject]@{ Name = $Arguments.Name; Query = $Arguments.Query }
            } else {
                [pscustomobject]@{ Name = $Arguments.Name }
            }
        }

        Install-WmiWatcher

        Should -Invoke -CommandName Set-WmiInstance -Times 3 -ParameterFilter {
            $Class -eq '__EventFilter' -and $Arguments.Query -match 'RegistryTreeChangeEvent'
        }
        Should -Invoke -CommandName Set-WmiInstance -Times 1 -ParameterFilter { $Class -eq 'NTEventLogEventConsumer' }
        Should -Invoke -CommandName Set-WmiInstance -Times 3 -ParameterFilter { $Class -eq '__FilterToConsumerBinding' }
    }

    It 'does not install enforcement task when the policy file is missing' {
        Import-AdapterLockFunction -Name 'Install-EnforcementTask'
        Mock -CommandName Test-Path -MockWith { $false }
        Mock -CommandName New-ScheduledTaskAction -MockWith { throw 'Should not create action without policy' }
        Mock -CommandName Register-ScheduledTask -MockWith { throw 'Should not register task without policy' }

        $result = Install-EnforcementTask -PolicyPath (Join-Path $TestDrive 'missing.json')

        $result | Should -Be $false
        Should -Invoke -CommandName New-ScheduledTaskAction -Times 0
        Should -Invoke -CommandName Register-ScheduledTask -Times 0
    }

    It 'builds parseable background worker scripts for WPF operations' {
        Import-AdapterLockFunction -Name `
            'ConvertTo-WorkerLiteral',
            'Get-UiWorkerScript',
            'Write-AppLog',
            'Write-EvtLog',
            'Get-NicType',
            'Get-NicTypeGlyph',
            'Get-RegistryLastWrite',
            'ConvertTo-ReportHtml',
            'ConvertTo-PolicyGuid',
            'ConvertTo-PolicyMac',
            'Get-PolicyIdentifierKey',
            'Export-LockPolicy',
            'Import-LockPolicy',
            'Get-LockPolicySummary',
            'Invoke-LockPolicy',
            'Get-InterfaceKeyPath',
            'Get-AdapterDhcpState',
            'Get-BackupKeyTag',
            'Save-AdapterSddl',
            'ConvertFrom-AdapterBackupFile',
            'Resolve-BackupFile',
            'Get-AdapterBackupRecord',
            'Get-BackupRestorePath',
            'Invoke-SddlRestore',
            'Restore-AdapterSddl',
            'Test-AdapterLockedDetailed',
            'Get-LockBadgeFromDetail',
            'Get-LockDetailText',
            'Test-AdapterLocked',
            'Lock-Adapter',
            'Unlock-Adapter',
            'Get-AdapterRow',
            'Find-AdapterByIdentifier'
        $script:Version = 'test'
        $script:LogPath = Join-Path $TestDrive 'adapterlock.log'
        $script:BackupDir = Join-Path $TestDrive 'Backups'

        $worker = Get-UiWorkerScript -Work { [pscustomobject]@{ Ok = $true } }
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseInput($worker, [ref]$tokens, [ref]$errors) | Out-Null

        $errors.Count | Should -Be 0
        $worker | Should -Match 'param\(\$WorkerArgument\)'
    }

    It 'classifies NIC types' {
        Import-AdapterLockFunction -Name 'Get-NicType'

        Get-NicType -A ([pscustomobject]@{ ifIndex = 1; PhysicalMediaType = ''; InterfaceDescription = 'Loopback' }) | Should -Be 'Loop'
        Get-NicType -A ([pscustomobject]@{ ifIndex = 2; PhysicalMediaType = '802.11'; InterfaceDescription = 'Intel Wi-Fi' }) | Should -Be 'WiFi'
        Get-NicType -A ([pscustomobject]@{ ifIndex = 3; PhysicalMediaType = ''; InterfaceDescription = 'Hyper-V vEthernet' }) | Should -Be 'Virt'
        Get-NicType -A ([pscustomobject]@{ ifIndex = 4; PhysicalMediaType = ''; InterfaceDescription = 'Intel Ethernet' }) | Should -Be 'Phys'
    }

    It 'maps NIC type glyphs and preserves unknown values' {
        Import-AdapterLockFunction -Name 'Get-NicTypeGlyph'

        Get-NicTypeGlyph -Type 'WiFi' | Should -Be ([char]0xE702)
        Get-NicTypeGlyph -Type 'Mystery' | Should -Be 'Mystery'
    }
}
