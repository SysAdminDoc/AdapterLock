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

            [pscustomobject]@{
                Access = @(
                    [pscustomobject]@{
                        AccessControlType = $AccessControlType
                        IdentityReference = [pscustomobject]@{ Value = $Identity }
                    }
                )
            }
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
        Import-AdapterLockFunction -Name 'Export-LockPolicy', 'Import-LockPolicy'
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
        Import-AdapterLockFunction -Name 'Import-LockPolicy'
        $policyPath = Join-Path $TestDrive 'bad-no-id.json'
        @{ Version = '0.6.0'; Adapters = @(@{ State = 'locked' }) } | ConvertTo-Json -Depth 3 | Set-Content $policyPath
        $result = @(Import-LockPolicy -Path $policyPath)
        $result.Count | Should -Be 0
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
        Import-AdapterLockFunction -Name 'Export-LockReport'
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
