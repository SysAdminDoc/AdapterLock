$script:RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:AdapterLockScript = Join-Path $script:RepoRoot 'AdapterLock.ps1'

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

Describe 'AdapterLock core functions' {
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
        Mock Test-Path { $true }
        Mock Get-Acl { New-FakeAcl }

        $result = Test-AdapterLockedDetailed -Guid '{11111111-1111-1111-1111-111111111111}'

        $result.V4Locked | Should Be $true
        $result.V6Locked | Should Be $true
        $result.NetBTLocked | Should Be $true
        Assert-MockCalled Get-Acl -Times 3
    }

    It 'logs lock dry-run paths without writing ACLs' {
        Import-AdapterLockFunction -Name 'Get-InterfaceKeyPath', 'Get-AdapterDhcpState', 'Lock-Adapter'
        Mock Test-Path { $true }
        Mock Get-ItemPropertyValue { 0 }
        Mock Get-Acl { throw 'Get-Acl should not be called during dry-run' }
        Mock Set-Acl { throw 'Set-Acl should not be called during dry-run' }

        $result = Lock-Adapter -Guid '{11111111-1111-1111-1111-111111111111}' -Name 'Ethernet' -Preview

        $result | Should Be $true
        ($script:LogMessages.Message -join "`n") | Should Match 'DRY-RUN Lock Ethernet'
    }

    It 'logs unlock dry-run paths without writing ACLs' {
        Import-AdapterLockFunction -Name 'Get-InterfaceKeyPath', 'Unlock-Adapter'
        Mock Test-Path { $true }
        Mock Get-Acl { throw 'Get-Acl should not be called during dry-run' }
        Mock Set-Acl { throw 'Set-Acl should not be called during dry-run' }

        $result = Unlock-Adapter -Guid '{11111111-1111-1111-1111-111111111111}' -Name 'Ethernet' -Preview

        $result | Should Be $true
        ($script:LogMessages.Message -join "`n") | Should Match 'DRY-RUN Unlock Ethernet'
    }

    It 'finds adapters by name, MAC, and GUID' {
        Import-AdapterLockFunction -Name 'Find-AdapterByIdentifier'
        Mock Get-NetAdapter {
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

        (Find-AdapterByIdentifier -ByName 'Ethernet').InterfaceGuid | Should Be '{11111111-1111-1111-1111-111111111111}'
        (Find-AdapterByIdentifier -ByMac '112233445566').Name | Should Be 'PACS Link'
        (Find-AdapterByIdentifier -ByGuid '{22222222-2222-2222-2222-222222222222}').Name | Should Be 'PACS Link'
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

        $adapters.Count | Should Be 1
        $adapters[0].Name | Should Be 'Ethernet'
        $adapters[0].State | Should Be 'locked'
    }

    It 'classifies NIC types' {
        Import-AdapterLockFunction -Name 'Get-NicType'

        Get-NicType -A ([pscustomobject]@{ ifIndex = 1; PhysicalMediaType = ''; InterfaceDescription = 'Loopback' }) | Should Be 'Loop'
        Get-NicType -A ([pscustomobject]@{ ifIndex = 2; PhysicalMediaType = '802.11'; InterfaceDescription = 'Intel Wi-Fi' }) | Should Be 'WiFi'
        Get-NicType -A ([pscustomobject]@{ ifIndex = 3; PhysicalMediaType = ''; InterfaceDescription = 'Hyper-V vEthernet' }) | Should Be 'Virt'
        Get-NicType -A ([pscustomobject]@{ ifIndex = 4; PhysicalMediaType = ''; InterfaceDescription = 'Intel Ethernet' }) | Should Be 'Phys'
    }

    It 'maps NIC type glyphs and preserves unknown values' {
        Import-AdapterLockFunction -Name 'Get-NicTypeGlyph'

        Get-NicTypeGlyph -Type 'WiFi' | Should Be ([char]0xE702)
        Get-NicTypeGlyph -Type 'Mystery' | Should Be 'Mystery'
    }
}
