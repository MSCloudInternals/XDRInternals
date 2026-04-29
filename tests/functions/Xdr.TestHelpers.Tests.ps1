$helperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
. $helperPath

Describe 'Xdr.TestHelpers live scenario generation' -Tag 'Functions', 'Live' {
    BeforeAll {
        $runtimeHelperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
        . $runtimeHelperPath
    }

    BeforeEach {
        Remove-Item Env:XDRINTERNALS_ENABLE_MUTATION_TESTS -ErrorAction Ignore
        $script:XdrTestSettings = $null
        $script:XdrTestSettingsPath = $null
        $script:XdrConnectionEstablished = $false
        $script:XdrWorkloadStatus = $null
        $script:XdrFixtureCache = @{}
        $script:XdrTestSettings = Get-XdrDefaultTestSettings
        $script:XdrTestSettings['scenarios']['Invoke-XdrEndpointDeviceLiveResponseCommand'] = @(
            @{
                name       = 'Configured'
                parameters = @{
                    SessionId = 'CLR-smoke'
                    Command   = 'processes'
                }
            }
        )
    }

    It 'skips configured scenarios for mutating cmdlets without WhatIf when mutation tests are disabled' {
        $command = Get-Command Invoke-XdrEndpointDeviceLiveResponseCommand

        $scenario = Get-XdrConfiguredScenarios -Command $command

        $scenario | Should -BeNullOrEmpty
    }

    It 'allows configured scenarios for mutating cmdlets without WhatIf when mutation tests are enabled' {
        $script:XdrTestSettings['execution']['enableMutationTests'] = $true

        $command = Get-Command Invoke-XdrEndpointDeviceLiveResponseCommand

        $scenario = Get-XdrConfiguredScenarios -Command $command

        $scenario | Should -Not -BeNullOrEmpty
        @($scenario).Count | Should -Be 1
        $scenario[0].Parameters.Command | Should -Be 'processes'
    }
}