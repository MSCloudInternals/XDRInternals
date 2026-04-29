$script:helperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
. $script:helperPath

$script:testSettings = Get-XdrTestSettings
$script:liveEnabled = [bool]$script:testSettings['liveTests']['enabled']
$script:liveScenarios = if ($script:liveEnabled) { Get-XdrLiveScenarios } else { @() }
$script:liveScenarioCases = foreach ($scenario in $script:liveScenarios) {
    @{
        CommandName  = $scenario.CommandName
        ScenarioName = $scenario.ScenarioName
        Scenario     = $scenario
    }
}

Describe 'Public cmdlet live smoke tests' -Tag 'Functions', 'PublicSurface', 'Live' {
    BeforeAll {
        $runtimeHelperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
        . $runtimeHelperPath
    }

    It 'is disabled until live test settings are enabled' -Skip:$script:liveEnabled {
        $true | Should -BeTrue
    }

    It '<CommandName> [<ScenarioName>] executes without throwing' -ForEach $script:liveScenarioCases {
        $execution = Invoke-XdrLiveScenario -Scenario $PSItem.Scenario

        if ($execution.Status -eq 'Skipped') {
            Set-ItResult -Skipped -Because $execution.Reason
            return
        }

        $execution.Status | Should -Be 'Passed'
    }
}
