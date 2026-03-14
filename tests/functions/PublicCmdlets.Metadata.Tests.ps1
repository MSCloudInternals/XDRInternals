$helperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
. $helperPath

$script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:publicCommands = Get-XdrPublicCommands
$script:commandCases = foreach ($command in $script:publicCommands) {
    @{
        Name              = $command.Name
        FunctionPath      = Join-Path $script:repoRoot "XDRInternals\functions\$($command.Name).ps1"
        ParameterSetCount = @($command.ParameterSets).Count
    }
}
$script:testSettings = Get-XdrTestSettings

Describe 'Public cmdlet metadata' -Tag 'Functions', 'PublicSurface' {
    It 'discovers exported public cmdlets from the manifest' {
        @($script:publicCommands).Count | Should -BeGreaterThan 0
    }

    It '<Name> is backed by a public function file' -ForEach $script:commandCases {
        Test-Path $PSItem.FunctionPath | Should -BeTrue
    }

    It '<Name> exposes at least one parameter set' -ForEach $script:commandCases {
        $PSItem.ParameterSetCount | Should -BeGreaterThan 0
    }

    It 'can report full parameter-set coverage when explicitly required' -Skip:(-not ($script:testSettings['liveTests']['enabled'] -and $script:testSettings['execution']['requireFullParameterCoverage'])) {
        $coverage = Get-XdrLiveCoverageReport
        $uncovered = $coverage | Where-Object { -not $_.Covered }

        if ($uncovered) {
            $message = ($uncovered | ForEach-Object { "$($_.CommandName) [$($_.ParameterSetName)]" }) -join ', '
        } else {
            $message = ''
        }

        $message | Should -BeNullOrEmpty
    }
}
