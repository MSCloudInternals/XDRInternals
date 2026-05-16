Describe 'Xdr.BenchmarkHelpers planning' -Tag 'Functions', 'Benchmarks' {
    BeforeAll {
        $helperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.BenchmarkHelpers.ps1'
        . $helperPath
    }

    It 'provides benchmark defaults with current branch wiring and common windows' {
        $settings = Get-XdrBenchmarkDefaultSettings

        $settings.benchmarks.enabled | Should -BeFalse
        $settings.branches.ContainsKey('current') | Should -BeTrue
        $settings.windows.ContainsKey('24h') | Should -BeTrue
        $settings.windows.ContainsKey('60d') | Should -BeTrue
        $settings.execution.defaultThrottleLimit | Should -Be 16
        $settings.execution.defaultPaginationDelayMinMilliseconds | Should -Be 0
        $settings.execution.defaultPaginationDelayMaxMilliseconds | Should -Be 0
    }

    It 'captures all configured windows from a single ToDate anchor' {
        $settings = Get-XdrBenchmarkDefaultSettings
        $capturedToDate = [datetime]'2026-05-12T08:00:00Z'

        $windowTable = Get-XdrBenchmarkWindowTable -Settings $settings -CapturedToDate $capturedToDate

        $windowTable['24h'].toDate | Should -Be $capturedToDate
        $windowTable['24h'].fromDate | Should -Be ([datetime]'2026-05-11T08:00:00Z')
        $windowTable['7d'].fromDate | Should -Be ([datetime]'2026-05-05T08:00:00Z')
        $windowTable['60d'].totalHours | Should -Be 1440
    }

    It 'expands paired ABBA runs for single-device scenarios and tracks concurrency budget' {
        $settings = Get-XdrBenchmarkDefaultSettings
        $settings.devices = @(
            @{ name = 'DenseWindows'; deviceId = ('a' * 40) },
            @{ name = 'MacPrimary'; deviceId = ('b' * 40) }
        )
        $settings.branches = @{
            main    = @{ label = 'main'; modulePath = 'C:\main\XDRInternals.psd1'; repoPath = 'C:\main' }
            current = @{ label = 'current'; modulePath = 'C:\current\XDRInternals.psd1'; repoPath = 'C:\current' }
        }
        $settings.scenarios.singleDevice = @(
            @{
                name        = 'baseline'
                deviceNames = @('DenseWindows')
                windowNames = @('24h')
                branchNames = @('main', 'current')
                repeats     = 2
                throttleLimit = 10
                paginationDelayMinMilliseconds = 100
                paginationDelayMaxMilliseconds = 300
            }
        )
        $settings.scenarios.concurrentDevices = @(
            @{
                name              = 'pair'
                deviceNames       = @('DenseWindows', 'MacPrimary')
                windowNames       = @('7d')
                branchNames       = @('main', 'current')
                repeats           = 1
                throttleLimit     = 6
                deviceConcurrency = 2
            }
        )

        $windowTable = Get-XdrBenchmarkWindowTable -Settings $settings -CapturedToDate ([datetime]'2026-05-12T08:00:00Z')
        $plan = Get-XdrBenchmarkRunPlan -Settings $settings -WindowTable $windowTable

        @($plan | Where-Object { $_.groupName -eq 'singleDevice' } | ForEach-Object branchName) | Should -Be @('main', 'current', 'current', 'main')

        $concurrentRun = $plan | Where-Object { $_.groupName -eq 'concurrentDevices' } | Select-Object -First 1
        $concurrentRun.deviceConcurrency | Should -Be 2
        $concurrentRun.requestBudget | Should -Be 12
        $concurrentRun.deviceSetLabel | Should -Be 'DenseWindows+MacPrimary'

        $singleRun = $plan | Where-Object { $_.groupName -eq 'singleDevice' } | Select-Object -First 1
        $singleRun.paginationDelayMinMilliseconds | Should -Be 100
        $singleRun.paginationDelayMaxMilliseconds | Should -Be 300
    }
}
