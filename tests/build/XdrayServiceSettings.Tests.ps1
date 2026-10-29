BeforeDiscovery {
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $scoped = @(Get-Content (Join-Path $root 'XDRay/CmdletApiMapping.json') -Raw | ConvertFrom-Json | Where-Object { $_.Method -eq 'GET' -and $_.Cmdlet -like 'Get-XdrEndpoint*' } | ForEach-Object { @{ Cmdlet = $_.Cmdlet; ApiUri = $_.ApiUri; Query = $_.Query; Parameters = $_.Parameters } })
}

Describe 'XDRay service-settings generator and replay' {
    BeforeAll {
        $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $script:FixtureRoot = Join-Path $TestDrive 'mapping-repo'
        foreach ($directory in @('build', 'XDRInternals/functions', 'XDRInternals/internal/functions', 'XDRay', 'XDRay Firefox')) {
            $null = New-Item -ItemType Directory -Path (Join-Path $script:FixtureRoot $directory) -Force
        }
        foreach ($relative in @('build/Sync-CmdletDocumentation.ps1', 'README.md', 'XDRInternals/XDRInternals.psd1')) {
            Copy-Item (Join-Path $script:RepoRoot $relative) (Join-Path $script:FixtureRoot $relative)
        }
        $script:Names = @(
            'Get-XdrEndpointConfigurationAttackDisruptionExclusion'
            'Get-XdrEndpointConfigurationAutomatedInvestigation'
            'Get-XdrEndpointConfigurationAutomatedInvestigationExclusion'
            'Get-XdrEndpointConfigurationCustomCollectionModel'
            'Get-XdrEndpointConfigurationIsolationAllowRule'
            'Get-XdrEndpointOnboardingActivator'
            'Get-XdrEndpointOnboardingStatus'
            'Get-XdrEndpointWebContentFilteringPolicy'
        )
        foreach ($name in @($script:Names) + @('Get-XdrEndpointConfigurationAdvancedFeatures', 'Get-XdrReport')) {
            Copy-Item (Join-Path $script:RepoRoot "XDRInternals/functions/$name.ps1") (Join-Path $script:FixtureRoot 'XDRInternals/functions')
        }
        Copy-Item (Join-Path $script:RepoRoot 'XDRInternals/internal/functions/Get-XdrReportCatalog.ps1') (Join-Path $script:FixtureRoot 'XDRInternals/internal/functions')
        $script:Existing = @{
            Cmdlet = 'Get-XdrEndpointConfigurationAdvancedFeatures'
            ApiUri = 'https://security.microsoft.com/apiproxy/mtp/settings/GetAdvancedFeaturesSetting'
        }
        $stale = @($script:Existing) + @(
            @{ Cmdlet = 'Get-XdrEndpointConfigurationAttackDisruptionExclusion'; ApiUri = 'https://security.microsoft.com/apiproxy/mtp/disrupt/api/exclusions/{path}' }
            @{ Cmdlet = 'Get-XdrEndpointConfigurationIsolationAllowRule'; ApiUri = 'https://security.microsoft.com/apiproxy/mtp/customizationApi/' }
            @{ Cmdlet = 'Get-XdrEndpointOnboardingActivator'; ApiUri = 'https://security.microsoft.com/apiproxy/mtp/packages/DownloadOnboardingWindowsActivator/{list}' }
        )
        $script:Paths = @('README.md', 'XDRInternals/XDRInternals.psd1', 'XDRay/CmdletApiMapping.json', 'XDRay Firefox/CmdletApiMapping.json')
        foreach ($path in $script:Paths | Where-Object { $_ -like '*.json' }) {
            $stale | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $script:FixtureRoot $path) -Encoding utf8
        }
        & (Join-Path $script:FixtureRoot 'build/Sync-CmdletDocumentation.ps1')
        $script:Generated = @(Get-Content (Join-Path $script:FixtureRoot 'XDRay/CmdletApiMapping.json') -Raw | ConvertFrom-Json)
    }

    It 'replaces stale aliases with thirteen explicit GET contracts for all eight getters' {
        $routes = @($script:Generated | Where-Object Cmdlet -In $script:Names)
        $routes | Should -HaveCount 13
        @($routes.Cmdlet | Sort-Object -Unique) | Should -HaveCount 8
        @($routes | Where-Object Method -NE 'GET') | Should -HaveCount 0
        @($routes | Where-Object ApiUri -Match '[{}]') | Should -HaveCount 0
        @($routes | Where-Object { $null -eq $_.Parameters }) | Should -HaveCount 0
        @($routes | Where-Object { $_.ApiUri -like '*/customizationApi/' -and -not $_.Query }) | Should -HaveCount 0
    }

    It 'preserves the unrelated existing mapping' {
        $existing = @($script:Generated | Where-Object Cmdlet -EQ $script:Existing.Cmdlet)
        $existing | Should -HaveCount 1
        $existing[0].ApiUri | Should -Be $script:Existing.ApiUri
        @($existing[0].PSObject.Properties.Name | Sort-Object) | Should -Be @('ApiUri', 'Cmdlet')
    }

    It 'generates identical Chromium and Firefox bytes and is stable on a second run' {
        $chrome = Join-Path $script:FixtureRoot 'XDRay/CmdletApiMapping.json'
        $firefox = Join-Path $script:FixtureRoot 'XDRay Firefox/CmdletApiMapping.json'
        (Get-FileHash $chrome).Hash | Should -Be (Get-FileHash $firefox).Hash
        $before = @($script:Paths | ForEach-Object { (Get-FileHash (Join-Path $script:FixtureRoot $_)).Hash })
        & (Join-Path $script:FixtureRoot 'build/Sync-CmdletDocumentation.ps1')
        $after = @($script:Paths | ForEach-Object { (Get-FileHash (Join-Path $script:FixtureRoot $_)).Hash })
        $after | Should -Be $before
    }

    It 'preserves all report catalog contracts and service contracts during report-only generation' {
        $reports = @($script:Generated | Where-Object Cmdlet -EQ 'Get-XdrReport')
        $reports | Should -HaveCount 183
        $expectedReports = @(Get-Content (Join-Path $script:RepoRoot 'XDRay/CmdletApiMapping.json') -Raw | ConvertFrom-Json | Where-Object Cmdlet -EQ 'Get-XdrReport')
        (ConvertTo-Json -InputObject $reports -Depth 100 -Compress) | Should -BeExactly (ConvertTo-Json -InputObject $expectedReports -Depth 100 -Compress)
        $before = (Get-FileHash (Join-Path $script:FixtureRoot 'XDRay/CmdletApiMapping.json')).Hash
        & (Join-Path $script:FixtureRoot 'build/Sync-CmdletDocumentation.ps1') -MappingCmdlet Get-XdrReport
        (Get-FileHash (Join-Path $script:FixtureRoot 'XDRay/CmdletApiMapping.json')).Hash | Should -Be $before
    }

    It 'runs real Chromium and Firefox panel matching and command regressions offline' {
        $node = Get-Command node -CommandType Application -ErrorAction Stop
        $output = & $node.Source --test --test-reporter=tap (Join-Path $script:RepoRoot 'tests/build/XdrayServiceSettings.Tests.js') 2>&1
        $nodeExitCode = $LASTEXITCODE
        $nodeExitCode | Should -Be 0 -Because ($output -join "`n")
        ($output -join "`n") | Should -Match '# tests 83'
        ($output -join "`n") | Should -Match '# fail 0'
    }

    It 'replays <Cmdlet> <ApiUri> <Query> through the actual getter without authentication' -ForEach $scoped {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { [pscustomobject]@{ RequestUri = [string]$Uri; results = @() } } -ModuleName XDRInternals
        $arguments = @{}
        foreach ($property in $Parameters.PSObject.Properties) {
            if ($property.Value -eq 'switch:true') { $arguments[$property.Name] = $true }
            else {
                $property.Value | Should -Match '^fixed:'
                $arguments[$property.Name] = $property.Value.Substring(6)
            }
        }
        $result = & $Cmdlet @arguments
        $actual = [uri]$result.RequestUri
        $actual.GetLeftPart([System.UriPartial]::Path) | Should -Be $ApiUri
        foreach ($constraint in @($Query -split '&' | Where-Object { $_ })) {
            $actual.Query.TrimStart('?').Split('&') | Should -Contain $constraint
        }
        Should -Invoke Update-XdrConnectionSettings -ModuleName XDRInternals -Times 1
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1
    }
}
