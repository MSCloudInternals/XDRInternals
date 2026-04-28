Describe 'Cloud Apps grouped command surface' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Invoke-XdrCloudAppsRequest { [pscustomobject]@{ ok = $true; path = $Path; body = $Body } } -ModuleName XDRInternals
        Mock Get-XdrCloudAppsDiscoveryStream {
            [pscustomobject]@{
                _id         = 'stream-1'
                displayName = 'Test stream'
            }
        } -ModuleName XDRInternals
    }

    It 'does not expose the misspelled Agressive timeline parameter alias' {
        $command = Get-Command Get-XdrCloudAppsActivityTimeline

        $command.Parameters.ContainsKey('Aggressive') | Should -BeTrue
        $command.Parameters.ContainsKey('Agressive') | Should -BeFalse
    }

    It 'routes app catalog metadata through the grouped app command' {
        Get-XdrCloudAppsApp -Type Catalog -Metadata

        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/discovery/app_catalog/metadata/' -and
            $TypeName -eq 'XdrCloudAppsAppCatalogMetadata'
        }
    }

    It 'routes discovered app queries through discovery stream context' {
        Get-XdrCloudAppsApp -Type Discovered -StreamName 'Test*' -Limit 25

        Should -Invoke Get-XdrCloudAppsDiscoveryStream -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $StreamName -eq 'Test*'
        }
        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/discovery/discovered_apps/' -and
            $Method -eq 'Post' -and
            $Body.streamId -eq 'stream-1' -and
            $Body.limit -eq 25
        }
    }

    It 'routes governance summary through App Governance status APIs' {
        Mock Invoke-XdrCloudAppsRequest {
            switch -Wildcard ($Path) {
                '*istenantonboarded' { $true }
                '*istenantinsightsready' { $true }
                '*tenantmetrics' { [pscustomobject]@{ totalApps = 10; highPrivilegeApps = 2; overpermissionedApps = 1; unusedApps = 3; riskyApps = 4 } }
            }
        } -ModuleName XDRInternals

        $result = Get-XdrCloudAppsGovernance

        $result.TotalApps | Should -Be 10
        $result.IsOnboarded | Should -BeTrue
    }

    It 'splits mixed recent and archived count-only timeline requests' {
        $from = [datetime]::UtcNow.AddDays(-35)
        $to = [datetime]::UtcNow.AddDays(-1)

        Get-XdrCloudAppsActivityTimeline -CountOnly -FromDate $from -ToDate $to

        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/archived_activities/count/'
        }
        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/activities/count/'
        }
    }
}

Describe 'Invoke-XdrCloudAppsRequest' {
    BeforeEach {
        $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
        $script:headers = @{}
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { [pscustomobject]@{ data = @([pscustomobject]@{ name = 'Item1' }) } } -ModuleName XDRInternals
    }

    It 'unwraps data arrays and applies the requested type name' {
        InModuleScope XDRInternals {
            $result = Invoke-XdrCloudAppsRequest -Path '/mcas/test' -TypeName 'XdrCloudAppsTest'

            $result.name | Should -Be 'Item1'
            $result.PSObject.TypeNames[0] | Should -Be 'XdrCloudAppsTest'
        }
    }
}

