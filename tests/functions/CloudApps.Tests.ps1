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
        $command.Parameters.ContainsKey('ExportFormat') | Should -BeTrue
    }

    It 'keeps only live-validated app type choices public' {
        $typeParameter = (Get-Command Get-XdrCloudAppsApp).Parameters['Type']
        $validValues = $typeParameter.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            Select-Object -ExpandProperty ValidValues

        $validValues | Should -Contain 'Discovered'
        $validValues | Should -Contain 'OAuth'
        $validValues | Should -Not -Contain 'AiAgent'
        $validValues | Should -Not -Contain 'ConnectedService'
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

    It 'returns discovery streams from the dedicated parameter set' {
        $result = Get-XdrCloudAppsDiscovery -ListStreams

        $result._id | Should -Be 'stream-1'
        Should -Invoke Get-XdrCloudAppsDiscoveryStream -ModuleName XDRInternals -Times 1 -Exactly
    }

    It 'routes governance summary through App Governance status APIs' {
        Mock Invoke-XdrCloudAppsRequest {
            switch -Wildcard ($Path) {
                '*istenantonboarded' { $true }
                '*istenantinsightsready' { $true }
                '*tenantmetrics' { [pscustomobject]@{ numberOfApps = 10; numberOfHighPrivilegedApps = 2; numberOfOverPermissionedApps = 1; numberOfUnusedApps = 3; numberOfRiskyApps = 4 } }
            }
        } -ModuleName XDRInternals

        $result = Get-XdrCloudAppsGovernance

        $result.TotalApps | Should -Be 10
        $result.HighPrivilegeApps | Should -Be 2
        $result.IsOnboarded | Should -BeTrue
    }

    It 'reports File policy metadata as unsupported by the live Cloud Apps API' {
        { Get-XdrCloudAppsPolicy -Type File -Metadata } |
            Should -Throw -ExpectedMessage '*File policy metadata is not exposed by the live Cloud Apps API*'
    }

    It 'adds the File policy type filter without mutating caller filters' {
        $filters = @{ enabled = @{ eq = @($true) } }
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { [pscustomobject]@{ data = @([pscustomobject]@{ name = 'File policy' }) } } -ModuleName XDRInternals

        Get-XdrCloudAppsPolicy -Type File -Filters $filters | Out-Null

        $filters.ContainsKey('type') | Should -BeFalse
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            ($Body | ConvertFrom-Json).filters.type.eq[0] -eq 'FILE'
        }
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

    It 'routes discovered app note updates through the write cmdlet' {
        Set-XdrCloudAppsDiscoveredApp -AppId '12345' -Note 'Approved' -Confirm:$false | Out-Null

        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/discovery/discovery_app/update_app_note/' -and
            $Method -eq 'Post' -and
            $Body.pk -eq '12345' -and
            $Body.note -eq 'Approved'
        }
    }

    It 'honors WhatIf for discovered app note updates' {
        Set-XdrCloudAppsDiscoveredApp -AppId '12345' -Note 'Approved' -WhatIf

        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 0 -Exactly
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

    It 'emits compact Cloud Apps request errors without portal HTML' {
        Mock Invoke-RestMethod {
            $exception = [System.Exception]::new('Response status code does not indicate success: 404 (Not Found).')
            $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'NotFound', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)
            $errorRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('var __ADALLOM_CONSTS = {};404Page not found')
            throw $errorRecord
        } -ModuleName XDRInternals

        InModuleScope XDRInternals {
            { Invoke-XdrCloudAppsRequest -Path '/mcas/missing' } |
                Should -Throw -ExpectedMessage '*Cloud Apps request failed: Get https://security.microsoft.com/apiproxy/mcas/missing returned request failure. The service returned an HTML portal error page.*'
        }
    }
}
