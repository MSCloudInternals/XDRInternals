Describe 'Incident associated alerts paging' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { throw 'Paged calls must not use the all-pages cache' } -ModuleName XDRInternals
        Mock Set-XdrCache { throw 'Paged calls must not populate the all-pages cache' } -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{
                items               = @([pscustomobject]@{ alertId = 'alert-2' })
                totalPagesAvailable = 200
            }
        } -ModuleName XDRInternals
    }

    It 'requests exactly one page even when more pages exist' {
        $alerts = @(Get-XdrIncidentAssociatedAlert -IncidentId 42 -PageIndex 2 -PageSize 1)

        $alerts | Should -HaveCount 1
        $alerts[0].alertId | Should -Be 'alert-2'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Uri -match '/incidents/42/AssociatedAlerts' -and
            ($Body | ConvertFrom-Json).PageIndex -eq 2 -and
            ($Body | ConvertFrom-Json).PageSize -eq 1
        }
        Should -Invoke Get-XdrCache -ModuleName XDRInternals -Times 0
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0
    }

    It 'uses page one when only a page size is supplied' {
        @(Get-XdrIncidentAssociatedAlert -IncidentId 42 -PageSize 1) | Should -HaveCount 1
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            ($Body | ConvertFrom-Json).PageIndex -eq 1 -and ($Body | ConvertFrom-Json).PageSize -eq 1
        }
    }

    It 'rejects an invalid page size before calling the portal' {
        { Get-XdrIncidentAssociatedAlert -IncidentId 42 -PageIndex 1 -PageSize 51 } | Should -Throw
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0
    }

    It 'throws rather than returning a partial page when the portal fails' {
        Mock Invoke-RestMethod { throw 'upstream failure' } -ModuleName XDRInternals
        { Get-XdrIncidentAssociatedAlert -IncidentId 42 -PageIndex 2 -PageSize 1 } | Should -Throw
    }

    It 'returns an explicitly empty page' {
        Mock Invoke-RestMethod { [pscustomobject]@{ items = @(); totalPagesAvailable = 0 } } -ModuleName XDRInternals
        @(Get-XdrIncidentAssociatedAlert -IncidentId 42 -PageIndex 1 -PageSize 1) | Should -HaveCount 0
    }

    It 'rejects a malformed portal response instead of reporting no alerts' {
        foreach ($response in @([pscustomobject]@{ totalPagesAvailable = 0 }, '<html>error</html>', [pscustomobject]@{ items = 'unexpected' }, [pscustomobject]@{ items = @($null) }, [pscustomobject]@{ items = @([pscustomobject]@{ alertId = 'valid' }, $null) })) {
            Mock Invoke-RestMethod { $response } -ModuleName XDRInternals
            { Get-XdrIncidentAssociatedAlert -IncidentId 42 -PageIndex 1 -PageSize 1 } | Should -Throw
        }
    }

    It 'rejects an oversized upstream page' {
        Mock Invoke-RestMethod { [pscustomobject]@{ items = @('one', 'two') } } -ModuleName XDRInternals
        { Get-XdrIncidentAssociatedAlert -IncidentId 42 -PageIndex 1 -PageSize 1 } | Should -Throw
    }
}