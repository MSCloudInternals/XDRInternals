Describe 'Identity inventory sort direction contract' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrIdentityHeaders { @{} } -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Get-XdrIdentityIdentityCount { 1 } -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            $request = $Body | ConvertFrom-Json
            if ($request.SortBy.Direction -notin @('Asc', 'Desc')) {
                throw 'Invalid API SortDirectionType'
            }
            [pscustomobject]@{ data = @([pscustomobject]@{ displayName = 'Synthetic identity' }) }
        } -ModuleName XDRInternals
    }

    It 'sends <Expected> for public <Direction> in <Mode> mode' -TestCases @(
        @{ Direction = 'Asc'; Expected = 'Asc'; Mode = 'Paged' }
        @{ Direction = 'Dsc'; Expected = 'Desc'; Mode = 'Paged' }
        @{ Direction = 'Asc'; Expected = 'Asc'; Mode = 'All' }
        @{ Direction = 'Dsc'; Expected = 'Desc'; Mode = 'All' }
    ) {
        param($Direction, $Expected, $Mode)
        $arguments = @{ SortDirection = $Direction; SortByField = 'CreatedDateTime'; Force = $true }
        if ($Mode -eq 'All') { $arguments.All = $true } else { $arguments.PageSize = 1 }

        $items = @(Get-XdrIdentityIdentity @arguments -ErrorAction Stop)

        $items.Count | Should -Be 1
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/identities' -and
            ($Body | ConvertFrom-Json).SortBy.Field -eq 'CreatedDateTime' -and
            ($Body | ConvertFrom-Json).SortBy.Direction -eq $Expected
        }
    }
}
