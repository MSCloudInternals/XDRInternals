Describe 'Captured Defender hunting proxy routes' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { throw 'Unverified hunting route' } -ModuleName XDRInternals
    }

    It 'reads schema from the hunting proxy and caches the tables' {
        Mock Invoke-RestMethod { [pscustomobject]@{ Tables = @([pscustomobject]@{ Name = 'DeviceEvents' }) } } -ModuleName XDRInternals -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq 'https://security.microsoft.com/apiproxy/hunting/huntingService/schema'
        }
        $tables = @(Get-XdrAdvancedHuntingTableSchema -Force)
        $tables.Name | Should -Be 'DeviceEvents'
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -Exactly
    }

    It 'reads bounded history from the hunting proxy' {
        Mock Invoke-RestMethod { @([pscustomobject]@{ QueryText = 'DeviceEvents | take 1' }) } -ModuleName XDRInternals -ParameterFilter {
            $Method -eq 'Post' -and $Uri -eq 'https://security.microsoft.com/apiproxy/hunting/huntingService/reports/userHistory' -and
                ($Body | ConvertFrom-Json).maxResults -eq 1
        }
        $rows = @(Get-XdrAdvancedHuntingUserHistory -StartTime ([datetime]'2026-10-28T00:00:00Z') -MaxResults 1)
        $rows | Should -HaveCount 1
    }

    It 'uses the same verified history route in the reporting catalog' {
        $definition = Get-XdrReportDefinition -Name 'Hunting.UserHistory'
        $definition.Path | Should -Be '/apiproxy/hunting/huntingService/reports/userHistory'
        $definition.Method | Should -Be 'Post'
    }
}
