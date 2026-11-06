Describe 'Advanced Hunting read routing and failure caching' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { throw 'Unexpected hunting route' } -ModuleName XDRInternals
    }

    It 'reads saved functions through the hunting proxy' {
        Mock Invoke-RestMethod { @([pscustomobject]@{ Id = 42; Name = 'Saved' }) } -ModuleName XDRInternals -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq 'https://security.microsoft.com/apiproxy/hunting/huntingService/savedFunctions'
        }
        $rows = @(Get-XdrAdvancedHuntingFunction -Force -WarningAction SilentlyContinue)
        $rows | Should -HaveCount 1
        $rows[0].Id | Should -Be 42
        Should -Invoke Set-XdrCache -Times 1 -Exactly -ModuleName XDRInternals
    }

    It 'reads one saved function through the hunting proxy' {
        Mock Invoke-RestMethod { [pscustomobject]@{ Id = 42; Body = 'DeviceEvents | take 1' } } -ModuleName XDRInternals -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq 'https://security.microsoft.com/apiproxy/hunting/huntingService/functions/defender/savedfunctions/42'
        }
        (Get-XdrAdvancedHuntingFunction -Id 42 -WarningAction SilentlyContinue).Id | Should -Be 42
    }

    It 'returns a valid empty saved-function cache without contacting the service' {
        Mock Get-XdrCache { [pscustomobject]@{ Value = @(); NotValidAfter = (Get-Date).AddMinutes(10) } } -ModuleName XDRInternals
        @(Get-XdrAdvancedHuntingFunction -WarningAction SilentlyContinue -ErrorAction SilentlyContinue) | Should -HaveCount 0
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly -ModuleName XDRInternals
        Should -Invoke Set-XdrCache -Times 0 -Exactly -ModuleName XDRInternals
    }

    It 'preserves HTTP <Status> on a <Mode> failure and never caches it' -ForEach @(
        foreach ($mode in @('list', 'detail')) {
            foreach ($status in @(401, 403, 429, 500)) { @{ Mode = $mode; Status = $status } }
        }
    ) {
        $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$Status)
        $global:__pester_data.HuntingReadException = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Synthetic provider failure', $response)
        Mock Invoke-RestMethod { throw $global:__pester_data.HuntingReadException } -ModuleName XDRInternals
        $caught = $null
        try {
            if ($Mode -eq 'list') { Get-XdrAdvancedHuntingFunction -Force -WarningAction SilentlyContinue -ErrorAction Stop }
            else { Get-XdrAdvancedHuntingFunction -Id 42 -WarningAction SilentlyContinue -ErrorAction Stop }
        } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        [object]::ReferenceEquals($caught.Exception, $global:__pester_data.HuntingReadException) | Should -BeTrue
        $caught.Exception.Response.StatusCode | Should -Be $Status
        Should -Invoke Set-XdrCache -Times 0 -Exactly -ModuleName XDRInternals
    }

    It 'does not cache failed list reads when errors are nonterminating' {
        Mock Invoke-RestMethod { throw [System.UnauthorizedAccessException]::new('Synthetic denied') } -ModuleName XDRInternals
        @(Get-XdrAdvancedHuntingFunction -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue) | Should -HaveCount 0
        Should -Invoke Set-XdrCache -Times 0 -Exactly -ModuleName XDRInternals
    }

    It 'preserves the not-found warning only for typed detail HTTP 404' {
        Mock Invoke-RestMethod {
            $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::NotFound)
            throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Synthetic missing', $response)
        } -ModuleName XDRInternals
        $warnings = @()
        @(Get-XdrAdvancedHuntingFunction -Id 42 -WarningAction SilentlyContinue -WarningVariable warnings -ErrorAction Stop) | Should -HaveCount 0
        @($warnings) | Should -HaveCount 1
        [string]$warnings[0] | Should -Be 'No function found with ID: 42'
    }

    It 'does not mistake untyped text mentioning 404 for a missing function' {
        Mock Invoke-RestMethod { throw 'Synthetic failure mentioning 404' } -ModuleName XDRInternals
        { Get-XdrAdvancedHuntingFunction -Id 42 -WarningAction SilentlyContinue -ErrorAction Stop } | Should -Throw '*Synthetic failure mentioning 404*'
    }

    It 'preserves successful empty saved-function reads in the cache' {
        Mock Invoke-RestMethod { @() } -ModuleName XDRInternals
        @(Get-XdrAdvancedHuntingFunction -Force -WarningAction SilentlyContinue) | Should -HaveCount 0
        Should -Invoke Set-XdrCache -Times 1 -Exactly -ModuleName XDRInternals -ParameterFilter { @($Value).Count -eq 0 }
    }

    It 'uses the hunting proxy for unified detection rules' {
        Mock Invoke-RestMethod { @([pscustomobject]@{ Id = 42 }) } -ModuleName XDRInternals -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq 'https://security.microsoft.com/apiproxy/hunting/huntingService/rules/unified?pageIndex=1&pageSize=10000&sortOrder=Ascending&isUnifiedRulesListEnabled=true'
        }
        @(Get-XdrAdvancedHuntingUnifiedDetectionRules -Force) | Should -HaveCount 1
    }

    It 'uses the hunting proxy for query encoding' {
        Mock Invoke-RestMethod { 'encoded' } -ModuleName XDRInternals -ParameterFilter {
            $Method -eq 'Post' -and $Uri -eq 'https://security.microsoft.com/apiproxy/hunting/huntingService/queries/encode' -and ($Body | ConvertFrom-Json).QueryText -eq 'DeviceEvents | where false'
        }
        ConvertTo-XdrEncodedAdvancedHuntingQuery -QueryText 'DeviceEvents | where false' -ErrorAction Stop | Should -Be 'encoded'
    }

    It 'uses the hunting proxy for query validation without creating a rule' {
        Mock Invoke-RestMethod { [pscustomobject]@{ IsAllowed = $true } } -ModuleName XDRInternals -ParameterFilter {
            $Method -eq 'Post' -and $Uri -eq 'https://security.microsoft.com/apiproxy/hunting/huntingService/rules/validateQuery' -and ($Body | ConvertFrom-Json).QueryText -eq 'DeviceEvents | where false' -and $null -eq ($Body | ConvertFrom-Json).HuntingRule
        }
        (Invoke-XdrHuntingQueryValidation -QueryText 'DeviceEvents | where false').IsAllowed | Should -BeTrue
    }
}
