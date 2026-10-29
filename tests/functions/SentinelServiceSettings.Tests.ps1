Describe 'Sentinel service settings' -Tag 'Functions', 'Sentinel' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{ kind = $Setting; properties = [pscustomobject]@{ isEnabled = $true } }
        } -ModuleName XDRInternals
    }

    It 'exports the workspace setting cmdlet' {
        (Get-Command Get-XdrSentinelConfigurationSetting).CommandType | Should -Be 'Function'
    }

    It 'uses the captured API version and route for <Setting>' -ForEach @(
        @{ Setting = 'Anomalies'; Path = 'providers/Microsoft.SecurityInsights/settings/Anomalies'; Version = '2019-01-01-preview' }
        @{ Setting = 'EntityAnalytics'; Path = 'providers/Microsoft.SecurityInsights/settings/EntityAnalytics'; Version = '2022-04-01-preview' }
        @{ Setting = 'Ueba'; Path = 'providers/Microsoft.SecurityInsights/settings/Ueba'; Version = '2022-04-01-preview' }
        @{ Setting = 'SecurityInsightsSecurityEventCollectionConfiguration'; Path = 'datasources/SecurityInsightsSecurityEventCollectionConfiguration'; Version = '2015-11-01-preview' }
        @{ Setting = 'SecurityEventCollectionConfiguration'; Path = 'datasources/SecurityEventCollectionConfiguration'; Version = '2015-11-01-preview' }
    ) {
        $result = Get-XdrSentinelConfigurationSetting -SubscriptionId 'sub-id' -ResourceGroupName 'test-rg' -WorkspaceName 'test-ws' -Setting $Setting

        $result.properties.isEnabled | Should -BeTrue
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Uri -eq "https://security.microsoft.com/apiproxy/arm/subscriptions/sub-id/resourceGroups/test-rg/providers/Microsoft.OperationalInsights/workspaces/test-ws/$Path`?api-version=$Version" -and
            $Method -eq 'Get' -and $ContentType -eq 'application/json'
        }
    }

    It 'rejects unobserved setting names before sending a request' {
        { Get-XdrSentinelConfigurationSetting -SubscriptionId 'sub-id' -ResourceGroupName 'test-rg' -WorkspaceName 'test-ws' -Setting 'Unknown' } | Should -Throw
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'rejects whitespace-only <ParameterName> before sending a request' -ForEach @(
        @{ ParameterName = 'SubscriptionId' }
        @{ ParameterName = 'ResourceGroupName' }
        @{ ParameterName = 'WorkspaceName' }
    ) {
        $parameters = @{ SubscriptionId = 'sub-id'; ResourceGroupName = 'test-rg'; WorkspaceName = 'test-ws'; Setting = 'Ueba' }
        $parameters[$ParameterName] = ' '
        { Get-XdrSentinelConfigurationSetting @parameters } | Should -Throw
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'encodes workspace path segments without changing the selected setting' {
        Mock Invoke-RestMethod { $Uri } -ModuleName XDRInternals
        $result = Get-XdrSentinelConfigurationSetting -SubscriptionId 'sub-id' -ResourceGroupName 'rg + team' -WorkspaceName 'test-ws' -Setting Ueba

        ([uri]$result).AbsoluteUri | Should -BeLike '*/resourceGroups/rg%20%2B%20team/providers/Microsoft.OperationalInsights/workspaces/test-ws/providers/Microsoft.SecurityInsights/settings/Ueba?api-version=2022-04-01-preview'
    }

    It 'preserves the HTTP exception for callers using ErrorAction Stop' {
        Mock Invoke-RestMethod {
            throw [System.Net.Http.HttpRequestException]::new('Forbidden', $null, [System.Net.HttpStatusCode]::Forbidden)
        } -ModuleName XDRInternals

        try {
            Get-XdrSentinelConfigurationSetting -SubscriptionId 'sub-id' -ResourceGroupName 'test-rg' -WorkspaceName 'test-ws' -Setting Ueba -ErrorAction Stop
            throw 'Expected an HTTP error'
        } catch {
            $_.Exception.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Forbidden)
        }
    }
}

Describe 'Sentinel connection refresh' -Tag 'Functions', 'Sentinel' {
    It 'retains tenant headers when a session refresh rotates the XSRF cookie' {
        InModuleScope XDRInternals {
            $hadSession = Test-Path variable:script:session
            $hadHeaders = Test-Path variable:script:headers
            $previousSession = $script:session
            $previousHeaders = $script:headers
            try {
                $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
                $script:session.Cookies.Add([System.Net.Cookie]::new('xsrf-token', 'old', '/', 'security.microsoft.com'))
                $script:session.Cookies.Add([System.Net.Cookie]::new('sccauth', 'session', '/', 'security.microsoft.com'))
                $script:headers = @{ 'x-tid' = 'test-tenant'; 'tenant-id' = 'test-tenant'; 'X-XSRF-TOKEN' = 'old' }

                Mock Get-XdrCache { [pscustomobject]@{ Value = 'test-tenant' } } -ParameterFilter { $CacheKey -eq 'XdrTenantId' }
                Mock Get-XdrCache { $null } -ParameterFilter { $CacheKey -eq 'XsrfToken' }
                Mock Invoke-WebRequest {
                    $script:session.Cookies.GetCookies('https://security.microsoft.com')['xsrf-token'].Value = 'new'
                }
                Mock Set-XdrCache {}

                Update-XdrConnectionSettings

                $script:headers['x-tid'] | Should -Be 'test-tenant'
                $script:headers['tenant-id'] | Should -Be 'test-tenant'
                $script:headers['X-XSRF-TOKEN'] | Should -Be 'new'
            } finally {
                if ($hadSession) { $script:session = $previousSession } else { Remove-Variable -Name session -Scope Script -ErrorAction SilentlyContinue }
                if ($hadHeaders) { $script:headers = $previousHeaders } else { Remove-Variable -Name headers -Scope Script -ErrorAction SilentlyContinue }
            }
            (Test-Path variable:script:session) | Should -Be $hadSession
            (Test-Path variable:script:headers) | Should -Be $hadHeaders
        }
    }

    It 'keeps the selected tenant when its cache entry has been cleared' {
        InModuleScope XDRInternals {
            $hadSession = Test-Path variable:script:session
            $hadHeaders = Test-Path variable:script:headers
            $previousSession = $script:session
            $previousHeaders = $script:headers
            try {
                $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
                $script:session.Cookies.Add([System.Net.Cookie]::new('xsrf-token', 'old', '/', 'security.microsoft.com'))
                $script:session.Cookies.Add([System.Net.Cookie]::new('sccauth', 'session', '/', 'security.microsoft.com'))
                $script:headers = @{ 'x-tid' = 'test-tenant'; 'tenant-id' = 'test-tenant'; 'X-XSRF-TOKEN' = 'old' }

                Mock Get-XdrCache { $null }
                Mock Invoke-WebRequest {
                    $script:session.Cookies.GetCookies('https://security.microsoft.com')['xsrf-token'].Value = 'new'
                }
                Mock Set-XdrCache {}

                Update-XdrConnectionSettings

                $script:headers['x-tid'] | Should -Be 'test-tenant'
                $script:headers['tenant-id'] | Should -Be 'test-tenant'
            } finally {
                if ($hadSession) { $script:session = $previousSession } else { Remove-Variable -Name session -Scope Script -ErrorAction SilentlyContinue }
                if ($hadHeaders) { $script:headers = $previousHeaders } else { Remove-Variable -Name headers -Scope Script -ErrorAction SilentlyContinue }
            }
            (Test-Path variable:script:session) | Should -Be $hadSession
            (Test-Path variable:script:headers) | Should -Be $hadHeaders
        }
    }
}
