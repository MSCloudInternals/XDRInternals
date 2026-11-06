Describe 'Explicit connection cache isolation' -Tag 'Functions', 'Cache' {
    BeforeEach {
        InModuleScope XDRInternals { $script:XdrCacheStore = @{} }
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Invoke-WebRequest { throw 'Unexpected live transport' } -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            param($WebSession)
            [pscustomobject]@{ Marker = $WebSession.Cookies.GetCookies('https://security.microsoft.com')['sccauth'].Value }
        } -ModuleName XDRInternals
    }

    It 'retrieves fresh settings after explicit same-tenant account replacement' {
        Set-XdrConnectionSettings -SccAuth 'synthetic-A' -Xsrf 'synthetic-xsrf' -TenantId 'synthetic-tenant' 6>$null
        (Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type IP).Marker | Should -Be 'synthetic-A'
        Set-XdrConnectionSettings -SccAuth 'synthetic-B' -Xsrf 'synthetic-xsrf' -TenantId 'synthetic-tenant' 6>$null
        (Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type IP).Marker | Should -Be 'synthetic-B'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2 -Exactly
    }

    It 'retrieves fresh settings after explicit WebSession replacement' {
        Set-XdrConnectionSettings -SccAuth 'synthetic-A' -Xsrf 'synthetic-xsrf' -TenantId 'synthetic-tenant' 6>$null
        (Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type IP).Marker | Should -Be 'synthetic-A'
        $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
        $session.Cookies.Add([System.Net.Cookie]::new('sccauth', 'synthetic-B', '/', 'security.microsoft.com'))
        $session.Cookies.Add([System.Net.Cookie]::new('xsrf-token', 'synthetic-xsrf', '/', 'security.microsoft.com'))
        Set-XdrConnectionSettings -WebSession $session -TenantId 'synthetic-tenant' 6>$null
        (Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type IP).Marker | Should -Be 'synthetic-B'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2 -Exactly
    }

    It 'preserves cached settings and selected tenant when resetting the same session' {
        Set-XdrConnectionSettings -SccAuth 'synthetic-A' -Xsrf 'synthetic-xsrf' -TenantId 'synthetic-tenant' 6>$null
        (Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type IP).Marker | Should -Be 'synthetic-A'
        Set-XdrConnectionSettings -ResetWebSession
        (Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type IP).Marker | Should -Be 'synthetic-A'
        InModuleScope XDRInternals {
            $script:headers['x-tid'] | Should -Be 'synthetic-tenant'
            $script:headers['tenant-id'] | Should -Be 'synthetic-tenant'
            (Get-XdrCache -CacheKey XdrTenantId).Value | Should -Be 'synthetic-tenant'
        }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly
    }
}
