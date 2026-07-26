InModuleScope XDRInternals {
    Describe 'Defender request context preservation' {
        AfterEach {
            Remove-Variable -Name session -Scope Script -ErrorAction SilentlyContinue
            Remove-Variable -Name headers -Scope Script -ErrorAction SilentlyContinue
        }

        It 'includes the authenticated browser user-agent in worker snapshots' {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:session.UserAgent = 'XDRInternals-Test-Browser/1.0'
            $script:session.Cookies.Add([System.Net.Cookie]::new('sccauth', 'cookie-value', '/', 'security.microsoft.com'))
            $script:headers = @{
                'X-XSRF-TOKEN' = 'xsrf-value'
                'x-tid' = 'tenant-id'
                'tenant-id' = 'tenant-id'
            }

            $snapshot = Get-XdrRequestContextSnapshot

            $snapshot.UserAgent | Should -Be 'XDRInternals-Test-Browser/1.0'
            $snapshot.HeadersData['x-tid'] | Should -Be 'tenant-id'
            $snapshot.HeadersData['tenant-id'] | Should -Be 'tenant-id'
            $snapshot.CookieData.Name | Should -Contain 'sccauth'
        }

        It 'uses the browser-compatible user-agent for a manually constructed portal session' {
            Mock Set-XdrCache {} -ModuleName XDRInternals
            Mock Write-Host {} -ModuleName XDRInternals

            Set-XdrConnectionSettings -SccAuth 'cookie-value' -Xsrf 'xsrf-value' -TenantId 'tenant-id'

            $script:session.UserAgent | Should -Be (Get-XdrDefaultUserAgent)
            $script:headers['X-XSRF-TOKEN'] | Should -Be 'xsrf-value'
            $script:headers['x-tid'] | Should -Be 'tenant-id'
            $script:headers['tenant-id'] | Should -Be 'tenant-id'
        }
    }
}
