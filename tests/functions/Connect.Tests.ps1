Describe 'Connect-XdrByTemporaryAccessPass' {
    BeforeEach {
        Mock Write-Host {} -ModuleName XDRInternals
        Mock Invoke-XdrTemporaryAccessPassAuthentication { 'ests-cookie-value' } -ModuleName XDRInternals
        Mock Connect-XdrByEstsCookie { 'connected' } -ModuleName XDRInternals
    }

    It 'uses the TAP helper and connects with the returned ESTS cookie' {
        $tap = ConvertTo-SecureString 'abc12345' -AsPlainText -Force

        $result = Connect-XdrByTemporaryAccessPass -Username 'user@contoso.com' -TemporaryAccessPass $tap -TenantId '847b5907-ca15-40f4-b171-eb18619dbfab'

        $result | Should -Be 'connected'
        Should -Invoke Invoke-XdrTemporaryAccessPassAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Username -eq 'user@contoso.com' -and
            $TenantId -eq '847b5907-ca15-40f4-b171-eb18619dbfab'
        }
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $EstsAuthCookieValue -eq 'ests-cookie-value' -and
            $TenantId -eq '847b5907-ca15-40f4-b171-eb18619dbfab'
        }
    }

    It 'throws when TAP authentication returns no cookie' {
        Mock Invoke-XdrTemporaryAccessPassAuthentication { $null } -ModuleName XDRInternals
        $tap = ConvertTo-SecureString 'abc12345' -AsPlainText -Force

        {
            Connect-XdrByTemporaryAccessPass -Username 'user@contoso.com' -TemporaryAccessPass $tap -TenantId '847b5907-ca15-40f4-b171-eb18619dbfab'
        } | Should -Throw '*no ESTS cookie*'
    }
}

Describe 'Connect-XdrByPhoneSignIn' {
    BeforeEach {
        Mock Read-Host { 'user@contoso.com' } -ModuleName XDRInternals
        Mock Invoke-XdrPhoneSignInAuthentication { 'ests-cookie-value' } -ModuleName XDRInternals
        Mock Connect-XdrByEstsCookie { 'connected' } -ModuleName XDRInternals
    }

    It 'uses the phone sign-in helper and connects with the returned ESTS cookie' {
        $result = Connect-XdrByPhoneSignIn -Username 'user@contoso.com' -TenantId '847b5907-ca15-40f4-b171-eb18619dbfab' -TimeoutSeconds 120

        $result | Should -Be 'connected'
        Should -Invoke Invoke-XdrPhoneSignInAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Username -eq 'user@contoso.com' -and
            $TimeoutSeconds -eq 120
        }
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $EstsAuthCookieValue -eq 'ests-cookie-value' -and
            $TenantId -eq '847b5907-ca15-40f4-b171-eb18619dbfab'
        }
    }

    It 'throws when phone sign-in returns no cookie' {
        Mock Invoke-XdrPhoneSignInAuthentication { $null } -ModuleName XDRInternals

        {
            Connect-XdrByPhoneSignIn -Username 'user@contoso.com'
        } | Should -Throw '*no ESTS cookie*'
    }
}

Describe 'Connect-XdrByBrowser' {
    BeforeEach {
        Mock Read-Host { 'user@contoso.com' } -ModuleName XDRInternals
        Mock Invoke-XdrBrowserAuthentication { 'ests-cookie-value' } -ModuleName XDRInternals
        Mock Connect-XdrByEstsCookie { 'connected' } -ModuleName XDRInternals
    }

    It 'uses the browser helper and connects with the returned ESTS cookie' {
        $result = Connect-XdrByBrowser -Username 'user@contoso.com' -TenantId '847b5907-ca15-40f4-b171-eb18619dbfab' -TimeoutSeconds 120

        $result | Should -Be 'connected'
        Should -Invoke Invoke-XdrBrowserAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Username -eq 'user@contoso.com' -and
            $TimeoutSeconds -eq 120
        }
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $EstsAuthCookieValue -eq 'ests-cookie-value' -and
            $TenantId -eq '847b5907-ca15-40f4-b171-eb18619dbfab'
        }
    }

    It 'throws when browser sign-in returns no cookie' {
        Mock Invoke-XdrBrowserAuthentication { $null } -ModuleName XDRInternals

        {
            Connect-XdrByBrowser -Username 'user@contoso.com'
        } | Should -Throw '*no ESTS cookie*'
    }
}