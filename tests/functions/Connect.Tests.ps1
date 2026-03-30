Describe 'Connect-XdrByTemporaryAccessPass' {
    BeforeAll {
        function New-TestSecureString {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Uses fixed placeholder values in unit tests only.')]
            param(
                [Parameter(Mandatory)]
                [string]$Value
            )

            return (ConvertTo-SecureString $Value -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock Write-Host {} -ModuleName XDRInternals
        Mock Resolve-XdrTenantIdFromUsername { 'resolved-tenant-id' } -ModuleName XDRInternals
        Mock Invoke-XdrTemporaryAccessPassAuthentication { 'ests-cookie-value' } -ModuleName XDRInternals
        Mock Connect-XdrByEstsCookie { 'connected' } -ModuleName XDRInternals
    }

    It 'uses the TAP helper and connects with the returned ESTS cookie' {
        $tap = New-TestSecureString -Value 'abc12345'

        $result = Connect-XdrByTemporaryAccessPass -Username 'user@contoso.com' -TemporaryAccessPass $tap -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2'

        $result | Should -Be 'connected'
        Should -Invoke Invoke-XdrTemporaryAccessPassAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Username -eq 'user@contoso.com' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
        }
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $EstsAuthCookieValue -eq 'ests-cookie-value' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
        }
    }

    It 'throws when TAP authentication returns no cookie' {
        Mock Invoke-XdrTemporaryAccessPassAuthentication { $null } -ModuleName XDRInternals
        $tap = New-TestSecureString -Value 'abc12345'

        {
            Connect-XdrByTemporaryAccessPass -Username 'user@contoso.com' -TemporaryAccessPass $tap -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2'
        } | Should -Throw '*no ESTS cookie*'
    }

    It 'resolves the tenant ID from the username when TenantId is omitted' {
        $tap = New-TestSecureString -Value 'abc12345'

        $result = Connect-XdrByTemporaryAccessPass -Username 'user@contoso.com' -TemporaryAccessPass $tap

        $result | Should -Be 'connected'
        Should -Invoke Resolve-XdrTenantIdFromUsername -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Username -eq 'user@contoso.com'
        }
        Should -Invoke Invoke-XdrTemporaryAccessPassAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Username -eq 'user@contoso.com' -and
            $TenantId -eq 'resolved-tenant-id'
        }
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $EstsAuthCookieValue -eq 'ests-cookie-value' -and
            $TenantId -eq 'resolved-tenant-id'
        }
    }
}

Describe 'Connect-XdrByPhoneSignIn' {
    BeforeEach {
        Mock Read-Host { 'user@contoso.com' } -ModuleName XDRInternals
        Mock Invoke-XdrPhoneSignInAuthentication { 'ests-cookie-value' } -ModuleName XDRInternals
        Mock Connect-XdrByEstsCookie { 'connected' } -ModuleName XDRInternals
    }

    It 'uses the phone sign-in helper and connects with the returned ESTS cookie' {
        $result = Connect-XdrByPhoneSignIn -Username 'user@contoso.com' -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2' -TimeoutSeconds 120

        $result | Should -Be 'connected'
        Should -Invoke Invoke-XdrPhoneSignInAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Username -eq 'user@contoso.com' -and
            $TimeoutSeconds -eq 120
        }
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $EstsAuthCookieValue -eq 'ests-cookie-value' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
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
        Mock Set-XdrConnectionSettings { 'connected-via-sccauth' } -ModuleName XDRInternals
    }

    It 'uses the browser helper and connects with the returned ESTS cookie' {
        $result = Connect-XdrByBrowser -Username 'user@contoso.com' -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2' -TimeoutSeconds 120

        $result | Should -Be 'connected'
        Should -Invoke Invoke-XdrBrowserAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Username -eq 'user@contoso.com' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2' -and
            $TimeoutSeconds -eq 120
        }
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $EstsAuthCookieValue -eq 'ests-cookie-value' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
        }
    }

    It 'forwards optional browser launch parameters when provided' {
        $result = Connect-XdrByBrowser -Username 'user@contoso.com' -BrowserPath 'msedge.exe' -ProfilePath 'C:\Temp\XdrBrowserProfile' -ResetProfile -UserAgent 'Custom-Agent/1.0'

        $result | Should -Be 'connected'
        Should -Invoke Invoke-XdrBrowserAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Username -eq 'user@contoso.com' -and
            $BrowserPath -eq 'msedge.exe' -and
            $ProfilePath -eq 'C:\Temp\XdrBrowserProfile' -and
            $ResetProfile -and
            $UserAgent -eq 'Custom-Agent/1.0'
        }
    }

    It 'forwards private session mode when requested' {
        $result = Connect-XdrByBrowser -Username 'user@contoso.com' -PrivateSession

        $result | Should -Be 'connected'
        Should -Invoke Invoke-XdrBrowserAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Username -eq 'user@contoso.com' -and
            $PrivateSession
        }
    }

    It 'allows account selection when Username is omitted' {
        $result = Connect-XdrByBrowser

        $result | Should -Be 'connected'
        Should -Invoke Invoke-XdrBrowserAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            -not $PSBoundParameters.ContainsKey('Username')
        }
        Should -Invoke Read-Host -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'rejects combining explicit profile and private session mode' {
        {
            Connect-XdrByBrowser -Username 'user@contoso.com' -ProfilePath 'C:\Temp\XdrBrowserProfile' -PrivateSession
        } | Should -Throw '*Do not combine -PrivateSession with -ProfilePath*'
    }

    It 'prefers ESTS cookie bootstrap when browser auth returns both ESTS and portal cookies' {
        Mock Invoke-XdrBrowserAuthentication {
            [pscustomobject]@{
                SccAuthCookieValue  = 'sccauth-cookie-value'
                XsrfToken           = 'xsrf-cookie-value'
                EstsAuthCookieValue = 'ests-cookie-value'
            }
        } -ModuleName XDRInternals

        $result = Connect-XdrByBrowser -Username 'user@contoso.com' -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2'

        $result | Should -Be 'connected'
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $EstsAuthCookieValue -eq 'ests-cookie-value' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
        }
        Should -Invoke Set-XdrConnectionSettings -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'falls back to Defender portal cookies when ESTS bootstrap is insufficient for SSO' {
        Mock Invoke-XdrBrowserAuthentication {
            [pscustomobject]@{
                SccAuthCookieValue  = 'sccauth-cookie-value'
                XsrfToken           = 'xsrf-cookie-value'
                EstsAuthCookieValue = 'ests-cookie-value'
            }
        } -ModuleName XDRInternals
        Mock Connect-XdrByEstsCookie { throw 'Session information is not sufficient for single-sign-on. Please use a incognito/private browsing session to obtain a new ESTSAUTH cookie value.' } -ModuleName XDRInternals

        $result = Connect-XdrByBrowser -Username 'user@contoso.com' -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2' -Verbose

        $result | Should -Be 'connected-via-sccauth'
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $EstsAuthCookieValue -eq 'ests-cookie-value' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
        }
        Should -Invoke Set-XdrConnectionSettings -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $SccAuth -eq 'sccauth-cookie-value' -and
            $Xsrf -eq 'xsrf-cookie-value' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
        }
    }

    It 'falls back to Defender portal cookies when browser auth returns no ESTS cookie' {
        Mock Invoke-XdrBrowserAuthentication {
            [pscustomobject]@{
                SccAuthCookieValue  = 'sccauth-cookie-value'
                XsrfToken           = 'xsrf-cookie-value'
                EstsAuthCookieValue = $null
            }
        } -ModuleName XDRInternals

        $result = Connect-XdrByBrowser -Username 'user@contoso.com' -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2'

        $result | Should -Be 'connected-via-sccauth'
        Should -Invoke Set-XdrConnectionSettings -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $SccAuth -eq 'sccauth-cookie-value' -and
            $Xsrf -eq 'xsrf-cookie-value' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
        }
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'throws when browser sign-in returns no cookie' {
        Mock Invoke-XdrBrowserAuthentication { $null } -ModuleName XDRInternals

        {
            Connect-XdrByBrowser -Username 'user@contoso.com'
        } | Should -Throw '*no authentication cookies*'
    }
}

Describe 'Connect-XdrBySSO' {
    BeforeEach {
        Mock Invoke-XdrSsoAuthentication {
            [pscustomobject]@{
                SccAuthCookieValue  = 'sccauth-cookie-value'
                XsrfToken           = 'xsrf-cookie-value'
                EstsAuthCookieValue = 'ests-cookie-value'
                SelectedTenantId    = '8612f621-73ca-4c12-973c-0da732bc44c2'
            }
        } -ModuleName XDRInternals
        Mock Set-XdrConnectionSettings { 'connected-via-sso' } -ModuleName XDRInternals
        Mock Connect-XdrByEstsCookie { 'connected-via-ests' } -ModuleName XDRInternals
    }

    It 'uses SSO helper and configures connection settings with portal cookies' {
        $result = Connect-XdrBySSO -TimeoutSeconds 120

        $result | Should -Be 'connected-via-sso'
        Should -Invoke Invoke-XdrSsoAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $TimeoutSeconds -eq 120
        }
        Should -Invoke Set-XdrConnectionSettings -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $SccAuth -eq 'sccauth-cookie-value' -and
            $Xsrf -eq 'xsrf-cookie-value' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
        }
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'falls back to ESTS cookie bootstrap when portal cookies are unavailable' {
        Mock Invoke-XdrSsoAuthentication {
            [pscustomobject]@{
                SccAuthCookieValue  = $null
                XsrfToken           = $null
                EstsAuthCookieValue = 'ests-cookie-value'
                SelectedTenantId    = '8612f621-73ca-4c12-973c-0da732bc44c2'
            }
        } -ModuleName XDRInternals

        $result = Connect-XdrBySSO

        $result | Should -Be 'connected-via-ests'
        Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $EstsAuthCookieValue -eq 'ests-cookie-value' -and
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
        }
        Should -Invoke Set-XdrConnectionSettings -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'forwards visible and browser options when provided' {
        $result = Connect-XdrBySSO -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2' -Visible -SkipTenantSelection -BrowserPath 'msedge.exe' -ProfilePath 'C:\Temp\XdrSsoProfile' -UserAgent 'Custom-Agent/1.0'

        $result | Should -Be 'connected-via-sso'
        Should -Invoke Invoke-XdrSsoAuthentication -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2' -and
            $Visible -and
            $SkipTenantSelection -and
            $BrowserPath -eq 'msedge.exe' -and
            $ProfilePath -eq 'C:\Temp\XdrSsoProfile' -and
            $UserAgent -eq 'Custom-Agent/1.0'
        }
    }

    It 'rejects non-GUID TenantId values before starting SSO' {
        {
            Connect-XdrBySSO -TenantId 'Contoso'
        } | Should -Throw

        Should -Invoke Invoke-XdrSsoAuthentication -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'throws when SSO authentication returns no cookies' {
        Mock Invoke-XdrSsoAuthentication { $null } -ModuleName XDRInternals

        {
            Connect-XdrBySSO
        } | Should -Throw '*no authentication cookies*'
    }
}

InModuleScope XDRInternals {
    Describe 'Internal auth helper functions' {
        BeforeEach {
            Mock Connect-XdrByEstsCookie { 'connected-via-ests' } -ModuleName XDRInternals
            Mock Set-XdrConnectionSettings { 'connected-via-sccauth' } -ModuleName XDRInternals
        }

        It 'returns the module default user agent' {
            Get-XdrDefaultUserAgent | Should -Be 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
        }

        It 'selects host-only ESTS cookies captured from the browser' {
            $cookie = Get-XdrBestBrowserEstsCookie -Cookies @(
                [pscustomobject]@{
                    name   = 'ESTSAUTH'
                    value  = 'host-only-cookie'
                    domain = 'login.microsoftonline.com'
                }
            )

            $cookie.value | Should -Be 'host-only-cookie'
        }

        It 'includes user application installs in the macOS browser candidate set' {
            $candidates = @(Get-XdrMacOSBrowserCandidateSet)
            $userApplicationRoot = Join-Path $HOME 'Applications'

            $candidates.FilePath | Should -Contain (Join-Path $userApplicationRoot 'Microsoft Edge.app/Contents/MacOS/Microsoft Edge')
            $candidates.FilePath | Should -Contain (Join-Path $userApplicationRoot 'Google Chrome.app/Contents/MacOS/Google Chrome')
            $candidates.FilePath | Should -Contain (Join-Path $userApplicationRoot 'Brave Browser.app/Contents/MacOS/Brave Browser')
            $candidates.FilePath | Should -Contain (Join-Path $userApplicationRoot 'Chromium.app/Contents/MacOS/Chromium')
        }

        It 'falls back to Google Chrome on macOS when Edge is unavailable' {
            $browserRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('xdrinternals-browser-candidates-' + [guid]::NewGuid().ToString('N'))
            $chromePath = Join-Path $browserRoot 'Google Chrome.app/Contents/MacOS/Google Chrome'

            try {
                $null = New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($chromePath)) -Force
                $null = New-Item -ItemType File -Path $chromePath -Force

                Mock Get-XdrMacOSBrowserCandidateSet {
                    @(
                        [pscustomobject]@{ Name = 'Microsoft Edge'; FilePath = '/path/that/does/not/exist/Microsoft Edge' }
                        [pscustomobject]@{ Name = 'Google Chrome'; FilePath = $chromePath }
                    )
                } -ModuleName XDRInternals

                $result = Resolve-XdrMacOSBrowserPath

                $result.Name | Should -Be 'Google Chrome'
                $result.Path | Should -Be $chromePath
            } finally {
                Remove-Item -Path $browserRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'resolves a macOS app bundle path to its executable path' {
            $bundleRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('xdrinternals-browser-bundle-' + [guid]::NewGuid().ToString('N'))
            $bundlePath = Join-Path $bundleRoot 'Contoso Browser.app'
            $macOsPath = Join-Path $bundlePath 'Contents/MacOS'
            $executablePath = Join-Path $macOsPath 'Contoso Browser'

            try {
                $null = New-Item -ItemType Directory -Path $macOsPath -Force
                $null = New-Item -ItemType File -Path $executablePath -Force

                $result = Resolve-XdrMacOSAppBundleExecutablePath -BundlePath $bundlePath

                $result.Name | Should -Be 'Contoso Browser'
                $result.Path | Should -Be $executablePath
            } finally {
                Remove-Item -Path $bundleRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'quotes process arguments whose values contain spaces' {
            $arguments = Format-XdrProcessArgumentList -ArgumentList @(
                '--remote-debugging-port=9222'
                '--user-data-dir=/Users/test/Library/Application Support/XdrInternals/BrowserProfile'
                '--user-agent=Mozilla/5.0 Test Agent'
                'https://security.microsoft.com/'
            )

            $arguments | Should -Contain '--remote-debugging-port=9222'
            $arguments | Should -Contain '--user-data-dir="/Users/test/Library/Application Support/XdrInternals/BrowserProfile"'
            $arguments | Should -Contain '--user-agent="Mozilla/5.0 Test Agent"'
            $arguments | Should -Contain 'https://security.microsoft.com/'
        }

        It 'suppresses interactive browser stdout and stderr on non-Windows platforms by default' {
            if ($IsWindows) {
                Set-ItResult -Skipped -Because 'Non-Windows launch behavior is not applicable on Windows.'
                return
            }

            Mock Start-Process {
                [pscustomobject]@{
                    Id        = 1234
                    HasExited = $false
                }
            } -ModuleName XDRInternals

            $result = Start-XdrBrowserProcess -BrowserPath '/usr/bin/microsoft-edge-stable' -ArgumentList @('https://security.microsoft.com/') -SuppressBrowserOutput

            Should -Invoke Start-Process -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $FilePath -eq '/usr/bin/microsoft-edge-stable' -and
                -not [string]::IsNullOrWhiteSpace($RedirectStandardOutput) -and
                -not [string]::IsNullOrWhiteSpace($RedirectStandardError) -and
                $RedirectStandardOutput -ne $RedirectStandardError
            }

            $result.StandardOutputPath | Should -Not -BeNullOrEmpty
            $result.StandardErrorPath | Should -Not -BeNullOrEmpty
            $result.StandardOutputPath | Should -Not -Be $result.StandardErrorPath
        }

        It 'preserves interactive browser stdout and stderr on non-Windows platforms when suppression is disabled' {
            if ($IsWindows) {
                Set-ItResult -Skipped -Because 'Non-Windows launch behavior is not applicable on Windows.'
                return
            }

            Mock Start-Process {
                [pscustomobject]@{
                    Id        = 1234
                    HasExited = $false
                }
            } -ModuleName XDRInternals

            $null = Start-XdrBrowserProcess -BrowserPath '/usr/bin/microsoft-edge-stable' -ArgumentList @('https://security.microsoft.com/')

            Should -Invoke Start-Process -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $FilePath -eq '/usr/bin/microsoft-edge-stable' -and
                -not $PSBoundParameters.ContainsKey('RedirectStandardOutput') -and
                -not $PSBoundParameters.ContainsKey('RedirectStandardError')
            }
        }

        It 'suppresses interactive browser output by default on non-Windows platforms' {
            if ($IsWindows) {
                Set-ItResult -Skipped -Because 'Non-Windows output suppression is not applicable on Windows.'
                return
            }

            $result = Test-XdrBrowserProcessOutputSuppression

            $result | Should -BeTrue
        }

        It 'disables interactive browser output suppression when verbose logging is enabled' {
            if ($IsWindows) {
                Set-ItResult -Skipped -Because 'Non-Windows output suppression is not applicable on Windows.'
                return
            }

            $result = Test-XdrBrowserProcessOutputSuppression -Verbose

            $result | Should -BeFalse
        }

        It 'waits for portal cookies while the ESTS grace period is still active' {
            $result = Test-XdrBrowserAuthenticationCompletion -EstsCookie ([pscustomobject]@{ value = 'ests-cookie' }) -FirstEstsCookieObservedAt (Get-Date).AddSeconds(-10) -Deadline (Get-Date).AddMinutes(2)

            $result | Should -BeFalse
        }

        It 'falls back to ESTS after the portal-cookie grace period expires' {
            $result = Test-XdrBrowserAuthenticationCompletion -EstsCookie ([pscustomobject]@{ value = 'ests-cookie' }) -FirstEstsCookieObservedAt (Get-Date).AddSeconds(-50) -Deadline (Get-Date).AddMinutes(2)

            $result | Should -BeTrue
        }

        It 'completes immediately when Defender portal cookies are available' {
            $result = Test-XdrBrowserAuthenticationCompletion -SccAuthCookieValue 'sccauth-cookie'

            $result | Should -BeTrue
        }

        It 'prefers Defender portal pages when selecting the browser target context' {
            Mock Get-XdrBrowserTargetList {
                @(
                    [pscustomobject]@{
                        type                 = 'page'
                        title                = 'Microsoft login'
                        url                  = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
                        webSocketDebuggerUrl = 'ws://login-target'
                    }
                    [pscustomobject]@{
                        type                 = 'page'
                        title                = 'Microsoft Defender'
                        url                  = 'https://security.microsoft.com/'
                        webSocketDebuggerUrl = 'ws://defender-target'
                    }
                )
            } -ModuleName XDRInternals

            $result = Get-XdrBrowserPreferredTargetContext -Port 9222 -FallbackWebSocketUrl 'ws://fallback-target'

            $result.Url | Should -Be 'https://security.microsoft.com/'
            $result.WebSocketUrl | Should -Be 'ws://defender-target'
        }

        It 'formats a browser target description from title and URL' {
            $result = Format-XdrBrowserTargetDescription -Title 'Microsoft Defender' -Url 'https://security.microsoft.com/'

            $result | Should -Be 'Microsoft Defender [https://security.microsoft.com/]'
        }

        It 'returns the macOS SSO default profile path' {
            if (-not $IsMacOS) {
                Set-ItResult -Skipped -Because 'macOS-specific path assertion.'
                return
            }

            Get-XdrSsoDefaultProfilePath | Should -Be (Join-Path $HOME 'Library/Application Support/XdrInternals/SsoBrowserProfile')
        }

        It 'launches the SSO browser without Windows-only process options on non-Windows platforms' {
            if ($IsWindows) {
                Set-ItResult -Skipped -Because 'Non-Windows launch behavior is not applicable on Windows.'
                return
            }

            Mock Start-Process {
                [pscustomobject]@{
                    Id        = 1234
                    HasExited = $false
                }
            } -ModuleName XDRInternals

            $null = Start-XdrSsoBrowserProcess -BrowserPath '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' -ArgumentList @('--headless=new', 'https://security.microsoft.com/')

            Should -Invoke Start-Process -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $FilePath -eq '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' -and
                -not $PSBoundParameters.ContainsKey('WindowStyle') -and
                -not $PSBoundParameters.ContainsKey('RedirectStandardError')
            }
        }

        It 'launches the SSO browser hidden on Windows when not visible' {
            if (-not $IsWindows) {
                Set-ItResult -Skipped -Because 'Windows-specific launch behavior is not applicable on this platform.'
                return
            }

            Mock Start-Process {
                [pscustomobject]@{
                    Id        = 1234
                    HasExited = $false
                }
            } -ModuleName XDRInternals

            $null = Start-XdrSsoBrowserProcess -BrowserPath 'msedge.exe' -ArgumentList @('--headless=new', 'https://security.microsoft.com/')

            Should -Invoke Start-Process -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $FilePath -eq 'msedge.exe' -and
                $WindowStyle -eq 'Hidden' -and
                $RedirectStandardError -eq 'NUL'
            }
        }

        It 'resolves a tenant ID from user realm and OpenID discovery metadata' {
            Mock Invoke-RestMethod {
                if ($Uri -like '*userrealm*') {
                    return [pscustomobject]@{
                        DomainName = 'contoso.com'
                    }
                }

                return [pscustomobject]@{
                    issuer = 'https://login.microsoftonline.com/8612f621-73ca-4c12-973c-0da732bc44c2/v2.0'
                }
            } -ModuleName XDRInternals

            $result = Resolve-XdrTenantIdFromUsername -Username 'user@contoso.com' -UserAgent 'Custom-Agent/1.0'

            $result | Should -Be '8612f621-73ca-4c12-973c-0da732bc44c2'
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2 -Exactly
        }

        It 'falls back to the username domain when user realm discovery does not return one' {
            Mock Invoke-RestMethod {
                if ($Uri -like '*userrealm*') {
                    return [pscustomobject]@{
                        DomainName = $null
                    }
                }

                return [pscustomobject]@{
                    authorization_endpoint = 'https://login.microsoftonline.com/8612f621-73ca-4c12-973c-0da732bc44c2/oauth2/v2.0/authorize'
                }
            } -ModuleName XDRInternals

            $result = Resolve-XdrTenantIdFromUsername -Username 'user@contoso.com'

            $result | Should -Be '8612f621-73ca-4c12-973c-0da732bc44c2'
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $Uri -like 'https://login.microsoftonline.com/contoso.com/v2.0/.well-known/openid-configuration'
            }
        }

        It 'prefers ESTS bootstrap when requested' {
            $result = Connect-XdrAuthArtifactSet -EstsAuthCookieValue 'ests-cookie-value' -SccAuthCookieValue 'sccauth-cookie-value' -XsrfToken 'xsrf-cookie-value' -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2' -UserAgent 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0' -ConnectionPreference PreferEsts -FailureLabel 'Browser sign-in'

            $result | Should -Be 'connected-via-ests'
            Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $EstsAuthCookieValue -eq 'ests-cookie-value' -and
                $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2' -and
                $UserAgent -eq 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
            }
            Should -Invoke Set-XdrConnectionSettings -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'prefers portal cookies when requested' {
            $result = Connect-XdrAuthArtifactSet -EstsAuthCookieValue 'ests-cookie-value' -SccAuthCookieValue 'sccauth-cookie-value' -XsrfToken 'xsrf-cookie-value' -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2' -ConnectionPreference PreferPortal -FailureLabel 'SSO authentication'

            $result | Should -Be 'connected-via-sccauth'
            Should -Invoke Set-XdrConnectionSettings -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $SccAuth -eq 'sccauth-cookie-value' -and
                $Xsrf -eq 'xsrf-cookie-value' -and
                $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
            }
            Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 0 -Exactly
        }

        It 'falls back to portal cookies after insufficient ESTS SSO bootstrap when requested' {
            Mock Connect-XdrByEstsCookie { throw 'Session information is not sufficient for single-sign-on. Please use a incognito/private browsing session to obtain a new ESTSAUTH cookie value.' } -ModuleName XDRInternals

            $result = Connect-XdrAuthArtifactSet -EstsAuthCookieValue 'ests-cookie-value' -SccAuthCookieValue 'sccauth-cookie-value' -XsrfToken 'xsrf-cookie-value' -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2' -ConnectionPreference PreferEsts -FallbackToPortalOnEstsBootstrapFailure -FailureLabel 'Browser sign-in' -Verbose

            $result | Should -Be 'connected-via-sccauth'
            Should -Invoke Connect-XdrByEstsCookie -ModuleName XDRInternals -Times 1 -Exactly
            Should -Invoke Set-XdrConnectionSettings -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
                $SccAuth -eq 'sccauth-cookie-value' -and
                $Xsrf -eq 'xsrf-cookie-value' -and
                $TenantId -eq '8612f621-73ca-4c12-973c-0da732bc44c2'
            }
        }

        It 'builds GET polling URIs from absolute endpoint strings' {
            $uri = Add-XdrUriQueryString -Uri 'https://login.microsoftonline.com/common/SAS/EndAuth' -Parameters @('authMethodId=PhoneAppNotification', 'pollCount=1')

            $uri | Should -Be 'https://login.microsoftonline.com/common/SAS/EndAuth?authMethodId=PhoneAppNotification&pollCount=1'
        }

        It 'uses POST polling when GET push polling returns no continuation state' {
            $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $beginAuth = [pscustomobject]@{
                SessionId = 'begin-session'
                FlowToken = 'begin-flow'
                Ctx       = 'begin-ctx'
            }
            $authState = [pscustomobject]@{
                fSasEndAuthPostToGetSwitch = $true
            }

            Mock Start-Sleep {} -ModuleName XDRInternals
            Mock Invoke-RestMethod {
                if ($Method -eq 'Get') {
                    return [pscustomobject]@{
                        ErrCode     = 500121
                        ResultValue = 'AuthenticationPending'
                        Retry       = $true
                    }
                }

                return [pscustomobject]@{
                    Success     = $true
                    ResultValue = 'Success'
                    SessionId   = 'poll-session'
                    FlowToken   = 'poll-flow'
                    Ctx         = 'poll-ctx'
                }
            } -ModuleName XDRInternals

            $result = Invoke-XdrSasPushNotificationPolling -SelectedMethod 'PhoneAppNotification' -BeginAuth $beginAuth -AuthState $authState -Session $session -Headers @{} -EndAuthUri 'https://login.microsoftonline.com/common/SAS/EndAuth' -Deadline (Get-Date).AddSeconds(10)

            $result.BeginAuth.SessionId | Should -Be 'poll-session'
            $result.BeginAuth.FlowToken | Should -Be 'poll-flow'
            $result.ProcessAuthPollStart | Should -Not -BeNullOrEmpty
            $result.ProcessAuthPollEnd | Should -Not -BeNullOrEmpty
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2 -Exactly
        }

        It 'retries ProcessAuth with form fields after a retryable JSON parsing error' {
            $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $beginAuth = [pscustomobject]@{
                FlowToken = 'begin-flow'
                Ctx       = 'begin-ctx'
            }
            $authState = [pscustomobject]@{
                canary        = 'test-canary'
                correlationId = 'test-correlation'
                i19           = 19
                sCtx          = 'auth-ctx'
            }
            $retryableState = [pscustomobject]@{
                iErrorCode                 = 90014
                strServiceExceptionMessage = 'required field request missing'
            }

            Mock Invoke-XdrRedirectCapturingWebRequest {
                [pscustomobject]@{ Step = if ($Body -is [string]) { 'json' } else { 'form' } }
            } -ModuleName XDRInternals
            Mock Get-XdrAuthStateFromResponse {
                if ($Response.Step -eq 'json') {
                    return $retryableState
                }

                return [pscustomobject]@{ pgid = 'ConvergedSignIn' }
            } -ModuleName XDRInternals
            Mock Resolve-XdrAuthenticationResponse {
                [pscustomobject]@{
                    AuthState = [pscustomobject]@{ pgid = 'ConvergedSignIn' }
                    Response  = $Response
                }
            } -ModuleName XDRInternals

            $result = Invoke-XdrSasProcessAuth -SelectedMethod 'OneWaySMS' -Username 'user@contoso.com' -BeginAuth $beginAuth -AuthState $authState -Session $session -Headers @{} -ProcessAuthUri 'https://login.microsoftonline.com/common/SAS/ProcessAuth' -MfaLastPollStart 111 -MfaLastPollEnd 222

            $result.Outcome.AuthState.pgid | Should -Be 'ConvergedSignIn'
            $result.ProcessResponse.Step | Should -Be 'form'
            Should -Invoke Invoke-XdrRedirectCapturingWebRequest -ModuleName XDRInternals -Times 2 -Exactly
        }
    }
}
