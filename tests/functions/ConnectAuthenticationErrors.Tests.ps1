Describe 'Connect authentication error integration' {
    BeforeAll {
        function New-AuthenticationTestSecureString {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Uses fixed placeholder values in unit tests only.')]
            param([string]$Value = 'placeholder-secret')
            ConvertTo-SecureString $Value -AsPlainText -Force
        }
    }

    BeforeEach {
        Mock Write-Host {} -ModuleName XDRInternals
    }

    It 'normalizes a structured credential rejection at the public boundary' {
        Mock Invoke-XdrCredentialAuthentication {
            $nativeException = [System.Exception]::new('HTTP request failed')
            $nativeRecord = [System.Management.Automation.ErrorRecord]::new($nativeException, 'NativeFailure', 'AuthenticationError', $null)
            $nativeRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":{"code":"AADSTS50126"},"correlation_id":"11111111-1111-1111-1111-111111111111","access_token":"secret-token"}')
            throw $nativeRecord
        } -ModuleName XDRInternals

        $credential = [PSCredential]::new('user@contoso.com', (New-AuthenticationTestSecureString))
        $caught = try { Connect-XdrByCredential -Credential $credential } catch { $_ }

        $caught.FullyQualifiedErrorId | Should -BeLike 'XdrAuthentication.InvalidCredentials*'
        $metadata = $caught.Exception.Data['XdrAuthenticationFailure']
        $metadata.AuthenticationMethod | Should -Be 'Credential'
        $metadata.Stage | Should -Be 'SignIn'
        $metadata.CorrelationId | Should -Be '11111111-1111-1111-1111-111111111111'
        (($caught.ErrorDetails.Message, $caught.ErrorDetails.RecommendedAction, ($metadata | ConvertTo-Json -Depth 8)) -join "`n") | Should -Not -Match 'secret-token'
    }

    It 'classifies an invalid software passkey credential file without exposing its path' {
        Mock Invoke-XdrPasskeyAuthentication { throw 'Credential file not found: /private/credentials/admin-passkey.json' } -ModuleName XDRInternals

        $caught = try { Connect-XdrBySoftwarePasskey -KeyFilePath '/private/credentials/admin-passkey.json' } catch { $_ }

        $caught.FullyQualifiedErrorId | Should -BeLike 'XdrAuthentication.CredentialFileInvalid*'
        $caught.ErrorDetails.Message | Should -Not -Match 'admin-passkey|/private/'
        $caught.Exception.Data['XdrAuthenticationFailure'].AuthenticationMethod | Should -Be 'SoftwarePasskey'
    }

    It 'classifies an ESTS session rejection from exact provider state' {
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-WebRequest {
            if ($Uri -eq 'https://login.microsoftonline.com/error') {
                return [pscustomobject]@{}
            }

            return [pscustomobject]@{
                InputFields = @()
                Content = '<script>$Config={"sErrorCode":"50058","sErrTxt":"unsafe provider text","sFT":"secret-flow-token","sCtx":"secret-context"};</script>'
                StatusCode = 200
            }
        } -ModuleName XDRInternals

        $caught = try { Connect-XdrByEstsCookie -EstsAuthCookieValue 'secret-cookie-value' -Verbose 4>&1 } catch { $_ }

        $caught.FullyQualifiedErrorId | Should -BeLike 'XdrAuthentication.SessionUnavailable*'
        $exposed = @(
            $caught.ErrorDetails.Message
            $caught.ErrorDetails.RecommendedAction
            ($caught.Exception.Data['XdrAuthenticationFailure'] | ConvertTo-Json -Depth 8)
        ) -join "`n"
        $exposed | Should -Not -Match 'secret-cookie-value|secret-flow-token|secret-context|unsafe provider text'
    }

    It 'keeps the successful ESTS-cookie bootstrap behavior unchanged' {
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Set-XdrConnectionSettings { 'connected' } -ModuleName XDRInternals
        Mock Invoke-WebRequest {
            if ($Uri -eq 'https://login.microsoftonline.com/error') {
                return [pscustomobject]@{}
            }

            if ($Method -eq 'Get') {
                return [pscustomobject]@{
                    InputFields = @(
                        [pscustomobject]@{ name = 'code'; value = 'authorization-code' }
                        [pscustomobject]@{ name = 'id_token'; value = 'identity-token' }
                        [pscustomobject]@{ name = 'state'; value = 'state-value' }
                        [pscustomobject]@{ name = 'session_state'; value = 'session-state' }
                        [pscustomobject]@{ name = 'correlation_id'; value = '11111111-1111-1111-1111-111111111111' }
                    )
                    Content = ''
                    StatusCode = 200
                }
            }

            return [pscustomobject]@{ StatusCode = 200 }
        } -ModuleName XDRInternals

        $output = @(Connect-XdrByEstsCookie -EstsAuthCookieValue 'secret-cookie-value' -Verbose 4>&1)

        $output[-1] | Should -Be 'connected'
        ($output | Out-String) | Should -Not -Match 'secret-cookie-value|authorization-code|identity-token|state-value|session-state'
        Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'Post' -and $Body.code -eq 'authorization-code'
        }
        Should -Invoke Set-XdrConnectionSettings -ModuleName XDRInternals -Times 1 -Exactly
    }

    It 'does not wrap an already-structured TAP error again' {
        Mock Invoke-XdrTemporaryAccessPassAuthentication {
            $exception = [System.Security.Authentication.AuthenticationException]::new('The username or password was not accepted.')
            $exception.Data['XdrAuthenticationFailure'] = [pscustomobject]@{
                Code = 'InvalidCredentials'; AuthenticationMethod = 'TemporaryAccessPass'; Stage = 'PassSubmission'
            }
            $record = [System.Management.Automation.ErrorRecord]::new($exception, 'XdrAuthentication.InvalidCredentials', 'AuthenticationError', $null)
            $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('The username or password was not accepted.')
            throw $record
        } -ModuleName XDRInternals
        Mock Connect-XdrByEstsCookie { 'connected' } -ModuleName XDRInternals

        $caught = try {
            Connect-XdrByTemporaryAccessPass -Username 'user@contoso.com' -TemporaryAccessPass (New-AuthenticationTestSecureString) -TenantId 'tenant-id'
        } catch { $_ }

        $caught.FullyQualifiedErrorId | Should -BeLike 'XdrAuthentication.InvalidCredentials*'
        $caught.Exception.InnerException | Should -BeNullOrEmpty
        $caught.Exception.Data['XdrAuthenticationFailure'].Stage | Should -Be 'PassSubmission'
    }

    It 'passes through structured Phone, Browser, and SSO failures' -ForEach @(
        @{ Command = 'Connect-XdrByPhoneSignIn'; Helper = 'Invoke-XdrPhoneSignInAuthentication'; Arguments = @{ Username = 'user@contoso.com' } }
        @{ Command = 'Connect-XdrByBrowser'; Helper = 'Invoke-XdrBrowserAuthentication'; Arguments = @{} }
        @{ Command = 'Connect-XdrBySSO'; Helper = 'Invoke-XdrSsoAuthentication'; Arguments = @{} }
    ) {
        Mock $Helper {
            $exception = [System.Security.Authentication.AuthenticationException]::new('Browser authentication did not complete before the timeout.')
            $exception.Data['XdrAuthenticationFailure'] = [pscustomobject]@{
                Code = 'BrowserTimeout'; AuthenticationMethod = 'StructuredMock'; Stage = 'BrowserSignIn'
            }
            $record = [System.Management.Automation.ErrorRecord]::new($exception, 'XdrAuthentication.BrowserTimeout', 'OperationTimeout', $null)
            $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('Browser authentication did not complete before the timeout.')
            throw $record
        } -ModuleName XDRInternals

        $caught = try { & $Command @Arguments } catch { $_ }

        $caught.FullyQualifiedErrorId | Should -BeLike 'XdrAuthentication.BrowserTimeout*'
        $caught.Exception.Data['XdrAuthenticationFailure'].AuthenticationMethod | Should -Be 'StructuredMock'
        $caught.Exception.InnerException | Should -BeNullOrEmpty
    }
}

Describe 'Authentication artifact fallback diagnostics' {
    InModuleScope XDRInternals {
        BeforeEach {
            Mock Connect-XdrByEstsCookie { throw 'ESTS native failure with cookie=secret-cookie' }
            Mock Set-XdrConnectionSettings { throw 'Portal native failure with token=secret-token' }
        }

        It 'retains safe classifications for both failed bootstrap attempts' {
            $caught = try {
                Connect-XdrAuthArtifactSet -EstsAuthCookieValue 'secret-cookie' -SccAuthCookieValue 'secret-portal-cookie' -XsrfToken 'secret-xsrf' -ConnectionPreference PreferEsts -FallbackToPortalOnEstsBootstrapFailure -FailureLabel 'Browser'
            } catch { $_ }

            $caught.FullyQualifiedErrorId | Should -BeLike 'XdrAuthentication.BootstrapFailed*'
            $metadata = $caught.Exception.Data['XdrAuthenticationFailure']
            ($metadata.SafeEvidence | Where-Object Name -EQ Attempt).Value | Should -Be 'ESTS:BootstrapFailed; Portal:BootstrapFailed'
            (($caught.ErrorDetails.Message, $caught.ErrorDetails.RecommendedAction, ($metadata | ConvertTo-Json -Depth 8)) -join "`n") | Should -Not -Match 'secret-cookie|secret-token|secret-xsrf|secret-portal-cookie'
        }
    }
}

Describe 'Browser authentication failure boundaries' {
    InModuleScope XDRInternals {
        BeforeEach {
            Mock Write-Host {}
            Mock Resolve-XdrBrowserPath { [pscustomobject]@{ Name = 'Test Browser'; Path = '/test/browser' } }
            Mock Get-XdrBrowserFreeTcpPort { 9222 }
            Mock Resolve-XdrBrowserProfileConfiguration {
                [pscustomobject]@{ ProfilePath = '/test/profile'; UsePrivateSession = $false; CleanupProfileOnExit = $false }
            }
            Mock Get-XdrBrowserInteractiveStartUrl { 'https://login.microsoftonline.com/' }
            Mock Get-XdrBrowserLaunchArgumentList { @('--test') }
            Mock Test-XdrBrowserProcessOutputSuppression { $true }
            Mock Get-XdrBrowserCdpVersion { [pscustomobject]@{ webSocketDebuggerUrl = 'ws://localhost/test' } }
            Mock Start-Sleep {}
            Mock Stop-XdrBrowserProcess {}
            Mock Remove-XdrBrowserProcessRedirectFiles {}
        }

        It 'returns BrowserClosed when the launched browser exits' {
            Mock Start-XdrBrowserProcess {
                $process = [pscustomobject]@{ HasExited = $true }
                $process | Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
                return $process
            }

            $caught = try { Invoke-XdrBrowserAuthentication -TimeoutSeconds 30 } catch { $_ }

            $caught.FullyQualifiedErrorId | Should -BeLike 'XdrAuthentication.BrowserClosed*'
            $caught.Exception.Data['XdrAuthenticationFailure'].Retryable | Should -BeTrue
        }

        It 'returns BrowserTimeout with allowlisted page evidence when cookies never appear' {
            Mock Start-XdrBrowserProcess {
                $process = [pscustomobject]@{ HasExited = $false }
                $process | Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
                return $process
            }
            Mock Get-Date {
                if (-not $script:browserDateCall) { $script:browserDateCall = 0 }
                $script:browserDateCall++
                if ($script:browserDateCall -eq 1) { return [datetime]'2026-01-01T00:00:00Z' }
                return [datetime]'2026-01-01T00:01:00Z'
            }
            Mock Get-XdrBrowserPreferredTargetContext {
                [pscustomobject]@{
                    Url = 'https://login.microsoftonline.com/common/oauth2/authorize?code=secret-code'
                    Title = 'Sign in to your account'
                    WebSocketUrl = 'ws://localhost/page'
                }
            }
            Mock Format-XdrBrowserTargetDescription { 'Sign in to your account [login.microsoftonline.com]' }
            Mock Get-XdrBrowserCookieJar { @() }
            Mock Get-XdrBestBrowserEstsCookie { $null }
            Mock Get-XdrBrowserCookieValue { $null }

            $caught = try { Invoke-XdrBrowserAuthentication -TimeoutSeconds 30 } catch { $_ }

            $caught.FullyQualifiedErrorId | Should -BeLike 'XdrAuthentication.BrowserTimeout*'
            $metadata = $caught.Exception.Data['XdrAuthenticationFailure']
            ($metadata.SafeEvidence | Where-Object Name -EQ Host).Value | Should -Be 'login.microsoftonline.com'
            ($metadata.SafeEvidence | Where-Object Name -EQ PageTitle).Value | Should -Be 'Sign in to your account'
            ($metadata | ConvertTo-Json -Depth 8) | Should -Not -Match 'secret-code|oauth2/authorize'
        }
    }
}
