Describe 'Authentication error classification' {
    InModuleScope XDRInternals {
        It 'maps documented Entra code <ProviderCode> to <Code>' -ForEach @(
            @{ ProviderCode = '16000'; Code = 'AccountNotFound' }
            @{ ProviderCode = '50034'; Code = 'AccountNotFound' }
            @{ ProviderCode = '50053'; Code = 'SignInBlocked' }
            @{ ProviderCode = '50055'; Code = 'PasswordExpired' }
            @{ ProviderCode = '50056'; Code = 'PasswordMissing' }
            @{ ProviderCode = '50057'; Code = 'AccountDisabled' }
            @{ ProviderCode = '50126'; Code = 'InvalidCredentials' }
            @{ ProviderCode = '50058'; Code = 'SessionUnavailable' }
            @{ ProviderCode = '50072'; Code = 'MfaEnrollmentRequired' }
            @{ ProviderCode = '50079'; Code = 'MfaEnrollmentRequired' }
            @{ ProviderCode = '50074'; Code = 'MfaRequired' }
            @{ ProviderCode = '50076'; Code = 'MfaRequired' }
            @{ ProviderCode = '50078'; Code = 'MfaTimeout' }
            @{ ProviderCode = '50087'; Code = 'MfaTemporarilyUnavailable' }
            @{ ProviderCode = '50088'; Code = 'MfaTemporarilyUnavailable' }
            @{ ProviderCode = '50089'; Code = 'FlowExpired' }
            @{ ProviderCode = '50105'; Code = 'AppAssignmentRequired' }
            @{ ProviderCode = '65001'; Code = 'ConsentRequired' }
            @{ ProviderCode = '90008'; Code = 'ConsentRequired' }
            @{ ProviderCode = '90094'; Code = 'ConsentRequired' }
            @{ ProviderCode = '90095'; Code = 'ConsentRequired' }
            @{ ProviderCode = '90002'; Code = 'InvalidTenant' }
            @{ ProviderCode = '53000'; Code = 'ConditionalAccess' }
            @{ ProviderCode = '53001'; Code = 'ConditionalAccess' }
            @{ ProviderCode = '53002'; Code = 'ConditionalAccess' }
            @{ ProviderCode = '53003'; Code = 'ConditionalAccess' }
            @{ ProviderCode = '53004'; Code = 'ConditionalAccess' }
            @{ ProviderCode = '53009'; Code = 'ConditionalAccess' }
            @{ ProviderCode = '90006'; Code = 'ProviderUnavailable' }
            @{ ProviderCode = '90024'; Code = 'ProviderUnavailable' }
            @{ ProviderCode = '90033'; Code = 'ProviderUnavailable' }
        ) {
            $failure = Get-XdrAuthenticationFailure -AuthState ([pscustomobject]@{ sErrorCode = $ProviderCode })
            $failure.Code | Should -Be $Code
            $failure.ProviderCode | Should -Be $ProviderCode
        }

        It 'does not describe AADSTS50053 as a definite account lockout' {
            $failure = Get-XdrAuthenticationFailure -AuthState ([pscustomobject]@{ sErrorCode = 'AADSTS50053' })

            $failure.Code | Should -Be 'SignInBlocked'
            $failure.Message | Should -Not -Match '(?i)account is locked'
            $failure.RecommendedAction | Should -Match '(?i)sign-in logs'
            $failure.RecommendedAction | Should -Match '(?i)blocked IP'
        }

        It 'calls out a compliant-device Conditional Access requirement' {
            $failure = Get-XdrAuthenticationFailure -AuthState ([pscustomobject]@{ sErrorCode = 'AADSTS53000' })

            $failure.Code | Should -Be 'ConditionalAccess'
            $failure.ConditionalAccessScenario | Should -Be 'DeviceNotCompliant'
            $failure.Message | Should -Match '(?i)requires a compliant device'
            $failure.RecommendedAction | Should -Match '(?i)device marked compliant'
            $failure.RecommendedAction | Should -Match '(?i)sign-in logs'
        }

        It 'keeps generic Conditional Access remediation for policy blocks without an exact scenario' {
            $failure = Get-XdrAuthenticationFailure -AuthState ([pscustomobject]@{ sErrorCode = 'AADSTS53003' })

            $failure.ConditionalAccessScenario | Should -Be 'PolicyBlocked'
            $failure.Message | Should -Be 'A Conditional Access policy blocked this sign-in.'
            $failure.RecommendedAction | Should -Match '(?i)reported Conditional Access requirements'
        }

        It 'maps OAuth errors from query and fragment redirects' -ForEach @(
            @{ Uri = 'https://localhost/callback?error=interaction_required&error_description=do-not-retain'; Code = 'MfaRequired' }
            @{ Uri = 'https://localhost/callback#error=user_denied&code=secret-code'; Code = 'MfaDenied' }
            @{ Uri = 'https://localhost/callback#error=temporarily_unavailable'; Code = 'ProviderUnavailable' }
            @{ Uri = 'https://localhost/callback#error=consent_required'; Code = 'ConsentRequired' }
            @{ Uri = 'https://localhost/callback#error=unexpected_provider_value'; Code = 'ProviderRejected' }
        ) {
            $failure = Get-XdrAuthenticationFailure -RedirectUri $Uri

            $failure.Code | Should -Be $Code
            ($failure | ConvertTo-Json -Depth 8) | Should -Not -Match 'do-not-retain|secret-code'
        }

        It 'maps SAS outcomes without retaining continuation state' -ForEach @(
            @{ ResultValue = 'AuthenticationDenied'; Retry = $false; Code = 'MfaDenied' }
            @{ ResultValue = 'AuthenticationPending'; Retry = $true; Code = 'MfaRequired' }
            @{ ResultValue = 'AuthenticationPending'; Retry = $false; Code = 'MfaTimeout' }
            @{ ResultValue = 'AuthenticationExpired'; Retry = $false; Code = 'MfaTimeout' }
        ) {
            $sas = [pscustomobject]@{ ResultValue = $ResultValue; Retry = $Retry; FlowToken = 'sas-flow-secret'; Ctx = 'sas-context-secret' }
            $failure = Get-XdrAuthenticationFailure -SasResult $sas

            $failure.Code | Should -Be $Code
            ($failure | ConvertTo-Json -Depth 8) | Should -Not -Match 'sas-flow-secret|sas-context-secret'
        }

        It 'maps HTTP status <StatusCode> to <Code>' -ForEach @(
            @{ StatusCode = 400; Code = 'RequestInvalid' }
            @{ StatusCode = 401; Code = 'ProviderRejected' }
            @{ StatusCode = 403; Code = 'ProviderRejected' }
            @{ StatusCode = 429; Code = 'Throttled' }
            @{ StatusCode = 502; Code = 'ProviderUnavailable' }
            @{ StatusCode = 503; Code = 'ProviderUnavailable' }
            @{ StatusCode = 504; Code = 'ProviderUnavailable' }
        ) {
            $failure = Get-XdrAuthenticationFailure -Response ([pscustomobject]@{ StatusCode = $StatusCode })
            $failure.Code | Should -Be $Code
            $failure.StatusCode | Should -Be $StatusCode
        }

        It 'parses JSON error details and preserves safe diagnostic identifiers' {
            $exception = [System.Exception]::new('HTTP request failed')
            $record = [System.Management.Automation.ErrorRecord]::new($exception, 'NativeFailure', 'ConnectionError', $null)
            $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":{"code":"AADSTS50126"},"correlation_id":"11111111-1111-1111-1111-111111111111","trace_id":"trace-123","access_token":"must-not-appear"}')

            $failure = Get-XdrAuthenticationFailure -ErrorRecord $record -AuthenticationMethod Credential -Stage Password

            $failure.Code | Should -Be 'InvalidCredentials'
            $failure.CorrelationId | Should -Be '11111111-1111-1111-1111-111111111111'
            $failure.TraceId | Should -Be 'trace-123'
            ($failure | ConvertTo-Json -Depth 8) | Should -Not -Match 'must-not-appear'
        }

        It 'gives exact provider codes precedence over caller defaults, OAuth, and HTTP status' {
            $failure = Get-XdrAuthenticationFailure -AuthState ([pscustomobject]@{ sErrorCode = '50057' }) -RedirectUri 'https://localhost/#error=interaction_required' -Response ([pscustomobject]@{ StatusCode = 503 }) -DefaultCode BrowserTimeout
            $failure.Code | Should -Be 'AccountDisabled'
        }

        It 'uses the requested local classification when no structured provider signal exists' -ForEach @(
            'CredentialFileInvalid', 'PasskeyUnavailable', 'PasskeyAssertionFailed', 'KeyVaultAccessFailed',
            'BrowserClosed', 'BrowserTimeout', 'BrowserStartupFailed', 'TenantSelectionFailed',
            'NoAuthenticationArtifact', 'BootstrapFailed', 'UnknownFailure'
        ) {
            $failure = Get-XdrAuthenticationFailure -DefaultCode $_
            $failure.Code | Should -Be $_
            $failure.Message | Should -Not -BeNullOrEmpty
            $failure.RecommendedAction | Should -Not -BeNullOrEmpty
        }

        It 'sets retryability according to whether a fresh attempt can succeed without configuration changes' -ForEach @(
            @{ Code = 'MfaTimeout'; Retryable = $true }
            @{ Code = 'FlowExpired'; Retryable = $true }
            @{ Code = 'Throttled'; Retryable = $true }
            @{ Code = 'ConditionalAccess'; Retryable = $false }
            @{ Code = 'AppAssignmentRequired'; Retryable = $false }
            @{ Code = 'ConsentRequired'; Retryable = $false }
            @{ Code = 'InvalidCredentials'; Retryable = $false }
        ) {
            (Get-XdrAuthenticationFailure -DefaultCode $Code).Retryable | Should -Be $Retryable
        }

        It 'adds only allowlisted and bounded safe evidence' {
            $failure = Get-XdrAuthenticationFailure -SafeEvidence ([ordered]@{
                    Attempt = 'ESTS'
                    Host = 'https://login.microsoftonline.com/path?code=secret-code'
                    Unsafe = 'must-not-appear'
                    Status = 'password=secret-password'
                    PageTitle = ('x' * 300)
                })

            $failure.SafeEvidence.Name | Should -Contain 'Attempt'
            $failure.SafeEvidence.Name | Should -Contain 'Host'
            $failure.SafeEvidence.Name | Should -Contain 'PageTitle'
            $failure.SafeEvidence.Name | Should -Not -Contain 'Unsafe'
            $failure.SafeEvidence.Name | Should -Not -Contain 'Status'
            ($failure.SafeEvidence | Where-Object Name -EQ 'Host').Value | Should -Be 'login.microsoftonline.com'
            ($failure.SafeEvidence | Where-Object Name -EQ 'PageTitle').Value.Length | Should -Be 256
            ($failure | ConvertTo-Json -Depth 8) | Should -Not -Match 'secret-code|secret-password|must-not-appear'
        }
    }
}

Describe 'Authentication error record contract' {
    InModuleScope XDRInternals {
        It 'creates a stable terminating record and preserves the original exception as the inner exception' {
            $original = [System.InvalidOperationException]::new('native failure')
            $nativeRecord = [System.Management.Automation.ErrorRecord]::new($original, 'NativeFailure', 'InvalidOperation', $null)
            $failure = Get-XdrAuthenticationFailure -AuthState ([pscustomobject]@{
                    sErrorCode = '53003'
                    correlationId = '11111111-1111-1111-1111-111111111111'
                }) -AuthenticationMethod Browser -Stage Authorize

            $record = New-XdrAuthenticationErrorRecord -Failure $failure -ErrorRecord $nativeRecord

            $record.FullyQualifiedErrorId | Should -Be 'XdrAuthentication.ConditionalAccess'
            $record.CategoryInfo.Category | Should -Be 'PermissionDenied'
            $record.ErrorDetails.Message | Should -Match 'Conditional Access'
            $record.ErrorDetails.RecommendedAction | Should -Match 'sign-in logs'
            [object]::ReferenceEquals($record.Exception.InnerException, $original) | Should -BeTrue
            $record.Exception.Data['XdrAuthenticationFailure'].Code | Should -Be 'ConditionalAccess'
            $record.Exception.Data['XdrAuthenticationFailure'].ConditionalAccessScenario | Should -Be 'PolicyBlocked'
        }

        It 'does not double-wrap an existing structured authentication error' {
            $firstFailure = Get-XdrAuthenticationFailure -DefaultCode BrowserTimeout
            $firstRecord = New-XdrAuthenticationErrorRecord -Failure $firstFailure
            $secondFailure = Get-XdrAuthenticationFailure -ErrorRecord $firstRecord

            $secondRecord = New-XdrAuthenticationErrorRecord -Failure $secondFailure -ErrorRecord $firstRecord

            [object]::ReferenceEquals($secondRecord, $firstRecord) | Should -BeTrue
        }

        It 'keeps secrets out of displayed details, remediation, and metadata' {
            $original = [System.Exception]::new('redirect https://localhost/?code=secret-code&session_id=secret-session')
            $nativeRecord = [System.Management.Automation.ErrorRecord]::new($original, 'NativeFailure', 'AuthenticationError', $null)
            $failure = Get-XdrAuthenticationFailure -RedirectUri 'https://localhost/?error=access_denied&code=secret-code' -SafeEvidence @{ Status = 'cookie=secret-cookie' }
            $record = New-XdrAuthenticationErrorRecord -Failure $failure -ErrorRecord $nativeRecord

            $exposed = @(
                $record.ErrorDetails.Message
                $record.ErrorDetails.RecommendedAction
                ($record.Exception.Data['XdrAuthenticationFailure'] | ConvertTo-Json -Depth 8)
            ) -join "`n"
            $exposed | Should -Not -Match 'secret-code|secret-session|secret-cookie'
        }
    }
}
