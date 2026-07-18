function Get-XdrAuthenticationFailure {
    <#
    .SYNOPSIS
        Classifies an authentication failure into the internal XDR authentication error contract.

    .DESCRIPTION
        Normalizes exact Entra error state, OAuth redirects, SAS results, HTTP responses, and
        native PowerShell errors into a secret-safe authentication failure description.

    .PARAMETER ErrorRecord
        A native PowerShell error to inspect for structured response details and status.

    .PARAMETER AuthState
        Parsed Entra authentication state containing exact provider error fields.

    .PARAMETER RedirectUri
        An OAuth redirect URI whose error fields should be classified without retaining other values.

    .PARAMETER SasResult
        A Server Authentication State result to classify.

    .PARAMETER Response
        An HTTP response whose status and safe identifiers should be inspected.

    .PARAMETER AuthenticationMethod
        The Connect authentication method that encountered the failure.

    .PARAMETER Stage
        The authentication stage that encountered the failure.

    .PARAMETER DefaultCode
        The stable fallback classification to use when no stronger structured signal exists.

    .PARAMETER SafeEvidence
        A small dictionary of allowlisted diagnostic evidence. Unknown or sensitive fields are discarded.

    .EXAMPLE
        Get-XdrAuthenticationFailure -AuthState $authState -AuthenticationMethod Credential -Stage Password

        Classifies exact Entra state returned after password submission.

    .OUTPUTS
        PSCustomObject containing the normalized authentication failure.
    #>
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [object]$AuthState,
        [string]$RedirectUri,
        [object]$SasResult,
        [object]$Response,
        [string]$AuthenticationMethod = 'Unknown',
        [string]$Stage = 'Authentication',
        [ValidateSet(
            'InvalidCredentials', 'AccountNotFound', 'AccountDisabled', 'SignInBlocked', 'PasswordExpired', 'PasswordMissing',
            'MfaEnrollmentRequired', 'MfaRequired', 'MfaDenied', 'MfaTimeout', 'MfaTemporarilyUnavailable', 'FlowExpired', 'SessionUnavailable',
            'ConditionalAccess', 'AppAssignmentRequired', 'ConsentRequired', 'InvalidTenant',
            'CredentialFileInvalid', 'PasskeyUnavailable', 'PasskeyAssertionFailed', 'KeyVaultAccessFailed',
            'ProviderUnavailable', 'Throttled', 'RequestInvalid', 'BrowserClosed', 'BrowserTimeout', 'BrowserStartupFailed',
            'TenantSelectionFailed', 'NoAuthenticationArtifact', 'BootstrapFailed', 'ProviderRejected', 'UnknownFailure'
        )]
        [string]$DefaultCode = 'UnknownFailure',
        [System.Collections.IDictionary]$SafeEvidence
    )

    $getValue = {
        param($InputObject, [string[]]$Names)

        if ($null -eq $InputObject) { return $null }
        foreach ($name in $Names) {
            if ($InputObject -is [System.Collections.IDictionary]) {
                foreach ($key in $InputObject.Keys) {
                    if ([string]$key -ieq $name) { return $InputObject[$key] }
                }
            } else {
                $property = $InputObject.PSObject.Properties | Where-Object Name -IEQ $name | Select-Object -First 1
                if ($property) { return $property.Value }
            }
        }
        return $null
    }

    $parsedError = if ($ErrorRecord) { Get-XdrParsedErrorDetail -ErrorRecord $ErrorRecord } else { $null }
    $sources = @($AuthState, $SasResult, $Response, $parsedError) | Where-Object { $null -ne $_ }

    $providerCode = $null
    foreach ($source in $sources) {
        $candidate = & $getValue $source @('sErrorCode', 'iErrorCode', 'ErrCode', 'errorCode', 'code')
        if (-not $candidate) {
            $nestedError = & $getValue $source @('error')
            if ($nestedError -and $nestedError -isnot [string]) {
                $candidate = & $getValue $nestedError @('code')
            }
        }
        if ($candidate) {
            $providerCode = [string]$candidate
            break
        }
    }

    if (-not $providerCode -and $ErrorRecord -and $ErrorRecord.Exception.Message -match '(?i)(?:AADSTS|error(?:\s+code)?[: (]+)(\d{5,8})') {
        $providerCode = $Matches[1]
    }

    $oauthError = $null
    if (-not [string]::IsNullOrWhiteSpace($RedirectUri)) {
        try {
            $redirect = [uri]$RedirectUri
            foreach ($component in @($redirect.Query.TrimStart('?'), $redirect.Fragment.TrimStart('#'))) {
                foreach ($pair in @($component -split '&')) {
                    if ([string]::IsNullOrWhiteSpace($pair)) { continue }
                    $parts = $pair -split '=', 2
                    $name = [uri]::UnescapeDataString(($parts[0] -replace '\+', ' '))
                    if ($name -ieq 'error' -and $parts.Count -gt 1) {
                        $oauthError = [uri]::UnescapeDataString(($parts[1] -replace '\+', ' '))
                    }
                }
            }
        } catch {
            # An invalid redirect URI is classified by the caller's fallback.
            $oauthError = $null
        }
    }

    if (-not $providerCode -and $oauthError) { $providerCode = $oauthError }
    if ($providerCode -and $providerCode -match '(?i)AADSTS(\d+)') { $providerCode = $Matches[1] }
    if ($providerCode -and $providerCode -notmatch '^[A-Za-z0-9._-]{1,64}$') { $providerCode = $null }

    $statusCode = $null
    foreach ($source in @($Response, $(if ($ErrorRecord) { $ErrorRecord.Exception.Response }))) {
        if (-not $source) { continue }
        $candidateStatus = & $getValue $source @('StatusCode', 'status')
        if ($candidateStatus) {
            try {
                $statusCode = [int]$candidateStatus
            } catch {
                $statusCode = $null
            }
            if ($statusCode) { break }
        }
    }

    $entraMappings = @{
        '16000' = 'AccountNotFound'; '50034' = 'AccountNotFound'; '50053' = 'SignInBlocked'; '50055' = 'PasswordExpired'; '50056' = 'PasswordMissing'
        '50057' = 'AccountDisabled'; '50126' = 'InvalidCredentials'; '50058' = 'SessionUnavailable'
        '50072' = 'MfaEnrollmentRequired'; '50079' = 'MfaEnrollmentRequired'; '50074' = 'MfaRequired'; '50076' = 'MfaRequired'
        '50078' = 'MfaTimeout'; '50087' = 'MfaTemporarilyUnavailable'; '50088' = 'MfaTemporarilyUnavailable'; '50089' = 'FlowExpired'
        '50105' = 'AppAssignmentRequired'; '65001' = 'ConsentRequired'; '90008' = 'ConsentRequired'; '90094' = 'ConsentRequired'; '90095' = 'ConsentRequired'
        '90002' = 'InvalidTenant'; '53000' = 'ConditionalAccess'; '53001' = 'ConditionalAccess'; '53002' = 'ConditionalAccess'
        '53003' = 'ConditionalAccess'; '53004' = 'ConditionalAccess'; '53009' = 'ConditionalAccess'
        '90006' = 'ProviderUnavailable'; '90024' = 'ProviderUnavailable'; '90033' = 'ProviderUnavailable'
    }

    $code = $null
    if ($providerCode -and $entraMappings.ContainsKey($providerCode)) {
        $code = $entraMappings[$providerCode]
    } elseif ($oauthError) {
        $code = switch -Regex ($oauthError) {
            '^interaction_required$' { 'MfaRequired'; break }
            '^(user_cancelled|user_denied)$' { 'MfaDenied'; break }
            '^temporarily_unavailable$' { 'ProviderUnavailable'; break }
            '^invalid_tenant$' { 'InvalidTenant'; break }
            '^consent_required$' { 'ConsentRequired'; break }
            default { 'ProviderRejected' }
        }
    } elseif ($SasResult) {
        $sasValue = [string](& $getValue $SasResult @('ResultValue', 'Outcome', 'AuthorizationState'))
        $sasRetry = & $getValue $SasResult @('Retry')
        $code = switch -Regex ($sasValue) {
            '(?i)denied|declined|rejected' { 'MfaDenied'; break }
            '(?i)timeout|expired' { 'MfaTimeout'; break }
            '(?i)pending' { if ($sasRetry -eq $false) { 'MfaTimeout' } else { 'MfaRequired' }; break }
            default { $null }
        }
    }

    if (-not $code -and $statusCode) {
        $code = switch ($statusCode) {
            429 { 'Throttled' }
            { $_ -in @(502, 503, 504) } { 'ProviderUnavailable' }
            400 { 'RequestInvalid' }
            { $_ -in @(401, 403) } { 'ProviderRejected' }
            default { $null }
        }
    }

    if (-not $code -and $DefaultCode -ne 'UnknownFailure') { $code = $DefaultCode }

    if (-not $code -and $ErrorRecord) {
        $legacyMessage = [string]$ErrorRecord.Exception.Message
        $code = switch -Regex ($legacyMessage) {
            '(?i)no supported Chromium|browser (executable|application bundle).+(not found|does not contain)|DevTools endpoint.+waiting' { 'BrowserStartupFailed'; break }
            '(?i)browser.+(closed|exited)|websocket.+closed' { 'BrowserClosed'; break }
            '(?i)timed out|timeout expired' { 'BrowserTimeout'; break }
            '(?i)tenant.+(not found|did not return|could not validate)' { 'TenantSelectionFailed'; break }
            '(?i)credential file.+(not found|invalid|missing)|invalid JSON in credential' { 'CredentialFileInvalid'; break }
            '(?i)key vault.+(token|access|sign)' { 'KeyVaultAccessFailed'; break }
            '(?i)passkey.+(not available|requires PowerShell)' { 'PasskeyUnavailable'; break }
            '(?i)passkey.+(assertion|validation)|signature generation failed' { 'PasskeyAssertionFailed'; break }
            default { 'UnknownFailure' }
        }
    }
    if (-not $code) { $code = $DefaultCode }

    $definitions = @{
        InvalidCredentials = @('The username or password was not accepted.', 'Verify the username and password, then try again.', 'AuthenticationError', $false)
        AccountNotFound = @('The account could not be found in the selected tenant.', 'Verify the username and tenant, then try again.', 'ObjectNotFound', $false)
        AccountDisabled = @('The account is disabled.', 'Ask a tenant administrator to enable the account before retrying.', 'PermissionDenied', $false)
        SignInBlocked = @('Entra ID blocked this sign-in.', 'Review the Entra sign-in logs to determine whether the account is locked or the sign-in originated from a blocked IP address.', 'PermissionDenied', $false)
        PasswordExpired = @('The account password has expired.', 'Change the password, then start a new connection attempt.', 'AuthenticationError', $false)
        PasswordMissing = @('The account has no valid password configured.', 'Reset or configure the account password before retrying.', 'AuthenticationError', $false)
        MfaEnrollmentRequired = @('The account must register multifactor authentication.', 'Complete the required MFA registration in an interactive sign-in, then retry.', 'PermissionDenied', $false)
        MfaRequired = @('Additional multifactor authentication is required.', 'Complete the requested MFA challenge and start a new connection attempt.', 'AuthenticationError', $true)
        MfaDenied = @('The multifactor authentication request was denied.', 'Approve a new MFA request only if you initiated it, then retry.', 'AuthenticationError', $true)
        MfaTimeout = @('The multifactor authentication request expired or timed out.', 'Start a new connection attempt and complete the MFA request promptly.', 'OperationTimeout', $true)
        MfaTemporarilyUnavailable = @('The multifactor authentication service is temporarily unavailable or limited.', 'Wait before starting a new connection attempt; review sign-in logs if the condition persists.', 'ResourceUnavailable', $true)
        FlowExpired = @('The authentication flow expired.', 'Start a new connection attempt.', 'OperationTimeout', $true)
        SessionUnavailable = @('The existing sign-in session is not sufficient for single sign-on.', 'Obtain a fresh authentication session and try again.', 'AuthenticationError', $true)
        ConditionalAccess = @('A Conditional Access policy blocked this sign-in.', 'Review the Entra sign-in logs and satisfy the reported Conditional Access requirements before retrying.', 'PermissionDenied', $false)
        AppAssignmentRequired = @('This account is not assigned to the required application.', 'Ask a tenant administrator to assign the account or group to the application.', 'PermissionDenied', $false)
        ConsentRequired = @('The application requires user or administrator consent.', 'Grant the required consent in the tenant, then retry.', 'PermissionDenied', $false)
        InvalidTenant = @('The requested tenant is invalid or unavailable.', 'Verify the tenant identifier and that the account has access to it.', 'InvalidArgument', $false)
        CredentialFileInvalid = @('The software passkey credential file is missing or invalid.', 'Verify the credential file path and required fields without sharing its contents.', 'InvalidData', $false)
        PasskeyUnavailable = @('Passkey authentication is not available for this account or environment.', 'Verify that the account has a supported passkey and that the local requirements are installed.', 'NotImplemented', $false)
        PasskeyAssertionFailed = @('The passkey assertion could not be created or accepted.', 'Verify the passkey credential and start a new connection attempt.', 'AuthenticationError', $false)
        KeyVaultAccessFailed = @('The passkey could not be used through Azure Key Vault.', 'Verify Key Vault authentication, key permissions, key name, and network access.', 'PermissionDenied', $false)
        ProviderUnavailable = @('The authentication provider is temporarily unavailable.', 'Wait briefly, then start a new connection attempt.', 'ResourceUnavailable', $true)
        Throttled = @('The authentication provider throttled the request.', 'Wait before starting a new connection attempt.', 'LimitsExceeded', $true)
        RequestInvalid = @('The authentication provider rejected an invalid request.', 'Start a new connection attempt; if this persists, collect the safe diagnostic identifiers and report the issue.', 'InvalidArgument', $false)
        BrowserClosed = @('The authentication browser closed before sign-in completed.', 'Keep the authentication browser open until Defender XDR finishes loading.', 'OperationStopped', $true)
        BrowserTimeout = @('Browser authentication did not complete before the timeout.', 'Complete sign-in more quickly or increase TimeoutSeconds, then retry.', 'OperationTimeout', $true)
        BrowserStartupFailed = @('The authentication browser could not be started.', 'Verify BrowserPath and that a supported Chromium-based browser can run.', 'OpenError', $false)
        TenantSelectionFailed = @('The requested Defender tenant could not be selected.', 'Verify the tenant identifier and that the signed-in account can access it.', 'ObjectNotFound', $false)
        NoAuthenticationArtifact = @('Authentication completed without a usable session artifact.', 'Start a new connection attempt and complete every sign-in prompt.', 'AuthenticationError', $true)
        BootstrapFailed = @('The authenticated session could not be established with Defender XDR.', 'Start a new connection attempt; use the safe diagnostic evidence if the problem persists.', 'ConnectionError', $true)
        ProviderRejected = @('The authentication provider rejected the sign-in.', 'Review the Entra sign-in logs using the diagnostic identifiers, then retry after resolving the reported cause.', 'AuthenticationError', $false)
        UnknownFailure = @('Authentication failed for an unclassified reason.', 'Retry once; if the failure persists, use the safe diagnostic identifiers when reporting the issue.', 'NotSpecified', $false)
    }

    $definition = $definitions[$code]
    $retryable = [bool]$definition[3]
    if ($providerCode -eq '50088') { $retryable = $false }

    $correlationId = $null
    $traceId = $null
    $requestId = $null
    foreach ($source in $sources) {
        if (-not $correlationId) { $correlationId = & $getValue $source @('correlation_id', 'correlationId', 'CorrelationId') }
        if (-not $traceId) { $traceId = & $getValue $source @('trace_id', 'traceId', 'TraceId') }
        if (-not $requestId) { $requestId = & $getValue $source @('request_id', 'requestId', 'RequestId') }
    }

    $safeIdentifier = {
        param($Value)
        if ($null -eq $Value) { return $null }
        $text = [string]$Value
        if ($text -match '^[A-Za-z0-9._:-]{1,128}$') { return $text }
        return $null
    }

    $conditionalAccessScenarios = @{
        '53000' = 'DeviceNotCompliant'; '53001' = 'DeviceNotDomainJoined'; '53002' = 'ApplicationBlocked'
        '53003' = 'PolicyBlocked'; '53004' = 'ProofUpRequired'; '53009' = 'ApplicationRequiresProtectionPolicy'
    }

    $evidence = @()
    $allowedEvidenceKeys = @('Attempt', 'PageTitle', 'Host', 'Status', 'Field', 'BrowserState')
    if ($SafeEvidence) {
        foreach ($key in $SafeEvidence.Keys) {
            if ([string]$key -notin $allowedEvidenceKeys) { continue }
            $value = [string]$SafeEvidence[$key]
            if ($value.Length -gt 256) { $value = $value.Substring(0, 256) }
            if ($value -match '(?i)(password|cookie|assertion|authorization.?code|token|sft|sctx|canary|session.?id)\s*[:=]') { continue }
            if ($value -match 'https?://') {
                try { $value = ([uri]$value).Host } catch { continue }
            }
            $evidence += [pscustomobject]@{ Name = [string]$key; Value = $value }
            if ($evidence.Count -ge 6) { break }
        }
    }

    $safeCorrelationId = if ($null -ne $correlationId) { & $safeIdentifier $correlationId } else { $null }
    $safeTraceId = if ($null -ne $traceId) { & $safeIdentifier $traceId } else { $null }
    $safeRequestId = if ($null -ne $requestId) { & $safeIdentifier $requestId } else { $null }
    $conditionalAccessScenario = if ($providerCode -and $conditionalAccessScenarios.ContainsKey($providerCode)) {
        $conditionalAccessScenarios[$providerCode]
    } else {
        $null
    }

    return [pscustomobject][ordered]@{
        Code                      = $code
        ProviderCode              = $providerCode
        AuthenticationMethod      = $AuthenticationMethod
        Stage                     = $Stage
        StatusCode                = $statusCode
        Retryable                 = $retryable
        CorrelationId             = $safeCorrelationId
        TraceId                   = $safeTraceId
        RequestId                 = $safeRequestId
        ConditionalAccessScenario = $conditionalAccessScenario
        SafeEvidence              = $evidence
        Message                   = $definition[0]
        RecommendedAction         = $definition[1]
        ErrorCategory             = [System.Management.Automation.ErrorCategory]::$($definition[2])
    }
}
