function Get-XdrSasProcessRequestState {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SelectedMethod,

        [Parameter(Mandatory)]
        $BeginAuth,

        [Parameter(Mandatory)]
        $AuthState
    )

    if ($SelectedMethod -eq 'PhoneAppNotification' -and $BeginAuth.Ctx) {
        return [string]$BeginAuth.Ctx
    }

    if ($BeginAuth.MobileAppAuthDetails -and $BeginAuth.MobileAppAuthDetails.AuthAppState) {
        return [string]$BeginAuth.MobileAppAuthDetails.AuthAppState
    }

    if ($BeginAuth.Ctx) {
        return [string]$BeginAuth.Ctx
    }

    if ($AuthState.sCtx) {
        return [string]$AuthState.sCtx
    }

    return $null
}

function Add-XdrUriQueryString {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string[]]$Parameters
    )

    $separator = if ($Uri -match '\?') { '&' } else { '?' }
    return ($Uri + $separator + ($Parameters -join '&'))
}

function Invoke-XdrSasBeginAuth {
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SelectedMethod,

        [Parameter(Mandatory)]
        $AuthState,

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string]$BeginAuthUri,

        [string]$FailureLabel = 'MFA'
    )

    $beginBody = @{
        AuthMethodId = $SelectedMethod
        Method       = 'BeginAuth'
        ctx          = $AuthState.sCtx
        flowToken    = $AuthState.sFT
    } | ConvertTo-Json

    Write-Verbose 'Calling SAS/BeginAuth...'
    $beginAuth = Invoke-RestMethod -Method Post `
        -Uri $BeginAuthUri `
        -Body $beginBody -ContentType 'application/json' `
        -Headers $Headers `
        -WebSession $Session -Verbose:$false

    $isPushDuplicateBeginAuth = (
        $SelectedMethod -eq 'PhoneAppNotification' -and
        $beginAuth -and
        $beginAuth.ErrCode -eq 500121 -and
        $beginAuth.ResultValue -eq 'UserAuthFailedDuplicateRequest' -and
        $beginAuth.FlowToken -and
        $beginAuth.Ctx
    )

    if ($isPushDuplicateBeginAuth) {
        Write-Verbose "BeginAuth returned UserAuthFailedDuplicateRequest for $FailureLabel. Continuing with polling using the returned continuation state."
        if (-not $beginAuth.SessionId -or $beginAuth.SessionId -eq '00000000-0000-0000-0000-000000000000') {
            $beginAuth.SessionId = $AuthState.sessionId
        }
    } elseif (-not $beginAuth.Success -and $beginAuth.ErrCode -ne 0) {
        throw "$FailureLabel BeginAuth failed (ErrCode: $($beginAuth.ErrCode)): $($beginAuth.Message)"
    }

    Write-Verbose "BeginAuth response: Success=$($beginAuth.Success), ResultValue=$($beginAuth.ResultValue)"
    return $beginAuth
}

function Invoke-XdrSasPushNotificationPolling {
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SelectedMethod,

        [Parameter(Mandatory)]
        $BeginAuth,

        [Parameter(Mandatory)]
        $AuthState,

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string]$EndAuthUri,

        [Parameter(Mandatory)]
        [datetime]$Deadline,

        [ValidateRange(1, 30)]
        [int]$PollingIntervalSeconds = 3,

        [string]$FailureLabel = 'Push notification',

        [string]$TimeoutMessage
    )

    $pollCount = 0
    $useGetForPushPolling = [bool]$AuthState.fSasEndAuthPostToGetSwitch
    $lastPollStart = $null
    $lastPollEnd = $null
    $processAuthPollStart = $null
    $processAuthPollEnd = $null

    while ((Get-Date) -lt $Deadline) {
        $pollCount++
        Start-Sleep -Seconds $PollingIntervalSeconds

        $pollStarted = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

        if ($useGetForPushPolling) {
            $pollParams = @(
                "authMethodId=$([uri]::EscapeDataString($SelectedMethod))",
                "pollCount=$pollCount"
            )
            if ($lastPollStart) {
                $pollParams += "lastPollStart=$lastPollStart"
            }
            if ($lastPollEnd) {
                $pollParams += "lastPollEnd=$lastPollEnd"
            }

            $pollUri = Add-XdrUriQueryString -Uri $EndAuthUri -Parameters $pollParams
            $pollBody = $null
            $pollResult = Invoke-RestMethod -Method Get `
                -Uri $pollUri `
                -WebSession $Session -Verbose:$false

            $shouldFallbackToPostPolling = (
                $pollResult -and
                $pollResult.ErrCode -eq 500121 -and
                -not $pollResult.FlowToken -and
                -not $pollResult.SessionId -and
                -not $pollResult.Ctx
            )

            if ($shouldFallbackToPostPolling) {
                Write-Verbose 'Initial GET-based push polling failed without continuation state. Falling back to POST-based polling.'
                $useGetForPushPolling = $false
                $pollBody = @{
                    AuthMethodId = $SelectedMethod
                    Method       = 'EndAuth'
                    SessionId    = $BeginAuth.SessionId
                    FlowToken    = $BeginAuth.FlowToken
                    Ctx          = $BeginAuth.Ctx
                    PollCount    = $pollCount
                } | ConvertTo-Json

                $pollUri = $EndAuthUri
                $pollResult = Invoke-RestMethod -Method Post `
                    -Uri $pollUri `
                    -Body $pollBody -ContentType 'application/json' `
                    -Headers $Headers `
                    -WebSession $Session -Verbose:$false
            }
        } else {
            $pollBody = @{
                AuthMethodId = $SelectedMethod
                Method       = 'EndAuth'
                SessionId    = $BeginAuth.SessionId
                FlowToken    = $BeginAuth.FlowToken
                Ctx          = $BeginAuth.Ctx
                PollCount    = $pollCount
            } | ConvertTo-Json

            $pollUri = $EndAuthUri
            $pollResult = Invoke-RestMethod -Method Post `
                -Uri $pollUri `
                -Body $pollBody -ContentType 'application/json' `
                -Headers $Headers `
                -WebSession $Session -Verbose:$false
        }

        $pollEnded = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        if ($null -eq $processAuthPollStart) {
            $processAuthPollStart = $pollStarted
            $processAuthPollEnd = $pollEnded
        }
        $lastPollStart = $pollStarted
        $lastPollEnd = $pollEnded

        Write-Verbose "Poll $pollCount : Success=$($pollResult.Success) ResultValue=$($pollResult.ResultValue)"

        if (Test-XdrMfaAuthSucceeded -Response $pollResult) {
            return [pscustomobject]@{
                BeginAuth            = $pollResult
                PollCount            = $pollCount
                ProcessAuthPollStart = $processAuthPollStart
                ProcessAuthPollEnd   = $processAuthPollEnd
            }
        }

        if ($pollResult.ResultValue -ne 'AuthenticationPending') {
            throw "$FailureLabel denied or failed: $($pollResult.ResultValue) - $($pollResult.Message)"
        }

        if (-not $pollResult.Retry) {
            throw "$FailureLabel timed out. Retry is false."
        }
    }

    if ($TimeoutMessage) {
        throw ($TimeoutMessage -f ($pollCount * $PollingIntervalSeconds))
    }

    throw "$FailureLabel did not complete before the timeout expired."
}

function Invoke-XdrSasProcessAuth {
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SelectedMethod,

        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        $BeginAuth,

        [Parameter(Mandatory)]
        $AuthState,

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string]$ProcessAuthUri,

        [Nullable[long]]$MfaLastPollStart,

        [Nullable[long]]$MfaLastPollEnd,

        [string]$MissingProcessRequestMessage = 'Authentication completed, but no ProcessAuth request state was returned.'
    )

    $processRequest = Get-XdrSasProcessRequestState -SelectedMethod $SelectedMethod -BeginAuth $BeginAuth -AuthState $AuthState
    if (-not $processRequest) {
        throw $MissingProcessRequestMessage
    }

    $processBody = Get-XdrProcessAuthRequestBody `
        -SelectedMethod $SelectedMethod `
        -Username $Username `
        -ProcessRequest $processRequest `
        -BeginAuth $BeginAuth `
        -AuthState $AuthState `
        -MfaLastPollStart $MfaLastPollStart `
        -MfaLastPollEnd $MfaLastPollEnd

    $processContentType = if ($processBody -is [string]) {
        'application/json'
    } else {
        'application/x-www-form-urlencoded'
    }

    Write-Verbose 'Calling SAS/ProcessAuth...'
    $processResponse = Invoke-XdrRedirectCapturingWebRequest `
        -Method Post `
        -Uri $ProcessAuthUri `
        -Body $processBody `
        -ContentType $processContentType `
        -Headers $Headers `
        -Session $Session

    $processResponseState = Get-XdrAuthStateFromResponse -Response $processResponse

    if (Test-XdrProcessAuthRetryableError -ParsedState $processResponseState) {
        $formProcessBody = [ordered]@{
            type         = 22
            request      = $processRequest
            flowToken    = $BeginAuth.FlowToken
            canary       = $AuthState.canary
            hpgrequestid = $AuthState.correlationId
        }

        if ($SelectedMethod -eq 'PhoneAppNotification') {
            $formProcessBody['mfaAuthMethod'] = $SelectedMethod
            $formProcessBody['login'] = $Username
            $formProcessBody['sacxt'] = ''
            $formProcessBody['hideSmsInMfaProofs'] = 'false'
            if ($null -ne $MfaLastPollStart) {
                $formProcessBody['mfaLastPollStart'] = [string]$MfaLastPollStart
            }
            if ($null -ne $MfaLastPollEnd) {
                $formProcessBody['mfaLastPollEnd'] = [string]$MfaLastPollEnd
            }
            if ($null -ne $AuthState.i19) {
                $formProcessBody['i19'] = [string]$AuthState.i19
            }
        } else {
            $formProcessBody['ctx'] = $BeginAuth.Ctx
        }

        Write-Verbose 'ProcessAuth returned a retryable request parsing error. Retrying with login-form style field names.'
        $processResponse = Invoke-XdrRedirectCapturingWebRequest `
            -Method Post `
            -Uri $ProcessAuthUri `
            -Body $formProcessBody `
            -ContentType 'application/x-www-form-urlencoded' `
            -Headers $Headers `
            -Session $Session

        $processResponseState = Get-XdrAuthStateFromResponse -Response $processResponse
    }

    return [pscustomobject]@{
        Outcome              = Resolve-XdrAuthenticationResponse -Response $processResponse -Session $Session
        ProcessResponse      = $processResponse
        ProcessResponseState = $processResponseState
    }
}