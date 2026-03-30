function Get-XdrPhoneSignInJsonResponseObject {
    [OutputType([object])]
    [CmdletBinding()]
    param($Response)

    if ($null -eq $Response -or [string]::IsNullOrWhiteSpace($Response.Content)) {
        return $null
    }

    try {
        return $Response.Content | ConvertFrom-Json -Depth 30
    } catch {
        Write-Verbose "Response content was not a plain JSON payload: $($_.Exception.Message)"
    }

    if ($Response.Content -match '{(.*)}') {
        try {
            return $Matches[0] | ConvertFrom-Json -Depth 30
        } catch {
            Write-Verbose "Embedded JSON payload could not be parsed: $($_.Exception.Message)"
        }
    }

    return $null
}

function Get-XdrPhoneSignInQueryValue {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $pattern = '(?:\?|&)' + [regex]::Escape($Name) + '=([^&]*)'
    $match = [regex]::Match($Uri, $pattern)
    if (-not $match.Success) {
        return $null
    }

    return [uri]::UnescapeDataString(($match.Groups[1].Value -replace '\+', ' '))
}

function Get-XdrPhoneSignInBrowserHeaderSet {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [string]$Referer,

        [string]$Origin,

        [string]$Accept,

        [string]$SecFetchMode,

        [string]$SecFetchDest,

        [string]$SecFetchSite,

        [switch]$IncludeUpgradeInsecureRequests,

        [switch]$IncludeSecFetchUser
    )

    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($Referer)) {
        $headers['Referer'] = $Referer
    }

    if (-not [string]::IsNullOrWhiteSpace($Origin)) {
        $headers['Origin'] = $Origin
    }

    if (-not [string]::IsNullOrWhiteSpace($Accept)) {
        $headers['Accept'] = $Accept
    }

    if (-not [string]::IsNullOrWhiteSpace($SecFetchMode)) {
        $headers['Sec-Fetch-Mode'] = $SecFetchMode
    }

    if (-not [string]::IsNullOrWhiteSpace($SecFetchDest)) {
        $headers['Sec-Fetch-Dest'] = $SecFetchDest
    }

    if (-not [string]::IsNullOrWhiteSpace($SecFetchSite)) {
        $headers['Sec-Fetch-Site'] = $SecFetchSite
    }

    if ($IncludeUpgradeInsecureRequests) {
        $headers['Upgrade-Insecure-Requests'] = '1'
    }

    if ($IncludeSecFetchUser) {
        $headers['Sec-Fetch-User'] = '?1'
    }

    return $headers
}

function Get-XdrPhoneSignInDisplayNumber {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    if ($text -notmatch '^\d{1,3}$') {
        return $null
    }

    return $text
}

function Get-XdrPhoneSignInInputFieldMap {
    [OutputType([ordered])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Response
    )

    $fields = [ordered]@{}
    if ($null -eq $Response -or $null -eq $Response.InputFields) {
        return $fields
    }

    foreach ($inputField in @($Response.InputFields)) {
        if ([string]::IsNullOrWhiteSpace($inputField.name)) {
            continue
        }

        $fields[[string]$inputField.name] = [string]$inputField.value
    }

    return $fields
}

function Get-XdrPhoneSignInRemoteNgcState {
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $AuthState,

        $GctResponse
    )

    if ($GctResponse -and $GctResponse.Credentials -and $GctResponse.Credentials.RemoteNgcParams) {
        return $GctResponse.Credentials.RemoteNgcParams
    }

    if ($AuthState.oGetCredTypeResult -and $AuthState.oGetCredTypeResult.Credentials -and $AuthState.oGetCredTypeResult.Credentials.RemoteNgcParams) {
        return $AuthState.oGetCredTypeResult.Credentials.RemoteNgcParams
    }

    return $null
}

function Get-XdrPhoneSignInFlowToken {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $AuthState,

        $GctResponse,

        [string]$CurrentFlowToken
    )

    if (-not [string]::IsNullOrWhiteSpace($CurrentFlowToken)) {
        return $CurrentFlowToken
    }

    if ($GctResponse -and -not [string]::IsNullOrWhiteSpace($GctResponse.FlowToken)) {
        return [string]$GctResponse.FlowToken
    }

    if ($AuthState.oGetCredTypeResult -and -not [string]::IsNullOrWhiteSpace($AuthState.oGetCredTypeResult.FlowToken)) {
        return [string]$AuthState.oGetCredTypeResult.FlowToken
    }

    return [string]$AuthState.sFT
}

function Test-XdrPhoneSignInRemoteNgcChallengeSent {
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        $RemoteNgcParams
    )

    if (-not $RemoteNgcParams) {
        return $false
    }

    $entropyProperty = $RemoteNgcParams.PSObject.Properties['Entropy']
    if (-not $entropyProperty) {
        return $false
    }

    return -not [string]::IsNullOrWhiteSpace([string]$entropyProperty.Value)
}

function Invoke-XdrPhoneSignInStartRemoteNgcChallenge {
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $AuthState,

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [Parameter(Mandatory)]
        [string]$FlowToken,

        $RemoteNgcState,

        [string]$AuthorizeUri
    )

    $challengeUri = Resolve-XdrAuthAbsoluteUri -Uri $AuthState.urlGetOneTimeCode
    if (-not $challengeUri) {
        throw 'Phone sign-in did not expose the RemoteNGC challenge endpoint.'
    }

    $headers = Get-XdrEstsApiHeaderSet -AuthState $AuthState
    $headers['Origin'] = 'https://login.microsoftonline.com'
    $headers['Referer'] = if ($AuthorizeUri) {
        $AuthorizeUri
    } elseif ($AuthState.urlResume) {
        Resolve-XdrAuthAbsoluteUri -Uri $AuthState.urlResume
    } else {
        'https://login.microsoftonline.com/'
    }

    if ($AuthState.correlationId) {
        $headers['hpgrequestid'] = [string]$AuthState.correlationId
    }

    $challengeBody = [ordered]@{
        Channel         = 'Authenticator'
        OriginalRequest = [string]$AuthState.sCtx
        FlowToken       = [string]$FlowToken
    }
    if ($RemoteNgcState.SessionIdentifier) {
        $challengeBody['OldDeviceCode'] = [string]$RemoteNgcState.SessionIdentifier
    }
    $challengeBody = $challengeBody | ConvertTo-Json -Compress

    $challengeResponse = $null
    $sessionLookupKey = $null
    $lastError = $null
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $challengeResponse = Invoke-RestMethod -Uri $challengeUri -Method Post -WebSession $Session -Headers $headers -Body $challengeBody -ContentType 'application/json; charset=UTF-8' -ErrorAction Stop

        if ($challengeResponse.error -and $challengeResponse.error.code) {
            $lastError = "Phone sign-in challenge start failed ($($challengeResponse.error.code)): $($challengeResponse.error.message)"
            if ($attempt -lt 2) {
                Write-Verbose "GetOneTimeCode attempt $attempt returned error $($challengeResponse.error.code), retrying..."
                Start-Sleep -Seconds 2
                continue
            }
            throw $lastError
        }

        $sessionLookupKey = if (-not [string]::IsNullOrWhiteSpace([string]$challengeResponse.RemoteNgcParams.SessionIdentifier)) {
            [string]$challengeResponse.RemoteNgcParams.SessionIdentifier
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$challengeResponse.SessionLookupKey)) {
            [string]$challengeResponse.SessionLookupKey
        } else {
            [string]$challengeResponse.DeviceCode
        }

        if (-not [string]::IsNullOrWhiteSpace($sessionLookupKey)) {
            break
        }

        if ($attempt -lt 2) {
            Write-Verbose "GetOneTimeCode attempt $attempt returned no session identifier, retrying..."
            Start-Sleep -Seconds 2
        }
    }

    $state = if ($null -ne $challengeResponse.State -and "$($challengeResponse.State)" -match '^\d+$') {
        [int]$challengeResponse.State
    } else {
        $null
    }

    $displayCode = if ($null -ne $challengeResponse.RemoteNgcParams.Entropy) {
        [string]$challengeResponse.RemoteNgcParams.Entropy
    } elseif (-not [string]::IsNullOrWhiteSpace([string]$challengeResponse.DisplaySignForUI)) {
        [string]$challengeResponse.DisplaySignForUI
    } else {
        [string]$challengeResponse.UserCode
    }

    $returnedFlowToken = if (-not [string]::IsNullOrWhiteSpace([string]$challengeResponse.FlowToken)) {
        [string]$challengeResponse.FlowToken
    } else {
        [string]$FlowToken
    }

    if ([string]::IsNullOrWhiteSpace($sessionLookupKey)) {
        $summary = $challengeResponse | ConvertTo-Json -Compress -Depth 10
        throw "Phone sign-in challenge start did not return an active RemoteNGC session. Response: $summary"
    }

    return [pscustomobject]@{
        State             = $state
        SessionIdentifier = $sessionLookupKey
        DisplayCode       = $displayCode
        FlowToken         = $returnedFlowToken
        RawResponse       = $challengeResponse
    }
}

function Invoke-XdrPhoneSignInGetCredentialType {
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        $AuthState,

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [Parameter(Mandatory)]
        [string]$AuthorizeUri
    )

    $countryCode = try {
        [System.Globalization.RegionInfo]::CurrentRegion.TwoLetterISORegionName
    } catch {
        'US'
    }

    $credHeaders = Get-XdrEstsApiHeaderSet -AuthState $AuthState
    $credHeaders['Origin'] = 'https://login.microsoftonline.com'
    $credHeaders['Referer'] = $AuthorizeUri
    if ($AuthState.correlationId) {
        $credHeaders['hpgrequestid'] = [string]$AuthState.correlationId
    }

    $credentialTypeBody = [ordered]@{
        username                       = $Username
        isOtherIdpSupported            = $true
        checkPhones                    = $false
        isRemoteNGCSupported           = $true
        isCookieBannerShown            = $false
        isFidoSupported                = $true
        originalRequest                = $AuthState.sCtx
        country                        = $countryCode
        forceotclogin                  = $false
        isExternalFederationDisallowed = $false
        isRemoteConnectSupported       = $false
        federationFlags                = 0
        isSignup                       = $false
        flowToken                      = $AuthState.sFT
        isAccessPassSupported          = $true
        isQrCodePinSupported           = $true
    } | ConvertTo-Json -Compress

    return Invoke-RestMethod -Uri 'https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US' -Method Post -WebSession $Session -Headers $credHeaders -Body $credentialTypeBody -ContentType 'application/json; charset=UTF-8' -ErrorAction Stop
}

function Invoke-XdrPhoneSignInFidoBootstrap {
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        $AuthState,

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [Parameter(Mandatory)]
        $GctResponse
    )

    $allowList = @($GctResponse.Credentials.FidoParams.AllowList)
    if (-not $allowList) {
        throw "Phone sign-in is not available for '$Username'. No Authenticator passkey credential was returned."
    }

    $verifyBody = [ordered]@{
        allowedIdentities            = 2
        canary                       = $AuthState.sFT
        serverChallenge              = $AuthState.sFT
        postBackUrl                  = $AuthState.urlPost
        postBackUrlAad               = $AuthState.urlPostAad
        postBackUrlMsa               = $AuthState.urlPostMsa
        cancelUrl                    = $(if ($AuthState.urlRefresh) { $AuthState.urlRefresh } else { $AuthState.urlLogin })
        resumeUrl                    = $(if ($AuthState.urlResume) { $AuthState.urlResume } else { $AuthState.urlLogin })
        correlationId                = $AuthState.correlationId
        credentialsJson              = ($allowList -join ',')
        ctx                          = $AuthState.sCtx
        username                     = $Username
        hasMsftAuthAppPasskey        = 1
        hasMsftAndroidAuthAppPasskey = 1
    }
    if ($AuthState.canary) {
        $verifyBody.loginCanary = $AuthState.canary
    }

    $verifyHeaders = Get-XdrPhoneSignInBrowserHeaderSet `
        -Origin 'https://login.microsoftonline.com' `
        -Referer 'https://login.microsoftonline.com/' `
        -Accept 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' `
        -IncludeUpgradeInsecureRequests

    $verifyResponse = Invoke-WebRequest -UseBasicParsing -Uri 'https://login.microsoft.com/common/fido/get?uiflavor=Web' -Method Post -Body $verifyBody -Headers $verifyHeaders -WebSession $Session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false
    if ($verifyResponse.StatusCode -ge 400) {
        throw "Phone sign-in initialization failed with HTTP $($verifyResponse.StatusCode)."
    }

    $verifyState = Get-XdrAuthStateFromResponse -Response $verifyResponse
    if (-not $verifyState -or [string]::IsNullOrWhiteSpace($verifyState.urlResume)) {
        throw 'Phone sign-in did not return a resume URL.'
    }

    return [pscustomobject]@{
        Response   = $verifyResponse
        AuthState  = $verifyState
        ResumeUri  = [string]$verifyState.urlResume
        NumberCode = Get-XdrPhoneSignInDisplayNumber (Get-XdrPhoneSignInQueryValue -Uri $verifyState.urlResume -Name 'npc')
    }
}

function Test-XdrPhoneSignInSasReady {
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $AuthState
    )

    if (-not $AuthState) {
        return $false
    }

    $phoneAppNotificationProof = @($AuthState.arrUserProofs | Where-Object authMethodId -EQ 'PhoneAppNotification')
    return [bool](
        $phoneAppNotificationProof -and
        -not [string]::IsNullOrWhiteSpace($AuthState.urlBeginAuth) -and
        -not [string]::IsNullOrWhiteSpace($AuthState.urlEndAuth) -and
        -not [string]::IsNullOrWhiteSpace($AuthState.urlPost)
    )
}

function Test-XdrPhoneSignInNativeBridgeFlow {
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $AuthState
    )

    if (-not $AuthState) {
        return $false
    }

    return [bool](
        $AuthState.fIsPasskey -and (
            $AuthState.fEnableWebNativeBridgeInterstitialUx -or
            $AuthState.fEnableWebNativeBridgeLoadFix -or
            $AuthState.fEnableNativeBridgeErrors -or
            $AuthState.sCookieDomain -eq 'login.microsoft.com'
        )
    )
}

function Invoke-XdrPhoneSignInSasAuthentication {
    [OutputType([object])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        $AuthState,

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [datetime]$Deadline,

        [string]$BootstrapNumberCode
    )

    $selectedMethod = 'PhoneAppNotification'
    $sasHeaders = Get-XdrEstsApiHeaderSet -AuthState $AuthState
    $loginReferer = Resolve-XdrAuthAbsoluteUri -Uri $AuthState.urlPost
    if (-not $loginReferer) {
        $loginReferer = 'https://login.microsoftonline.com/common/login'
    }

    $browserHeaders = Get-XdrPhoneSignInBrowserHeaderSet `
        -Origin 'https://login.microsoftonline.com' `
        -Referer $loginReferer `
        -Accept 'application/json, text/javascript, */*; q=0.01' `
        -SecFetchMode 'cors' `
        -SecFetchDest 'empty' `
        -SecFetchSite 'same-origin'

    foreach ($headerName in $browserHeaders.Keys) {
        $sasHeaders[$headerName] = $browserHeaders[$headerName]
    }

    $beginAuthUri = Resolve-XdrAuthAbsoluteUri -Uri $AuthState.urlBeginAuth
    $endAuthUri = Resolve-XdrAuthAbsoluteUri -Uri $AuthState.urlEndAuth
    $processUri = Resolve-XdrAuthAbsoluteUri -Uri $AuthState.urlPost
    $beginAuth = Invoke-XdrSasBeginAuth -SelectedMethod $selectedMethod -AuthState $AuthState -Session $Session -Headers $sasHeaders -BeginAuthUri $beginAuthUri -FailureLabel 'Phone sign-in'

    $displayNumber = if ($beginAuth.Entropy -and $beginAuth.Entropy -gt 0) {
        Get-XdrPhoneSignInDisplayNumber -Value $beginAuth.Entropy
    } elseif ($BootstrapNumberCode) {
        Get-XdrPhoneSignInDisplayNumber -Value $BootstrapNumberCode
    } else {
        $null
    }

    if ($displayNumber) {
        Write-Host "Approve the phone sign-in in Microsoft Authenticator and choose number $displayNumber."
    } else {
        Write-Host 'Approve the phone sign-in in Microsoft Authenticator.'
    }

    $pollOutcome = Invoke-XdrSasPushNotificationPolling -SelectedMethod $selectedMethod -BeginAuth $beginAuth -AuthState $AuthState -Session $Session -Headers $sasHeaders -EndAuthUri $endAuthUri -Deadline $Deadline -FailureLabel 'Phone sign-in' -TimeoutMessage 'Phone sign-in did not complete before the timeout expired.'
    $beginAuth = $pollOutcome.BeginAuth
    $processAuthPollStart = $pollOutcome.ProcessAuthPollStart
    $processAuthPollEnd = $pollOutcome.ProcessAuthPollEnd

    Write-Host 'Phone sign-in approved.'

    $processOutcome = Invoke-XdrSasProcessAuth -SelectedMethod $selectedMethod -Username $Username -BeginAuth $beginAuth -AuthState $AuthState -Session $Session -Headers $sasHeaders -ProcessAuthUri $processUri -MfaLastPollStart $processAuthPollStart -MfaLastPollEnd $processAuthPollEnd -MissingProcessRequestMessage 'Phone sign-in approval completed, but no ProcessAuth request state was returned.'

    return [pscustomobject]@{
        Outcome       = $processOutcome.Outcome
        DisplayNumber = $displayNumber
    }
}

function Test-XdrPhoneSignInApproved {
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $PollResponse
    )

    switch ($PollResponse.AuthorizationState) {
        0 { return $false }
        2 { return $true }
        3 { return $false }
        6 { return $false }
        1 { throw 'Phone sign-in was denied.' }
        default { throw "Phone sign-in polling returned unexpected AuthorizationState '$($PollResponse.AuthorizationState)'." }
    }
}

function Invoke-XdrPhoneSignInPollSession {
    [OutputType([void])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $AuthState,

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [Parameter(Mandatory)]
        [string]$SessionIdentifier,

        [datetime]$Deadline,

        [int]$PollingIntervalSeconds = 1,

        [string]$DisplayCode
    )

    if ($AuthState.iRemoteNgcPollingType -ne 2) {
        throw "Phone sign-in exposed unsupported polling type '$($AuthState.iRemoteNgcPollingType)'."
    }

    $pollUri = Resolve-XdrAuthAbsoluteUri -Uri $AuthState.urlSessionState
    if (-not $pollUri) {
        throw 'Phone sign-in did not expose a session polling endpoint.'
    }

    $headers = Get-XdrEstsApiHeaderSet -AuthState $AuthState
    $pollUri = if ($pollUri -match '\?') {
        "${pollUri}&code=$([uri]::EscapeDataString($SessionIdentifier))"
    } else {
        "${pollUri}?code=$([uri]::EscapeDataString($SessionIdentifier))"
    }

    $reminderInterval = 10
    $nextReminder = (Get-Date).AddSeconds($reminderInterval)

    do {
        $pollResponse = Invoke-RestMethod -Uri $pollUri -Method Post -WebSession $Session -Headers $headers -Body (@{ DeviceCode = $SessionIdentifier } | ConvertTo-Json -Compress) -ContentType 'application/json; charset=UTF-8' -ErrorAction Stop
        if (Test-XdrPhoneSignInApproved -PollResponse $pollResponse) {
            return
        }

        if ($DisplayCode -and (Get-Date) -ge $nextReminder) {
            Write-Host "  Waiting for Authenticator approval — choose number $DisplayCode"
            $nextReminder = (Get-Date).AddSeconds($reminderInterval)
        }

        Start-Sleep -Seconds $PollingIntervalSeconds
    } while ((Get-Date) -lt $Deadline)

    throw 'Phone sign-in did not complete before the timeout expired.'
}

function Invoke-XdrPhoneSignInSubmitApprovedSession {
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        $AuthState,

        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,

        [Parameter(Mandatory)]
        [hashtable]$LoginFormFields,

        [Parameter(Mandatory)]
        [string]$FlowToken,

        [Parameter(Mandatory)]
        [string]$SessionIdentifier,

        [string]$DisplayCode,

        [int]$RemoteNgcDefaultType = 1,

        [switch]$KeepMeSignedIn
    )

    $body = [ordered]@{}
    foreach ($entry in $LoginFormFields.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace($entry.Key)) {
            continue
        }

        $body[$entry.Key] = $entry.Value
    }

    $loginOptions = if ($KeepMeSignedIn) { 1 } else { 3 }
    $sessionIdentifierName = if ([string]::IsNullOrWhiteSpace($AuthState.sSessionIdentifierName)) { 'code' } else { [string]$AuthState.sSessionIdentifierName }

    $body['login'] = $Username
    $body['loginfmt'] = $Username
    $body['type'] = '21'
    $body['ps'] = '4'
    $body['LoginOptions'] = [string]$loginOptions
    $body['i13'] = if ($KeepMeSignedIn) { '1' } else { '0' }
    $body['flowToken'] = $FlowToken
    $body['ctx'] = [string]$AuthState.sCtx
    $body['canary'] = [string]$AuthState.canary
    $body['hpgrequestid'] = [string]$(if ($AuthState.correlationId) { $AuthState.correlationId } else { $AuthState.sessionId })
    $body['psRNGCDefaultType'] = [string]$RemoteNgcDefaultType
    $body['psRNGCEntropy'] = [string]$(if ($DisplayCode) { $DisplayCode } else { '' })
    $body['psRNGCSLK'] = $SessionIdentifier
    $body[$sessionIdentifierName] = $SessionIdentifier

    if ($AuthState.sUnauthSessionID) {
        $body['uaid'] = [string]$AuthState.sUnauthSessionID
    }

    $postUri = Resolve-XdrAuthAbsoluteUri -Uri $AuthState.urlPost
    $submitResponse = Invoke-XdrRedirectCapturingWebRequest -Uri $postUri -Method Post -Session $Session -Body $body -ContentType 'application/x-www-form-urlencoded'
    return Resolve-XdrAuthenticationResponse -Response $submitResponse -Session $Session
}

function Invoke-XdrPhoneSignInAuthentication {
    <#
    .SYNOPSIS
        Performs Microsoft Authenticator phone sign-in and returns the ESTSAUTH cookie.

    .DESCRIPTION
        Starts the Defender portal phone sign-in flow, selects the Microsoft Authenticator passkey-backed
        branch used for phone sign-in, shows the number returned by Entra ID when available, waits for the
        approval to complete, and returns the resulting ESTSAUTH cookie.

        This is an internal function used by Connect-XdrByPhoneSignIn.

    .PARAMETER Username
        Optional username to display to the user while they complete the sign-in.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for the phone sign-in to complete.

    .PARAMETER UserAgent
        User-Agent string used for the underlying Entra ID web requests.

    .OUTPUTS
        String - the ESTSAUTH cookie value suitable for passing to Connect-XdrByEstsCookie.

    .EXAMPLE
        $cookie = Invoke-XdrPhoneSignInAuthentication -Username 'admin@contoso.com'

        Starts phone sign-in, waits for Microsoft Authenticator approval, and returns the
        captured ESTSAUTH cookie.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [string]$Username,

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 300,

        [string]$UserAgent = (Get-XdrDefaultUserAgent)
    )

    if (-not $Username) {
        throw 'No username provided.'
    }

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = $UserAgent

    $portalResponse = Invoke-XdrRedirectCapturingWebRequest -Uri 'https://security.microsoft.com/' -Method Get -Session $session
    $authorizeLocation = Get-XdrResponseLocation -Response $portalResponse
    if (-not $authorizeLocation) {
        throw 'Unable to obtain the Defender XDR authorize redirect.'
    }

    $authorizeUri = "$authorizeLocation&login_hint=$([uri]::EscapeDataString($Username))"

    Write-Host "Starting phone sign-in for $Username..."
    $authResponse = Invoke-WebRequest -UseBasicParsing -Uri $authorizeUri -Method Get -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false
    $authState = Get-XdrAuthStateFromResponse -Response $authResponse
    if (-not $authState) {
        throw 'Unexpected response from the Defender portal authorize flow.'
    }

    if (Test-XdrPhoneSignInSasReady -AuthState $authState) {
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $sasOutcome = Invoke-XdrPhoneSignInSasAuthentication -Username $Username -AuthState $authState -Session $session -Deadline $deadline
        $currentCookie = Get-XdrBestEstsCookieValue -Session $session
        if ($currentCookie) {
            return $currentCookie
        }

        if ($sasOutcome.Outcome.AuthState -and $sasOutcome.Outcome.AuthState.sErrorCode) {
            throw "Phone sign-in failed with error $($sasOutcome.Outcome.AuthState.sErrorCode): $($sasOutcome.Outcome.AuthState.sErrTxt)"
        }

        throw 'Phone sign-in completed, but no ESTSAUTH cookie was captured.'
    }

    try {
        $credentialType = Invoke-XdrPhoneSignInGetCredentialType -Username $Username -AuthState $authState -Session $session -AuthorizeUri $authorizeUri
    } catch {
        throw "GetCredentialType failed: $($_.Exception.Message)"
    }

    # --- RemoteNGC / GetOneTimeCode → DeviceCodeStatus flow (preferred) ---
    $remoteNgcState = Get-XdrPhoneSignInRemoteNgcState -AuthState $authState -GctResponse $credentialType
    $flowToken = Get-XdrPhoneSignInFlowToken -AuthState $authState -GctResponse $credentialType

    if ($remoteNgcState -and $authState.urlGetOneTimeCode) {
        Write-Verbose 'RemoteNGC flow available — using GetOneTimeCode → DeviceCodeStatus path.'
        $challenge = Invoke-XdrPhoneSignInStartRemoteNgcChallenge -AuthState $authState -Session $session -FlowToken $flowToken -RemoteNgcState $remoteNgcState -AuthorizeUri $authorizeUri
        $displayCode = Get-XdrPhoneSignInDisplayNumber -Value $challenge.DisplayCode

        if ($displayCode) {
            Write-Host ''
            Write-Host '  ========================================'
            Write-Host "  Approve in Microsoft Authenticator: $displayCode"
            Write-Host '  ========================================'
            Write-Host ''
        } else {
            Write-Host 'Approve the phone sign-in in Microsoft Authenticator.'
        }

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        Invoke-XdrPhoneSignInPollSession -AuthState $authState -Session $session -SessionIdentifier $challenge.SessionIdentifier -Deadline $deadline -DisplayCode $displayCode

        Write-Host 'Phone sign-in approved.'

        $loginFormFields = Get-XdrPhoneSignInInputFieldMap -Response $authResponse
        $submitResult = Invoke-XdrPhoneSignInSubmitApprovedSession `
            -Username $Username `
            -AuthState $authState `
            -Session $session `
            -LoginFormFields $loginFormFields `
            -FlowToken $challenge.FlowToken `
            -SessionIdentifier $challenge.SessionIdentifier `
            -DisplayCode $displayCode

        $currentCookie = Get-XdrBestEstsCookieValue -Session $session
        if ($currentCookie) {
            return $currentCookie
        }

        if ($submitResult.AuthState -and $submitResult.AuthState.sErrorCode) {
            throw "Phone sign-in login submission failed with error $($submitResult.AuthState.sErrorCode): $($submitResult.AuthState.sErrTxt)"
        }

        throw 'Phone sign-in completed and approved, but no ESTSAUTH cookie was captured.'
    }

    # --- Fallback: fido/get bootstrap → SAS BeginAuth/EndAuth flow ---
    Write-Verbose 'RemoteNGC flow not available — falling back to FIDO bootstrap path.'
    $fidoBootstrap = Invoke-XdrPhoneSignInFidoBootstrap -Username $Username -AuthState $authState -Session $session -GctResponse $credentialType
    $numberCode = Get-XdrPhoneSignInDisplayNumber -Value $fidoBootstrap.NumberCode
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    if (Test-XdrPhoneSignInSasReady -AuthState $fidoBootstrap.AuthState) {
        $sasOutcome = Invoke-XdrPhoneSignInSasAuthentication -Username $Username -AuthState $fidoBootstrap.AuthState -Session $session -Deadline $deadline -BootstrapNumberCode $numberCode
        $currentCookie = Get-XdrBestEstsCookieValue -Session $session
        if ($currentCookie) {
            return $currentCookie
        }

        if ($sasOutcome.Outcome.AuthState -and $sasOutcome.Outcome.AuthState.sErrorCode) {
            throw "Phone sign-in failed with error $($sasOutcome.Outcome.AuthState.sErrorCode): $($sasOutcome.Outcome.AuthState.sErrTxt)"
        }

        throw 'Phone sign-in completed, but no ESTSAUTH cookie was captured.'
    }

    $resumeHeaders = Get-XdrPhoneSignInBrowserHeaderSet `
        -Referer 'https://login.microsoft.com/' `
        -Accept 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' `
        -IncludeUpgradeInsecureRequests

    $resumeResponse = Invoke-XdrRedirectCapturingWebRequest -Uri $fidoBootstrap.ResumeUri -Method Get -Session $session -Headers $resumeHeaders
    $resumeOutcome = Resolve-XdrAuthenticationResponse -Response $resumeResponse -Session $session
    $currentAuthState = $resumeOutcome.AuthState
    if (-not $currentAuthState) {
        throw 'Phone sign-in did not return a usable RemoteNGC state after the resume step.'
    }

    if (Test-XdrPhoneSignInSasReady -AuthState $currentAuthState) {
        $sasOutcome = Invoke-XdrPhoneSignInSasAuthentication -Username $Username -AuthState $currentAuthState -Session $session -Deadline $deadline -BootstrapNumberCode $numberCode
        $currentCookie = Get-XdrBestEstsCookieValue -Session $session
        if ($currentCookie) {
            return $currentCookie
        }

        if ($sasOutcome.Outcome.AuthState -and $sasOutcome.Outcome.AuthState.sErrorCode) {
            throw "Phone sign-in failed with error $($sasOutcome.Outcome.AuthState.sErrorCode): $($sasOutcome.Outcome.AuthState.sErrTxt)"
        }

        throw 'Phone sign-in completed, but no ESTSAUTH cookie was captured.'
    }

    if (Test-XdrPhoneSignInNativeBridgeFlow -AuthState $fidoBootstrap.AuthState) {
        throw "Phone sign-in reached the login.microsoft.com FIDO/passkey interstitial, but that branch requires the browser-native passkey/Auth App bridge before the resume URL becomes inline PhoneAppNotification. Use Connect-XdrByBrowser for this account or tenant."
    }

    $supportedMethods = @()
    if ($currentAuthState.arrUserProofs) {
        $supportedMethods = @(Get-XdrSupportedMfaOption -AuthState $currentAuthState)
    }

    $offeredMethods = @($currentAuthState.arrUserProofs | ForEach-Object authMethodId | Where-Object { $_ } | Sort-Object -Unique)
    $offeredMethodsText = if ($offeredMethods) { $offeredMethods -join ', ' } else { 'none returned by service' }
    $supportedMethodsText = if ($supportedMethods) { ($supportedMethods | ForEach-Object AuthMethodId) -join ', ' } else { 'none' }

    throw "Phone sign-in did not transition into inline Authenticator approval after the resume step. Resume page '$($currentAuthState.pgid)' exposed supported inline methods '$supportedMethodsText' and offered methods '$offeredMethodsText'."
}