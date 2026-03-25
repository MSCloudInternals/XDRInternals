#region Private Helper Functions

function Get-XdrTotpCode {
    <#
    .SYNOPSIS
        Computes a TOTP code from a base32-encoded secret.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Secret,
        [int]$Digits = 6,
        [int]$Period = 30
    )

    # Decode base32
    $base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $cleanSecret = $Secret.ToUpper().TrimEnd('=') -replace '\s', ''
    $bits = ""
    foreach ($c in $cleanSecret.ToCharArray()) {
        $idx = $base32Chars.IndexOf($c)
        if ($idx -lt 0) { throw "Invalid base32 character: $c" }
        $bits += [Convert]::ToString($idx, 2).PadLeft(5, '0')
    }
    $keyBytes = [byte[]]::new([Math]::Floor($bits.Length / 8))
    for ($i = 0; $i -lt $keyBytes.Length; $i++) {
        $keyBytes[$i] = [Convert]::ToByte($bits.Substring($i * 8, 8), 2)
    }

    # Time counter
    $epoch = [long][Math]::Floor(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) / $Period)
    $counterBytes = [BitConverter]::GetBytes($epoch)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($counterBytes) }

    # HMAC-SHA1
    $hmac = New-Object System.Security.Cryptography.HMACSHA1(, $keyBytes)
    try {
        $hash = $hmac.ComputeHash($counterBytes)
    } finally {
        $hmac.Dispose()
    }

    # Dynamic truncation
    $offset = $hash[$hash.Length - 1] -band 0x0F
    $code = (($hash[$offset] -band 0x7F) -shl 24) -bor
    ($hash[$offset + 1] -shl 16) -bor
    ($hash[$offset + 2] -shl 8) -bor
    $hash[$offset + 3]

    return ($code % [Math]::Pow(10, $Digits)).ToString().PadLeft($Digits, '0')
}

function Get-XdrAuthDebugHeaderMap {
    param($Headers)

    $result = [ordered]@{}
    if (-not $Headers) {
        return $result
    }

    foreach ($key in $Headers.Keys) {
        $value = $Headers[$key]
        if ($value -is [System.Array]) {
            $result[$key] = @($value)
        } else {
            $result[$key] = [string]$value
        }
    }

    return $result
}

function Get-XdrAuthDebugCookieSnapshot {
    param(
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )

    $domains = @('https://login.microsoftonline.com', 'https://security.microsoft.com')
    $result = [ordered]@{}

    foreach ($domain in $domains) {
        $cookies = @($Session.Cookies.GetCookies($domain))
        $result[$domain] = @(
            foreach ($cookie in $cookies) {
                [pscustomobject]@{
                    Name     = $cookie.Name
                    Value    = $cookie.Value
                    Domain   = $cookie.Domain
                    Path     = $cookie.Path
                    Secure   = $cookie.Secure
                    HttpOnly = $cookie.HttpOnly
                    Expired  = $cookie.Expired
                }
            }
        )
    }

    return $result
}

function Get-XdrAuthDebugResponse {
    param($Response)

    if (-not $Response) {
        return $null
    }

    $statusCode = $null
    if ($Response.StatusCode) {
        $statusCode = [int]$Response.StatusCode
    } elseif ($Response.BaseResponse -and $Response.BaseResponse.StatusCode) {
        $statusCode = [int]$Response.BaseResponse.StatusCode
    }

    $responseUri = $null
    if ($Response.BaseResponse -and $Response.BaseResponse.ResponseUri) {
        $responseUri = [string]$Response.BaseResponse.ResponseUri
    }

    return [ordered]@{
        StatusCode  = $statusCode
        ResponseUri = $responseUri
        Headers     = Get-XdrAuthDebugHeaderMap -Headers $(if ($Response.Headers) { $Response.Headers } elseif ($Response.BaseResponse) { $Response.BaseResponse.Headers } else { $null })
        Content     = $Response.Content
    }
}

function Get-XdrAuthDebugInterestingFieldSet {
    param($ParsedState)

    if (-not $ParsedState) {
        return $null
    }

    $result = [ordered]@{}
    $fieldNames = @(
        'pgid', 'sFT', 'canary', 'sCtx', 'correlationId', 'sessionId',
        'sCrossDomainCanary', 'urlPost', 'urlLogin', 'urlPostAad', 'urlPostMsa',
        'urlResume', 'urlRefresh', 'sErrorCode', 'sErrTxt'
    )

    foreach ($fieldName in $fieldNames) {
        if ($null -ne $ParsedState.$fieldName) {
            $result[$fieldName] = $ParsedState.$fieldName
        }
    }

    if ($null -ne $ParsedState.oGetCredTypeResult -and $null -ne $ParsedState.oGetCredTypeResult.FlowToken) {
        $result['oGetCredTypeResult.FlowToken'] = $ParsedState.oGetCredTypeResult.FlowToken
    }

    if ($null -ne $ParsedState.arrSessions) {
        $result['arrSessions'] = @(
            foreach ($sessionInfo in @($ParsedState.arrSessions)) {
                [pscustomobject]@{
                    id = $sessionInfo.id
                }
            }
        )
    }

    return $result
}

function Test-XdrMfaAuthSucceeded {
    param($Response)

    if (-not $Response) {
        return $false
    }

    if ($Response.ResultValue -eq 'AuthenticationSucceeded') {
        return $true
    }

    if ($Response.Success -eq $true -and $Response.ResultValue -eq 'Success') {
        return $true
    }

    return $false
}

function Get-XdrEstsApiHeaderSet {
    param($AuthState)

    $headers = @{}
    if (-not $AuthState) {
        return $headers
    }

    if ($AuthState.canary) {
        $headers['canary'] = [string]$AuthState.canary
    }

    if ($AuthState.correlationId) {
        $headers['client-request-id'] = [string]$AuthState.correlationId
    }

    if ($null -ne $AuthState.hpgid) {
        $headers['hpgid'] = [string]$AuthState.hpgid
    }

    if ($null -ne $AuthState.hpgact) {
        $headers['hpgact'] = [string]$AuthState.hpgact
    }

    $headers['Accept'] = 'application/json'
    $headers['X-Requested-With'] = 'XMLHttpRequest'

    return $headers
}

function Test-XdrProcessAuthRetryableError {
    param($ParsedState)

    if (-not $ParsedState) {
        return $false
    }

    if ($ParsedState.iErrorCode -notin @(90014, 9000410)) {
        return $false
    }

    $message = [string]$ParsedState.strServiceExceptionMessage
    return (
        $message -match "required field .*request.* missing" -or
        $message -match 'Malformed JSON'
    )
}

function Get-XdrProcessAuthRequestBody {
    param(
        [Parameter(Mandatory)]
        [string]$SelectedMethod,
        [Parameter(Mandatory)]
        [string]$Username,
        [Parameter(Mandatory)]
        [string]$ProcessRequest,
        [Parameter(Mandatory)]
        $BeginAuth,
        [Parameter(Mandatory)]
        $AuthState,
        [Nullable[long]]$MfaLastPollStart,
        [Nullable[long]]$MfaLastPollEnd
    )

    if ($SelectedMethod -eq 'PhoneAppNotification') {
        $body = [ordered]@{
            type               = 22
            request            = $ProcessRequest
            mfaAuthMethod      = $SelectedMethod
            login              = $Username
            flowToken          = $BeginAuth.FlowToken
            hpgrequestid       = $AuthState.correlationId
            sacxt              = ''
            hideSmsInMfaProofs = 'false'
            canary             = $AuthState.canary
        }

        if ($null -ne $MfaLastPollStart) {
            $body['mfaLastPollStart'] = [string]$MfaLastPollStart
        }

        if ($null -ne $MfaLastPollEnd) {
            $body['mfaLastPollEnd'] = [string]$MfaLastPollEnd
        }

        if ($null -ne $AuthState.i19) {
            $body['i19'] = [string]$AuthState.i19
        }

        return $body
    }

    return @{
        type      = 22
        FlowToken = $BeginAuth.FlowToken
        request   = $ProcessRequest
        ctx       = $BeginAuth.Ctx
    } | ConvertTo-Json
}

function Save-XdrAuthDebugRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Private helper that writes opt-in authentication diagnostics to disk.')]
    param(
        [Parameter(Mandatory)]
        [string]$Directory,
        [Parameter(Mandatory)]
        [string]$Stage,
        [string]$Method,
        [string]$Uri,
        $RequestBody,
        $Response,
        $ParsedState,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $Extra
    )

    if (-not (Test-Path $Directory)) {
        $null = New-Item -ItemType Directory -Path $Directory -Force
    }

    $safeStage = ($Stage -replace '[^A-Za-z0-9._-]', '_')
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
    $filePath = Join-Path $Directory "$timestamp-$safeStage.json"

    $payload = [ordered]@{
        Timestamp   = (Get-Date).ToString('o')
        Stage       = $Stage
        Method      = $Method
        Uri         = $Uri
        RequestBody = $RequestBody
        Response    = Get-XdrAuthDebugResponse -Response $Response
        ParsedState = $ParsedState
        Interesting = Get-XdrAuthDebugInterestingFieldSet -ParsedState $ParsedState
        Extra       = $Extra
        Cookies     = if ($Session) { Get-XdrAuthDebugCookieSnapshot -Session $Session } else { $null }
    }

    $payload | ConvertTo-Json -Depth 20 | Set-Content -Path $filePath -Encoding UTF8
}

function Get-XdrAuthStateFromResponse {
    param($Response)

    if ($null -eq $Response -or [string]::IsNullOrWhiteSpace($Response.Content)) {
        return $null
    }

    if ($Response.Content -match '{(.*)}') {
        try {
            return $Matches[0] | ConvertFrom-Json
        } catch {
            return $null
        }
    }

    return $null
}

function Get-XdrResponseLocation {
    param($Response)

    if ($null -eq $Response) {
        return $null
    }

    if ($Response.Headers -and $Response.Headers.Location) {
        return [string]$Response.Headers.Location
    }

    if ($Response.BaseResponse -and $Response.BaseResponse.Headers -and $Response.BaseResponse.Headers['Location']) {
        return [string]$Response.BaseResponse.Headers['Location']
    }

    return $null
}

function Invoke-XdrRedirectCapturingWebRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [string]$Method,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        $Body,
        $Headers,
        [string]$ContentType
    )

    $requestParams = @{
        Uri                = $Uri
        Method             = $Method
        UseBasicParsing    = $true
        SkipHttpErrorCheck = $true
        MaximumRedirection = 0
        Verbose            = $false
        ErrorAction        = 'SilentlyContinue'
    }

    if ($PSBoundParameters.ContainsKey('Session')) {
        $requestParams['WebSession'] = $Session
    }

    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $requestParams['Body'] = $Body
    }

    if ($PSBoundParameters.ContainsKey('Headers') -and $null -ne $Headers) {
        $requestParams['Headers'] = $Headers
    }

    if ($PSBoundParameters.ContainsKey('ContentType') -and -not [string]::IsNullOrWhiteSpace($ContentType)) {
        $requestParams['ContentType'] = $ContentType
    }

    $redirectErrors = @()
    $response = Invoke-WebRequest @requestParams -ErrorVariable +redirectErrors
    if ($null -ne $response) {
        return $response
    }

    foreach ($errorRecord in $redirectErrors) {
        $redirectResponse = if ($errorRecord.Exception) { $errorRecord.Exception.Response } else { $null }
        if ($null -ne $redirectResponse -and (Get-XdrResponseLocation -Response $redirectResponse)) {
            return $redirectResponse
        }

        if ($errorRecord.Exception -and $errorRecord.Exception.Message -match 'maximum redirection count has been exceeded') {
            Write-Verbose "Captured redirect response from $Method $Uri after PowerShell reported the redirection limit."
            continue
        }

        throw $errorRecord
    }

    throw "Web request to '$Uri' did not return a usable response."
}

function Test-XdrSecurityPortalFormPostResponse {
    param($Response)

    if ($null -eq $Response -or $null -eq $Response.InputFields) {
        return $false
    }

    $requiredFields = @('code', 'id_token', 'state', 'session_state', 'correlation_id')
    $inputNames = @($Response.InputFields | Select-Object -ExpandProperty name)

    foreach ($field in $requiredFields) {
        if ($inputNames -notcontains $field) {
            return $false
        }
    }

    return $true
}

function Complete-XdrSecurityPortalFormPost {
    param(
        $Response,
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )

    $requiredFields = @('code', 'id_token', 'state', 'session_state', 'correlation_id')
    $body = @{}
    foreach ($field in $requiredFields) {
        $body[$field] = $Response.InputFields | Where-Object name -EQ $field | Select-Object -ExpandProperty value
    }

    $postUri = if ($Response.BaseResponse -and $Response.BaseResponse.ResponseUri) {
        $Response.BaseResponse.ResponseUri.GetLeftPart([System.UriPartial]::Path)
    } else {
        'https://security.microsoft.com/'
    }

    Write-Verbose "Completing security.microsoft.com form POST at $postUri"
    return Invoke-WebRequest -UseBasicParsing -Method Post -Uri $postUri -Body $body -WebSession $Session -MaximumRedirection 10 -SkipHttpErrorCheck -Verbose:$false
}

function Resolve-XdrAuthenticationResponse {
    param(
        $Response,
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )

    $currentResponse = $Response

    for ($redirectCount = 0; $redirectCount -lt 5 -and $null -ne $currentResponse; $redirectCount++) {
        $authState = Get-XdrAuthStateFromResponse -Response $currentResponse
        if ($authState) {
            return [pscustomobject]@{
                AuthState = $authState
                Response  = $currentResponse
            }
        }

        if (Test-XdrSecurityPortalFormPostResponse -Response $currentResponse) {
            $currentResponse = Complete-XdrSecurityPortalFormPost -Response $currentResponse -Session $Session
            continue
        }

        $location = Get-XdrResponseLocation -Response $currentResponse
        if (-not $location) {
            break
        }

        $baseUri = if ($currentResponse.BaseResponse -and $currentResponse.BaseResponse.ResponseUri) {
            $currentResponse.BaseResponse.ResponseUri
        } else {
            [uri]'https://login.microsoftonline.com/'
        }

        $nextUri = [uri]::new($baseUri, $location)
        if ($nextUri.Scheme -notin @('http', 'https')) {
            Write-Verbose "Authentication redirect reached native callback URI $nextUri; stopping redirect resolution."
            break
        }

        Write-Verbose "Following authentication redirect to $nextUri"
        $currentResponse = Invoke-WebRequest -UseBasicParsing -Method Get -Uri $nextUri -WebSession $Session -MaximumRedirection 10 -SkipHttpErrorCheck -Verbose:$false
    }

    return [pscustomobject]@{
        AuthState = (Get-XdrAuthStateFromResponse -Response $currentResponse)
        Response  = $currentResponse
    }
}

function Get-XdrSupportedMfaOption {
    param($AuthState)

    $descriptions = @{
        PhoneAppOTP          = 'Authenticator app code'
        PhoneAppNotification = 'Authenticator app approval'
        OneWaySMS            = 'Text message code'
    }

    $supportedMethods = [ordered]@{}
    foreach ($proof in @($AuthState.arrUserProofs)) {
        if (-not $proof.authMethodId -or -not $descriptions.ContainsKey($proof.authMethodId)) {
            continue
        }

        if ($supportedMethods.Contains($proof.authMethodId)) {
            continue
        }

        $supportedMethods[$proof.authMethodId] = [pscustomobject]@{
            AuthMethodId = $proof.authMethodId
            Description  = $descriptions[$proof.authMethodId]
            IsDefault    = [bool]$proof.isDefault
        }
    }

    return @(
        $supportedMethods.Values | Sort-Object -Property @(
            @{ Expression = { if ($_.IsDefault) { 0 } else { 1 } } },
            @{ Expression = { $_.AuthMethodId } }
        )
    )
}

function Select-XdrMfaMethod {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    param(
        [Parameter(Mandatory)]
        [object[]]$SupportedMethods,
        [string]$PreferredMethod,
        [string]$TotpSecret
    )

    $supportedMethodIds = @($SupportedMethods | ForEach-Object AuthMethodId)

    if ($PreferredMethod) {
        if ($supportedMethodIds -contains $PreferredMethod) {
            return $PreferredMethod
        }

        throw "Requested MFA method '$PreferredMethod' is not offered for this sign-in. Supported methods: $($supportedMethodIds -join ', ')."
    }

    if ($TotpSecret -and $supportedMethodIds -contains 'PhoneAppOTP') {
        return 'PhoneAppOTP'
    }

    if ($SupportedMethods.Count -eq 1) {
        return $SupportedMethods[0].AuthMethodId
    }

    Write-Host 'Available MFA methods:'
    for ($i = 0; $i -lt $SupportedMethods.Count; $i++) {
        $method = $SupportedMethods[$i]
        $defaultSuffix = if ($method.IsDefault) { ' [default]' } else { '' }
        Write-Host "  [$($i + 1)] $($method.Description) ($($method.AuthMethodId))$defaultSuffix"
    }

    while ($true) {
        $selection = Read-Host "Select MFA method [1-$($SupportedMethods.Count)]"
        $index = 0
        if ([int]::TryParse($selection, [ref]$index) -and $index -ge 1 -and $index -le $SupportedMethods.Count) {
            return $SupportedMethods[$index - 1].AuthMethodId
        }

        Write-Host 'Invalid selection. Try again.'
    }
}

#endregion

function Invoke-XdrCredentialAuthentication {
    <#
    .SYNOPSIS
        Performs username/password + optional TOTP authentication against Entra ID and returns the ESTSAUTH cookie value.

    .DESCRIPTION
        Implements the full Entra ID web login flow programmatically: submits credentials to the
        /authorize endpoint, handles MFA challenges via the SAS (Server Authentication State) endpoints,
        and processes interrupt pages (KMSI, CMSI, ConvergedSignIn).

        This is an internal function used by Connect-XdrByCredential.

        Supported MFA methods:
          - PhoneAppOTP: Authenticator app TOTP code (computed automatically from -TotpSecret)
          - PhoneAppNotification: Push notification (polls for user approval, displays number match)
          - OneWaySMS: SMS code (prompts user to enter code from phone)

    .PARAMETER Username
        The user principal name (e.g., admin@contoso.com).

    .PARAMETER Password
        The password as a SecureString. The plain-text value is materialized only
        immediately before it is submitted to the Entra ID sign-in form.

    .PARAMETER TotpSecret
        Base32-encoded TOTP secret for automatic MFA code generation.
        This is the secret from the QR code when setting up Microsoft Authenticator
        (otpauth://totp/...?secret=JBSWY3DPEHPK3PXP).
        If not provided and MFA is required, the function will attempt push notification
        or prompt for a code.

    .PARAMETER MfaMethod
        Preferred MFA method. Valid values: PhoneAppOTP, PhoneAppNotification, OneWaySMS.
        If not specified, PhoneAppOTP is auto-selected only when -TotpSecret is provided and
        that method is actually offered. Otherwise, the function chooses the only supported inline
        method or prompts you when multiple supported inline methods are available.

    .PARAMETER UserAgent
        User-Agent string for HTTP requests.

    .PARAMETER DebugCaptureDirectory
        Optional directory for writing detailed credential-auth debug captures.
        When provided, request bodies, response bodies, headers, parsed state, and cookie snapshots
        are written under the specified path for each major authentication stage.

    .EXAMPLE
        $password = ConvertTo-SecureString "MyPassword" -AsPlainText -Force
        Invoke-XdrCredentialAuthentication -Username "admin@contoso.com" -Password $password -TotpSecret "JBSWY3DPEHPK3PXP"

        Authenticates with a SecureString password and returns the ESTSAUTH cookie value.

    .OUTPUTS
        String - the ESTSAUTH cookie value suitable for passing to Connect-XdrByEstsCookie.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        [SecureString]$Password,

        [string]$TotpSecret,

        [ValidateSet('PhoneAppOTP', 'PhoneAppNotification', 'OneWaySMS')]
        [string]$MfaMethod,

        [string]$DebugCaptureDirectory,

        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
    )

    $captureDirectory = $null
    if ($DebugCaptureDirectory) {
        $captureDirectory = Join-Path $DebugCaptureDirectory ("xdr-credential-auth-" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Write-Verbose "Credential auth debug capture enabled: $captureDirectory"
    }

    #region Establish session and initiate authentication flow
    $authUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize" +
    "?response_type=code" +
    "&redirect_uri=msauth.com.msauth.unsignedapp://auth" +
    "&scope=https://graph.microsoft.com/.default" +
    "&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46" +
    "&sso_reload=true" +
    "&login_hint=$([uri]::EscapeDataString($Username))"

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = $UserAgent

    Write-Verbose "Initiating authentication flow for $Username..."
    $initialResponse = Invoke-WebRequest -UseBasicParsing -Uri $authUrl -Method Get -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false

    $sessionInfo = Get-XdrAuthStateFromResponse -Response $initialResponse
    if ($captureDirectory) {
        Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '01-initial-authorize' -Method 'GET' -Uri $authUrl -Response $initialResponse -ParsedState $sessionInfo -Session $session
    }
    if (-not $sessionInfo) {
        throw "Unexpected response from Entra ID authentication endpoint."
    }

    if (-not $sessionInfo.urlPost) {
        if ($sessionInfo.sErrorCode) {
            throw "Authentication failed with error $($sessionInfo.sErrorCode): $($sessionInfo.sErrTxt)"
        }
        throw "Unexpected response: no urlPost in login page configuration."
    }
    Write-Verbose "Login page loaded (pgid: $($sessionInfo.pgid))"
    #endregion

    #region Submit credentials (type=11 = password)
    Write-Host "Submitting credentials for $Username..."
    $passwordHandle = [IntPtr]::Zero
    $plainPassword = $null

    try {
        $passwordHandle = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordHandle)

        $credBody = @{
            login        = $Username
            loginfmt     = $Username
            passwd       = $plainPassword
            type         = 11
            ps           = 2
            LoginOptions = 3
            flowToken    = $sessionInfo.sFT
            ctx          = $sessionInfo.sCtx
            canary       = $sessionInfo.canary
            hpgrequestid = $sessionInfo.correlationId
        }

        $credResponse = Invoke-WebRequest -UseBasicParsing -Method Post `
            -Uri $sessionInfo.urlPost `
            -Body $credBody `
            -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false
    } finally {
        $plainPassword = $null
        if ($passwordHandle -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordHandle)
        }
    }

    if ($captureDirectory) {
        Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '02-password-submit' -Method 'POST' -Uri $sessionInfo.urlPost -RequestBody $credBody -Response $credResponse -ParsedState (Get-XdrAuthStateFromResponse -Response $credResponse) -Session $session
    }

    $credOutcome = Resolve-XdrAuthenticationResponse -Response $credResponse -Session $session
    $authState = $credOutcome.AuthState
    if ($captureDirectory) {
        Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '03-password-resolved' -Method 'POST' -Uri $sessionInfo.urlPost -RequestBody $credBody -Response $credOutcome.Response -ParsedState $authState -Session $session
    }
    if (-not $authState) {
        throw "Unexpected response after credential submission."
    }

    # Check for credential errors
    if ($authState.sErrorCode) {
        $errorMessages = @{
            '50126' = "Invalid username or password."
            '50053' = "Account is locked. Too many failed sign-in attempts."
            '50057' = "Account is disabled."
            '50055' = "Password has expired."
            '50056' = "Invalid or null password."
            '53003' = "Blocked by Conditional Access policy."
            '50034' = "User account not found."
        }
        $msg = $errorMessages[$authState.sErrorCode]
        if (-not $msg) { $msg = $authState.sErrTxt }
        throw "Authentication failed ($($authState.sErrorCode)): $msg"
    }

    Write-Verbose "Credential submission succeeded (pgid: $($authState.pgid))"
    #endregion

    #region Handle MFA challenge (ConvergedTFA)
    if ($authState.pgid -eq 'ConvergedTFA') {
        Write-Host "MFA required."
        $sasHeaders = Get-XdrEstsApiHeaderSet -AuthState $authState

        # Determine MFA method
        $supportedMethods = Get-XdrSupportedMfaOption -AuthState $authState
        if (-not $supportedMethods) {
            $offeredMethods = @($authState.arrUserProofs | ForEach-Object authMethodId | Sort-Object -Unique)
            $offeredMethodsText = if ($offeredMethods) { $offeredMethods -join ', ' } else { 'none returned by service' }
            throw "No supported inline MFA methods were offered for this sign-in. Offered methods: $offeredMethodsText. Use Connect-XdrBySoftwarePasskey for passkey-based methods."
        }

        $selectedMethod = Select-XdrMfaMethod -SupportedMethods $supportedMethods -PreferredMethod $MfaMethod -TotpSecret $TotpSecret

        Write-Host "Using MFA method: $selectedMethod"
        Write-Verbose "Available methods: $(($supportedMethods | ForEach-Object { $_.AuthMethodId }) -join ', ')"

        # BeginAuth
        $beginBody = @{
            AuthMethodId = $selectedMethod
            Method       = "BeginAuth"
            ctx          = $authState.sCtx
            flowToken    = $authState.sFT
        } | ConvertTo-Json

        Write-Verbose "Calling SAS/BeginAuth..."
        $beginAuth = Invoke-RestMethod -Method Post `
            -Uri "https://login.microsoftonline.com/common/SAS/BeginAuth" `
            -Body $beginBody -ContentType "application/json" `
            -Headers $sasHeaders `
            -WebSession $session -Verbose:$false

        if ($captureDirectory) {
            Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '04-mfa-beginauth' -Method 'POST' -Uri 'https://login.microsoftonline.com/common/SAS/BeginAuth' -RequestBody ($beginBody | ConvertFrom-Json) -ParsedState $beginAuth -Session $session
        }

        $isPushDuplicateBeginAuth = (
            $selectedMethod -eq 'PhoneAppNotification' -and
            $beginAuth -and
            $beginAuth.ErrCode -eq 500121 -and
            $beginAuth.ResultValue -eq 'UserAuthFailedDuplicateRequest' -and
            $beginAuth.FlowToken -and
            $beginAuth.Ctx
        )

        if ($isPushDuplicateBeginAuth) {
            Write-Verbose 'BeginAuth returned UserAuthFailedDuplicateRequest for push MFA. Continuing with polling using the returned continuation state.'
            if (-not $beginAuth.SessionId -or $beginAuth.SessionId -eq '00000000-0000-0000-0000-000000000000') {
                $beginAuth.SessionId = $authState.sessionId
            }
        } elseif (-not $beginAuth.Success -and $beginAuth.ErrCode -ne 0) {
            throw "MFA BeginAuth failed (ErrCode: $($beginAuth.ErrCode)): $($beginAuth.Message)"
        }

        Write-Verbose "BeginAuth response: Success=$($beginAuth.Success), ResultValue=$($beginAuth.ResultValue)"

        # Get the verification code based on method
        $verificationCode = $null

        switch ($selectedMethod) {
            'PhoneAppOTP' {
                if ($TotpSecret) {
                    $verificationCode = Get-XdrTotpCode -Secret $TotpSecret
                    Write-Verbose "Computed TOTP code: $verificationCode"
                } else {
                    Write-Host "Enter the code from your authenticator app:"
                    $verificationCode = Read-Host "Code"
                }
            }
            'OneWaySMS' {
                Write-Host "An SMS has been sent to your phone."
                Write-Host "Enter the verification code:"
                $verificationCode = Read-Host "Code"
            }
            'PhoneAppNotification' {
                # Push notification - poll for approval
                $entropy = $beginAuth.Entropy
                if ($entropy -and $entropy -gt 0) {
                    Write-Host "Approve the sign-in request in your Authenticator app."
                    Write-Host "Number to match: $entropy" -ForegroundColor Yellow
                } else {
                    Write-Host "Approve the sign-in request in your Authenticator app."
                }

                # Poll EndAuth until approved or denied
                $pollCount = 0
                $maxPolls = 60  # 60 * 3s = 180 seconds max
                $pushApproved = $false

                $useGetForPushPolling = [bool]$authState.fSasEndAuthPostToGetSwitch
                $lastPollStart = $null
                $lastPollEnd = $null
                $processAuthPollStart = $null
                $processAuthPollEnd = $null

                while ($pollCount -lt $maxPolls) {
                    $pollCount++
                    Start-Sleep -Seconds 3

                    $pollStarted = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

                    if ($useGetForPushPolling) {
                        $pollParams = @(
                            "authMethodId=$([uri]::EscapeDataString($selectedMethod))",
                            "pollCount=$pollCount"
                        )
                        if ($lastPollStart) {
                            $pollParams += "lastPollStart=$lastPollStart"
                        }
                        if ($lastPollEnd) {
                            $pollParams += "lastPollEnd=$lastPollEnd"
                        }

                        $pollUri = "https://login.microsoftonline.com/common/SAS/EndAuth?" + ($pollParams -join '&')
                        $pollBody = $null
                        $pollResult = Invoke-RestMethod -Method Get `
                            -Uri $pollUri `
                            -WebSession $session -Verbose:$false

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
                                AuthMethodId = $selectedMethod
                                Method       = "EndAuth"
                                SessionId    = $beginAuth.SessionId
                                FlowToken    = $beginAuth.FlowToken
                                Ctx          = $beginAuth.Ctx
                                PollCount    = $pollCount
                            } | ConvertTo-Json

                            $pollUri = "https://login.microsoftonline.com/common/SAS/EndAuth"
                            $pollResult = Invoke-RestMethod -Method Post `
                                -Uri $pollUri `
                                -Body $pollBody -ContentType "application/json" `
                                -Headers $sasHeaders `
                                -WebSession $session -Verbose:$false
                        }
                    } else {
                        $pollBody = @{
                            AuthMethodId = $selectedMethod
                            Method       = "EndAuth"
                            SessionId    = $beginAuth.SessionId
                            FlowToken    = $beginAuth.FlowToken
                            Ctx          = $beginAuth.Ctx
                            PollCount    = $pollCount
                        } | ConvertTo-Json

                        $pollUri = "https://login.microsoftonline.com/common/SAS/EndAuth"
                        $pollResult = Invoke-RestMethod -Method Post `
                            -Uri $pollUri `
                            -Body $pollBody -ContentType "application/json" `
                            -Headers $sasHeaders `
                            -WebSession $session -Verbose:$false
                    }

                    $pollEnded = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                    if ($null -eq $processAuthPollStart) {
                        $processAuthPollStart = $pollStarted
                        $processAuthPollEnd = $pollEnded
                    }
                    $lastPollStart = $pollStarted
                    $lastPollEnd = $pollEnded

                    if ($captureDirectory) {
                        $pollRequestBody = if ($pollBody) { $pollBody | ConvertFrom-Json } else { [ordered]@{ AuthMethodId = $selectedMethod; PollCount = $pollCount; LastPollStart = $lastPollStart; LastPollEnd = $lastPollEnd } }
                        $pollMethod = if ($useGetForPushPolling) { 'GET' } else { 'POST' }
                        Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage ("05-mfa-poll-" + $pollCount) -Method $pollMethod -Uri $pollUri -RequestBody $pollRequestBody -ParsedState $pollResult -Session $session
                    }

                    Write-Verbose "Poll $pollCount : Success=$($pollResult.Success) ResultValue=$($pollResult.ResultValue)"

                    if (Test-XdrMfaAuthSucceeded -Response $pollResult) {
                        $pushApproved = $true
                        $beginAuth = $pollResult  # Carry forward for ProcessAuth
                        break
                    } elseif ($pollResult.ResultValue -ne 'AuthenticationPending') {
                        throw "Push notification denied or failed: $($pollResult.ResultValue) - $($pollResult.Message)"
                    }

                    if (-not $pollResult.Retry) {
                        throw "Push notification timed out. Retry is false."
                    }
                }

                if (-not $pushApproved) {
                    throw "Push notification timed out after $($pollCount * 3) seconds."
                }

                Write-Host "Push notification approved."
            }
        }

        # EndAuth - submit verification code (for OTP and SMS methods)
        if ($selectedMethod -ne 'PhoneAppNotification') {
            if (-not $verificationCode) {
                throw "No verification code provided for MFA method $selectedMethod."
            }

            $endBody = @{
                AuthMethodId       = $selectedMethod
                Method             = "EndAuth"
                SessionId          = $beginAuth.SessionId
                FlowToken          = $beginAuth.FlowToken
                Ctx                = $beginAuth.Ctx
                AdditionalAuthData = $verificationCode
                PollCount          = 1
            } | ConvertTo-Json

            Write-Verbose "Calling SAS/EndAuth with verification code..."
            $endAuth = Invoke-RestMethod -Method Post `
                -Uri "https://login.microsoftonline.com/common/SAS/EndAuth" `
                -Body $endBody -ContentType "application/json" `
                -Headers $sasHeaders `
                -WebSession $session -Verbose:$false

            if ($captureDirectory) {
                Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '06-mfa-endauth' -Method 'POST' -Uri 'https://login.microsoftonline.com/common/SAS/EndAuth' -RequestBody ($endBody | ConvertFrom-Json) -ParsedState $endAuth -Session $session
            }

            if (-not (Test-XdrMfaAuthSucceeded -Response $endAuth)) {
                $errDetail = if ($endAuth.Message) { $endAuth.Message } else { $endAuth.ResultValue }
                throw "MFA verification failed: $errDetail"
            }

            Write-Host "MFA verification succeeded."
            $beginAuth = $endAuth  # Carry forward FlowToken for ProcessAuth
        }

        # ProcessAuth - finalize MFA and continue the login flow
        $processRequest = if ($selectedMethod -eq 'PhoneAppNotification' -and $beginAuth.Ctx) {
            $beginAuth.Ctx
        } elseif ($beginAuth.MobileAppAuthDetails -and $beginAuth.MobileAppAuthDetails.AuthAppState) {
            $beginAuth.MobileAppAuthDetails.AuthAppState
        } elseif ($beginAuth.Ctx) {
            $beginAuth.Ctx
        } else {
            $authState.sCtx
        }

        $processBody = Get-XdrProcessAuthRequestBody `
            -SelectedMethod $selectedMethod `
            -Username $Username `
            -ProcessRequest $processRequest `
            -BeginAuth $beginAuth `
            -AuthState $authState `
            -MfaLastPollStart $processAuthPollStart `
            -MfaLastPollEnd $processAuthPollEnd

        $processBodyForDebug = if ($processBody -is [string]) {
            $processBody | ConvertFrom-Json
        } else {
            [pscustomobject]$processBody
        }

        $processContentType = if ($processBody -is [string]) {
            'application/json'
        } else {
            'application/x-www-form-urlencoded'
        }

        Write-Verbose "Calling SAS/ProcessAuth..."
        $processResponse = Invoke-XdrRedirectCapturingWebRequest `
            -Method Post `
            -Uri "https://login.microsoftonline.com/common/SAS/ProcessAuth" `
            -Body $processBody `
            -ContentType $processContentType `
            -Headers $sasHeaders `
            -Session $session

        $processResponseState = Get-XdrAuthStateFromResponse -Response $processResponse

        if (Test-XdrProcessAuthRetryableError -ParsedState $processResponseState) {
            $formProcessBody = [ordered]@{
                type         = 22
                request      = $processRequest
                flowToken    = $beginAuth.FlowToken
                canary       = $authState.canary
                hpgrequestid = $authState.correlationId
            }

            if ($selectedMethod -eq 'PhoneAppNotification') {
                $formProcessBody['mfaAuthMethod'] = $selectedMethod
                $formProcessBody['login'] = $Username
                $formProcessBody['sacxt'] = ''
                $formProcessBody['hideSmsInMfaProofs'] = 'false'
                if ($null -ne $processAuthPollStart) {
                    $formProcessBody['mfaLastPollStart'] = [string]$processAuthPollStart
                }
                if ($null -ne $processAuthPollEnd) {
                    $formProcessBody['mfaLastPollEnd'] = [string]$processAuthPollEnd
                }
                if ($null -ne $authState.i19) {
                    $formProcessBody['i19'] = [string]$authState.i19
                }
            } else {
                $formProcessBody['ctx'] = $beginAuth.Ctx
            }

            if ($captureDirectory) {
                Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '07a-mfa-processauth-json-retryable-error' -Method 'POST' -Uri 'https://login.microsoftonline.com/common/SAS/ProcessAuth' -RequestBody $processBodyForDebug -Response $processResponse -ParsedState $processResponseState -Session $session
            }

            Write-Verbose 'ProcessAuth returned a retryable request parsing error. Retrying with login-form style field names.'
            $processResponse = Invoke-XdrRedirectCapturingWebRequest `
                -Method Post `
                -Uri "https://login.microsoftonline.com/common/SAS/ProcessAuth" `
                -Body $formProcessBody `
                -ContentType 'application/x-www-form-urlencoded' `
                -Headers $sasHeaders `
                -Session $session

            $processBody = $formProcessBody
            $processBodyForDebug = [pscustomobject]$formProcessBody
            $processResponseState = Get-XdrAuthStateFromResponse -Response $processResponse
        }

        if ($captureDirectory) {
            Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '07-mfa-processauth-raw' -Method 'POST' -Uri 'https://login.microsoftonline.com/common/SAS/ProcessAuth' -RequestBody $processBodyForDebug -Response $processResponse -ParsedState $processResponseState -Session $session
        }

        $processOutcome = Resolve-XdrAuthenticationResponse -Response $processResponse -Session $session
        $authState = $processOutcome.AuthState

        if ($captureDirectory) {
            Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '08-mfa-processauth-resolved' -Method 'POST' -Uri 'https://login.microsoftonline.com/common/SAS/ProcessAuth' -RequestBody $processBodyForDebug -Response $processOutcome.Response -ParsedState $authState -Session $session
        }

        if ($authState) {
            Write-Verbose "ProcessAuth completed (pgid: $($authState.pgid))"
        } else {
            Write-Verbose 'ProcessAuth completed with a non-JSON terminal response.'
        }
    }

    # Handle ConvergedProofUpRedirect (MFA registration prompt - skip it)
    if ($authState -and $authState.pgid -eq 'ConvergedProofUpRedirect') {
        Write-Verbose "MFA registration prompt detected, attempting to skip..."
        if ($authState.iRemainingDaysToSkipMfaRegistration -and $authState.iRemainingDaysToSkipMfaRegistration -gt 0) {
            $skipBody = @{
                type      = 22
                FlowToken = $authState.sFT
                request   = $authState.sProofUpAuthState
                ctx       = $authState.sProofUpAuthState
            } | ConvertTo-Json
            $skipResponse = Invoke-XdrRedirectCapturingWebRequest `
                -Method Post `
                -Uri "https://login.microsoftonline.com/common/SAS/ProcessAuth" `
                -Body $skipBody `
                -ContentType "application/json" `
                -Headers (Get-XdrEstsApiHeaderSet -AuthState $authState) `
                -Session $session

            $skipResponseState = Get-XdrAuthStateFromResponse -Response $skipResponse

            if (Test-XdrProcessAuthRetryableError -ParsedState $skipResponseState) {
                $formSkipBody = @{
                    type         = 22
                    request      = $authState.sProofUpAuthState
                    flowToken    = $authState.sFT
                    ctx          = $authState.sProofUpAuthState
                    canary       = $authState.canary
                    hpgrequestid = $authState.correlationId
                }

                if ($captureDirectory) {
                    Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '09a-proofup-skip-json-retryable-error' -Method 'POST' -Uri 'https://login.microsoftonline.com/common/SAS/ProcessAuth' -RequestBody ($skipBody | ConvertFrom-Json) -Response $skipResponse -ParsedState $skipResponseState -Session $session
                }

                Write-Verbose 'Proof-up skip ProcessAuth returned a retryable request parsing error. Retrying with login-form style field names.'
                $skipResponse = Invoke-XdrRedirectCapturingWebRequest `
                    -Method Post `
                    -Uri "https://login.microsoftonline.com/common/SAS/ProcessAuth" `
                    -Body $formSkipBody `
                    -Session $session

                $skipBody = $formSkipBody | ConvertTo-Json
                $skipResponseState = Get-XdrAuthStateFromResponse -Response $skipResponse
            }

            if ($captureDirectory) {
                Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '09-proofup-skip-raw' -Method 'POST' -Uri 'https://login.microsoftonline.com/common/SAS/ProcessAuth' -RequestBody ($skipBody | ConvertFrom-Json) -Response $skipResponse -ParsedState $skipResponseState -Session $session
            }

            $skipOutcome = Resolve-XdrAuthenticationResponse -Response $skipResponse -Session $session
            $authState = $skipOutcome.AuthState

            if ($captureDirectory) {
                Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '10-proofup-skip-resolved' -Method 'POST' -Uri 'https://login.microsoftonline.com/common/SAS/ProcessAuth' -RequestBody ($skipBody | ConvertFrom-Json) -Response $skipOutcome.Response -ParsedState $authState -Session $session
            }
        } else {
            throw "MFA registration is required for this account and cannot be skipped."
        }
    }
    #endregion

    #region Handle interrupt pages (CmsiInterrupt, KmsiInterrupt, ConvergedSignIn)
    # This section is identical to the passkey flow interrupt handling
    $debug = $authState

    $interruptHandlers = @{
        "CmsiInterrupt"   = @{
            Uri    = "https://login.microsoftonline.com/appverify"
            Method = "Post"
            Body   = { @{
                    ContinueAuth    = "true"
                    i19             = Get-Random -Minimum 1000 -Maximum 9999
                    canary          = $debug.canary
                    iscsrfspeedbump = "false"
                    flowToken       = $debug.sFT
                    hpgrequestid    = $debug.correlationId
                    ctx             = $debug.sCtx
                } }
        }
        "KmsiInterrupt"   = @{
            Uri    = "https://login.microsoftonline.com/kmsi"
            Method = "Post"
            Body   = { @{
                    LoginOptions = 1
                    type         = 28
                    ctx          = $debug.sCtx
                    hpgrequestid = $debug.correlationId
                    flowToken    = $debug.sFT
                    canary       = $debug.canary
                    i19          = 4130
                } }
        }
        "ConvergedSignIn" = @{
            Uri    = { $sessionId = if ($null -ne $debug.arrSessions -and $null -ne $debug.arrSessions[0].id) { $debug.arrSessions[0].id } else { $debug.sessionId }; "$($debug.urlLogin)&sessionid=$sessionId" }
            Method = "Get"
        }
    }

    $loopCount = 0
    $lastPageId = $null
    $authFailed = $false

    while ($debug -and $debug.pgid -in $interruptHandlers.Keys) {
        $currentPageId = $debug.pgid
        if ($currentPageId -eq $lastPageId -or ++$loopCount -gt 10) {
            $authFailed = $true
            Write-Verbose "Stuck in interrupt loop (lastPageId: $lastPageId, currentPageId: $currentPageId, loopCount: $loopCount)"
            break
        }
        $lastPageId = $currentPageId
        $handler = $interruptHandlers[$currentPageId]
        Write-Verbose "Handling interrupt: $currentPageId"

        $reqParams = @{
            Uri                = if ($handler.Uri -is [scriptblock]) { & $handler.Uri } else { $handler.Uri }
            Method             = $handler.Method
            WebSession         = $session
            UseBasicParsing    = $true
            SkipHttpErrorCheck = $true
            MaximumRedirection = 10
            Verbose            = $false
        }
        if ($handler.Body) { $reqParams.Body = & $handler.Body }

        $respFinalize = Invoke-WebRequest @reqParams
        Start-Sleep -Milliseconds 300

        if ($captureDirectory) {
            Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage ("11-interrupt-" + $currentPageId) -Method $handler.Method -Uri $reqParams.Uri -RequestBody $reqParams.Body -Response $respFinalize -ParsedState (Get-XdrAuthStateFromResponse -Response $respFinalize) -Session $session
        }

        $interruptOutcome = Resolve-XdrAuthenticationResponse -Response $respFinalize -Session $session
        $debug = $interruptOutcome.AuthState
        if ($captureDirectory) {
            Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage ("12-interrupt-resolved-" + $currentPageId) -Method $handler.Method -Uri $reqParams.Uri -RequestBody $reqParams.Body -Response $interruptOutcome.Response -ParsedState $debug -Session $session
        }
        if (-not $debug -or -not $debug.pgid) {
            break
        }
    }

    if ($authFailed) {
        throw "Authentication failed: stuck in interrupt page loop. Verify credentials and MFA configuration."
    }
    #endregion

    #region Verify and return ESTSAUTH cookie
    $allCookies = $session.Cookies.GetCookies("https://login.microsoftonline.com")
    Write-Verbose "Cookies present: $($allCookies.Name -join ', ')"

    $estsCookies = $allCookies | Where-Object Name -Like "ESTS*"
    if (-not $estsCookies) {
        throw "Authentication flow completed but no ESTS authentication cookie was obtained. Verify username, password, and MFA configuration."
    }

    # Pick the longest cookie (ESTSAUTHPERSISTENT is preferred when available)
    $bestCookie = @(
        $allCookies | Where-Object Name -EQ "ESTSAUTH"
        $allCookies | Where-Object Name -EQ "ESTSAUTHPERSISTENT"
        $allCookies | Where-Object Name -EQ "ESTSAUTHLIGHT"
    ) | Where-Object { $_ } | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1

    if ($captureDirectory) {
        Save-XdrAuthDebugRecord -Directory $captureDirectory -Stage '13-final-cookies' -Method 'GET' -Uri 'https://login.microsoftonline.com' -ParsedState ([pscustomobject]@{ SelectedCookie = $bestCookie.Name; SelectedCookieLength = $bestCookie.Value.Length }) -Session $session -Extra ([pscustomobject]@{ AvailableEstsCookies = @($estsCookies | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Length = $_.Value.Length } }) })
    }

    Write-Verbose "Obtained $($bestCookie.Name) cookie (length: $($bestCookie.Value.Length))"
    return $bestCookie.Value
    #endregion
}
