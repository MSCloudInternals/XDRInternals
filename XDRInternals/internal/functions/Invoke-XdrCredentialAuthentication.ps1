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
    }
    finally {
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
        The password as a plain string. Use Connect-XdrByCredential for SecureString support.

    .PARAMETER TotpSecret
        Base32-encoded TOTP secret for automatic MFA code generation.
        This is the secret from the QR code when setting up Microsoft Authenticator
        (otpauth://totp/...?secret=JBSWY3DPEHPK3PXP).
        If not provided and MFA is required, the function will attempt push notification
        or prompt for a code.

    .PARAMETER MfaMethod
        Preferred MFA method. Valid values: PhoneAppOTP, PhoneAppNotification, OneWaySMS.
        If not specified, auto-selects: PhoneAppOTP when TotpSecret is provided,
        otherwise uses the default method from arrUserProofs.

    .PARAMETER UserAgent
        User-Agent string for HTTP requests.

    .OUTPUTS
        String — the ESTSAUTH cookie value suitable for passing to Connect-XdrByEstsCookie.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        [string]$Password,

        [string]$TotpSecret,

        [ValidateSet('PhoneAppOTP', 'PhoneAppNotification', 'OneWaySMS')]
        [string]$MfaMethod,

        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
    )

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

    if (-not ($initialResponse.Content -match '{(.*)}')) {
        throw "Unexpected response from Entra ID authentication endpoint."
    }
    $sessionInfo = $Matches[0] | ConvertFrom-Json

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
    $credBody = @{
        login         = $Username
        passwd        = $Password
        type          = 11
        ps            = 2
        flowToken     = $sessionInfo.sFT
        ctx           = $sessionInfo.sCtx
        canary        = $sessionInfo.canary
        hpgrequestid  = $sessionInfo.correlationId
    }

    $credResponse = Invoke-WebRequest -UseBasicParsing -Method Post `
        -Uri $sessionInfo.urlPost `
        -Body $credBody `
        -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false

    if (-not ($credResponse.Content -match '{(.*)}')) {
        throw "Unexpected response after credential submission."
    }
    $authState = $Matches[0] | ConvertFrom-Json

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

        # Determine MFA method
        $selectedMethod = $MfaMethod
        if (-not $selectedMethod) {
            if ($TotpSecret) {
                $selectedMethod = 'PhoneAppOTP'
            }
            elseif ($authState.arrUserProofs) {
                # Use the default method from available proofs
                $defaultProof = $authState.arrUserProofs | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1
                if ($defaultProof) {
                    $selectedMethod = $defaultProof.authMethodId
                }
                else {
                    $selectedMethod = $authState.arrUserProofs[0].authMethodId
                }
            }
            else {
                $selectedMethod = 'PhoneAppOTP'
            }
        }

        Write-Host "Using MFA method: $selectedMethod"
        Write-Verbose "Available methods: $(($authState.arrUserProofs | ForEach-Object { $_.authMethodId }) -join ', ')"

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
            -WebSession $session -Verbose:$false

        if (-not $beginAuth.Success -and $beginAuth.ErrCode -ne 0) {
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
                }
                else {
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
                # Push notification — poll for approval
                $entropy = $beginAuth.Entropy
                if ($entropy -and $entropy -gt 0) {
                    Write-Host "Approve the sign-in request in your Authenticator app."
                    Write-Host "Number to match: $entropy" -ForegroundColor Yellow
                }
                else {
                    Write-Host "Approve the sign-in request in your Authenticator app."
                }

                # Poll EndAuth until approved or denied
                $pollCount = 0
                $maxPolls = 60  # 60 * 3s = 180 seconds max
                $pushApproved = $false

                while ($pollCount -lt $maxPolls) {
                    $pollCount++
                    Start-Sleep -Seconds 3

                    $pollBody = @{
                        AuthMethodId = $selectedMethod
                        Method       = "EndAuth"
                        SessionId    = $beginAuth.SessionId
                        FlowToken    = $beginAuth.FlowToken
                        Ctx          = $beginAuth.Ctx
                        PollCount    = $pollCount
                    } | ConvertTo-Json

                    $pollResult = Invoke-RestMethod -Method Post `
                        -Uri "https://login.microsoftonline.com/common/SAS/EndAuth" `
                        -Body $pollBody -ContentType "application/json" `
                        -WebSession $session -Verbose:$false

                    Write-Verbose "Poll $pollCount : ResultValue=$($pollResult.ResultValue)"

                    if ($pollResult.ResultValue -eq 'AuthenticationSucceeded') {
                        $pushApproved = $true
                        $beginAuth = $pollResult  # Carry forward for ProcessAuth
                        break
                    }
                    elseif ($pollResult.ResultValue -ne 'AuthenticationPending') {
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

        # EndAuth — submit verification code (for OTP and SMS methods)
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
                -WebSession $session -Verbose:$false

            if ($endAuth.ResultValue -ne 'AuthenticationSucceeded') {
                $errDetail = if ($endAuth.Message) { $endAuth.Message } else { $endAuth.ResultValue }
                throw "MFA verification failed: $errDetail"
            }

            Write-Host "MFA verification succeeded."
            $beginAuth = $endAuth  # Carry forward FlowToken for ProcessAuth
        }

        # ProcessAuth — finalize MFA and continue the login flow
        $processBody = @{
            type      = 22
            FlowToken = $beginAuth.FlowToken
            request   = $beginAuth.Ctx
            ctx       = $beginAuth.Ctx
        }

        Write-Verbose "Calling SAS/ProcessAuth..."
        $processResponse = Invoke-WebRequest -UseBasicParsing -Method Post `
            -Uri "https://login.microsoftonline.com/common/SAS/ProcessAuth" `
            -Body $processBody `
            -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false

        if ($processResponse.Content -match '{(.*)}') {
            try { $authState = $Matches[0] | ConvertFrom-Json } catch { $authState = $null }
        }
        else {
            $authState = $null
        }

        Write-Verbose "ProcessAuth completed (pgid: $($authState.pgid))"
    }

    # Handle ConvergedProofUpRedirect (MFA registration prompt — skip it)
    if ($authState -and $authState.pgid -eq 'ConvergedProofUpRedirect') {
        Write-Verbose "MFA registration prompt detected, attempting to skip..."
        if ($authState.iRemainingDaysToSkipMfaRegistration -and $authState.iRemainingDaysToSkipMfaRegistration -gt 0) {
            $skipBody = @{
                type      = 22
                FlowToken = $authState.sFT
                request   = $authState.sProofUpAuthState
                ctx       = $authState.sProofUpAuthState
            }
            $skipResponse = Invoke-WebRequest -UseBasicParsing -Method Post `
                -Uri "https://login.microsoftonline.com/common/SAS/ProcessAuth" `
                -Body $skipBody `
                -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck -Verbose:$false

            if ($skipResponse.Content -match '{(.*)}') {
                try { $authState = $Matches[0] | ConvertFrom-Json } catch { $authState = $null }
            }
        }
        else {
            throw "MFA registration is required for this account and cannot be skipped."
        }
    }
    #endregion

    #region Handle interrupt pages (CmsiInterrupt, KmsiInterrupt, ConvergedSignIn)
    # This section is identical to the passkey flow interrupt handling
    $debug = $authState

    $interruptHandlers = @{
        "CmsiInterrupt" = @{
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
        "KmsiInterrupt" = @{
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

        $debug = $null
        if ($respFinalize.Content -match '{(.*)}') {
            try {
                $debug = $Matches[0] | ConvertFrom-Json
                if (-not $debug.pgid) { break }
            } catch {
                break
            }
        } else {
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
        $allCookies | Where-Object Name -EQ "ESTSAUTHPERSISTENT"
        $allCookies | Where-Object Name -EQ "ESTSAUTH"
        $allCookies | Where-Object Name -EQ "ESTSAUTHLIGHT"
    ) | Where-Object { $_ } | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1

    Write-Verbose "Obtained $($bestCookie.Name) cookie (length: $($bestCookie.Value.Length))"
    return $bestCookie.Value
    #endregion
}
