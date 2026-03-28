function Invoke-XdrTemporaryAccessPassAuthentication {
    <#
    .SYNOPSIS
        Performs Temporary Access Pass authentication against Entra ID and returns the ESTSAUTH cookie value.

    .DESCRIPTION
        Implements the Entra ID TAP web sign-in flow used by mysignins.microsoft.com, then extracts the
        resulting ESTSAUTH cookie so it can be passed to Connect-XdrByEstsCookie.

        TAP sign-in is tenant-scoped. The same TenantId is used for the Entra authorize request and is
        typically passed on to Connect-XdrByEstsCookie so the Defender XDR portal opens the intended tenant.

        This is an internal function used by Connect-XdrByTemporaryAccessPass.

    .PARAMETER Username
        The user principal name (e.g., admin@contoso.com).

    .PARAMETER TemporaryAccessPass
        The Temporary Access Pass as a SecureString.

    .PARAMETER TenantId
        The Entra tenant ID used for the TAP authorize request.

    .PARAMETER UserAgent
        User-Agent string for HTTP requests.

    .OUTPUTS
        String - the ESTSAUTH cookie value suitable for passing to Connect-XdrByEstsCookie.

    .EXAMPLE
        $tap = ConvertTo-SecureString 'ABC12345' -AsPlainText -Force
        Invoke-XdrTemporaryAccessPassAuthentication -Username 'admin@contoso.com' -TemporaryAccessPass $tap -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2'

        Performs the internal TAP sign-in flow and returns the ESTSAUTH cookie value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        [SecureString]$TemporaryAccessPass,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [string]$UserAgent = (Get-XdrDefaultUserAgent)
    )

    $clientId = '19db86c3-b2b9-44cc-b339-36da233a3be2'
    $redirectUri = 'https://mysignins.microsoft.com'
    $tokenScope = "$clientId/.default openid profile offline_access"

    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $session.UserAgent = $UserAgent

    $verifierBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
    $codeVerifier = ConvertTo-XdrBase64Url -Bytes $verifierBytes
    $challengeBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
    $codeChallenge = ConvertTo-XdrBase64Url -Bytes $challengeBytes

    $authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?" +
    "client_id=$([uri]::EscapeDataString($clientId))" +
    "&redirect_uri=$([uri]::EscapeDataString($redirectUri))" +
    "&scope=$([uri]::EscapeDataString($tokenScope))" +
    "&response_type=code&response_mode=fragment&prompt=login" +
    "&login_hint=$([uri]::EscapeDataString($Username))" +
    "&code_challenge=$([uri]::EscapeDataString($codeChallenge))&code_challenge_method=S256&state=test"

    Write-Verbose "Initiating TAP authentication flow for $Username in tenant $TenantId"
    $loginPage = Invoke-WebRequest -Uri $authUrl -Method Get -UseBasicParsing -MaximumRedirection 10 -WebSession $session -Verbose:$false
    $config = Get-XdrAuthStateFromResponse -Response $loginPage

    if (-not $config) {
        throw 'Unexpected response from Entra TAP authentication endpoint.'
    }

    $tapHandle = [IntPtr]::Zero
    $plainTap = $null

    try {
        $tapHandle = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($TemporaryAccessPass)
        $plainTap = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($tapHandle)

        $loginBody = [ordered]@{
            login             = $Username
            loginfmt          = $Username
            accesspass        = $plainTap
            ps                = '56'
            psRNGCDefaultType = '1'
            psRNGCEntropy     = ''
            psRNGCSLK         = [string]$config.sFT
            canary            = [string]$config.canary
            ctx               = [string]$config.sCtx
            hpgrequestid      = [string]$(if ($config.sessionId) { $config.sessionId } else { $config.correlationId })
            flowToken         = [string]$config.sFT
            PPSX              = ''
            NewUser           = '1'
            FoundMSAs         = ''
            fspost            = '0'
            i21               = '0'
            CookieDisclosure  = '0'
            IsFidoSupported   = '1'
            isSignupPost      = '0'
            DfpArtifact       = ''
            i19               = '10000'
        }
        $encodedLoginBody = ConvertTo-XdrFormUrlEncodedBody -Data $loginBody
    } finally {
        $plainTap = $null
        if ($tapHandle -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tapHandle)
        }
    }

    $currentUrl = Resolve-XdrAuthAbsoluteUri -Uri $(if ($config.urlPost) { $config.urlPost } else { 'https://login.microsoftonline.com/common/login' }) -BaseUri 'https://login.microsoftonline.com/'
    $currentMethod = 'POST'
    $currentBody = $encodedLoginBody

    for ($step = 0; $step -lt 15; $step++) {
        try {
            $requestParams = @{
                Uri                = $currentUrl
                Method             = $currentMethod
                WebSession         = $session
                UseBasicParsing    = $true
                MaximumRedirection = 0
                Verbose            = $false
            }
            if ($currentMethod -eq 'POST' -and $null -ne $currentBody) {
                $requestParams['Body'] = $currentBody
                $requestParams['ContentType'] = 'application/x-www-form-urlencoded'
            }

            $response = Invoke-WebRequest @requestParams -ErrorAction Stop
            $parsedState = Get-XdrAuthStateFromResponse -Response $response

            $formPost = Get-XdrHtmlFormPost -Response $response
            if ($response.StatusCode -eq 200 -and $formPost) {
                $currentUrl = Resolve-XdrAuthAbsoluteUri -Uri $formPost.Action -BaseUri $currentUrl
                $currentMethod = 'POST'
                $currentBody = $formPost.Body
                continue
            }

            if ($parsedState -and $parsedState.sErrorCode) {
                throw "TAP authentication failed ($($parsedState.sErrorCode)): $($parsedState.sErrTxt)"
            }

            break
        } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            $response = $_.Exception.Response
            $statusCode = [int]$response.StatusCode

            if ($statusCode -lt 300 -or $statusCode -ge 400) {
                throw
            }

            $location = Get-XdrResponseLocation -Response $response
            if (-not $location) {
                throw 'TAP authentication redirected without a Location header.'
            }

            $resolvedLocation = Resolve-XdrAuthAbsoluteUri -Uri $location -BaseUri $currentUrl
            if ($resolvedLocation -match '[#?&]code=') {
                break
            }

            if ($resolvedLocation -match 'error=') {
                throw "TAP authentication failed: $resolvedLocation"
            }

            $currentUrl = $resolvedLocation
            $currentMethod = 'GET'
            $currentBody = $null
            continue
        }
    }

    $bestCookie = Get-XdrBestEstsCookieValue -Session $session
    if (-not $bestCookie) {
        throw 'No ESTSAUTH cookie found after TAP authentication.'
    }

    Write-Verbose "Obtained ESTS cookie (length: $($bestCookie.Length))"
    return $bestCookie
}
