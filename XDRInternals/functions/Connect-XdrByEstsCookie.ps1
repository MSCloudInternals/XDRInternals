function Connect-XdrByEstsCookie {
    <#
    .SYNOPSIS
        Establishes an authenticated session to the Microsoft Defender XDR portal.

    .DESCRIPTION
        Connects to security.microsoft.com using an ESTSAUTHPERSISTENT cookie value to establish
        an authenticated web session. This function creates global session and headers variables
        that can be used by other XDR cmdlets to interact with the portal APIs.

    .PARAMETER EstsAuthCookieValue
        The ESTSAUTHPERSISTENT cookie value from an authenticated browser session.

    .PARAMETER TenantId
        The Tenant ID to use for the connection. If not provided, the default tenant will be used.

    .PARAMETER UserAgent
        The User-Agent string to use for the web requests. Defaults to Edge browser user agent.

    .EXAMPLE
        Connect-XdrByEstsCookie -EstsAuthCookieValue "your_cookie_value_here"
        Connects to the XDR portal using the provided authentication cookie.

    .OUTPUTS
        String
        Returns a confirmation message when successfully connected.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$EstsAuthCookieValue,

        [Parameter()]
        $TenantId,

        [Parameter()]
        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
    )

    # Clear cache if existing
    Clear-XdrCache

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = $UserAgent
    # Bootstrap the session by making an initial request to login.microsoftonline.com
    $null = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 99 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/error" -Verbose:$false

    $cookie = [System.Net.Cookie]::new("ESTSAUTHPERSISTENT", $EstsAuthCookieValue)
    $session.Cookies.Add('https://login.microsoftonline.com/', $cookie)
    $SessionCookies = $session.Cookies.GetCookies('https://login.microsoftonline.com') | Select-Object -ExpandProperty Name
    Write-Verbose "Session cookies: $( $SessionCookies -join ', ' )"

    # Invoke a GET request to security.microsoft.com to initiate the authentication flow
    if ($TenantId) {
        $SecurityPortalUri = "https://security.microsoft.com/" + "?tid=$TenantId"
        Set-XdrCache -CacheKey "XdrTenantId" -Value $TenantId -TTLMinutes 3660
    } else {
        $SecurityPortalUri = "https://security.microsoft.com/"
    }
    Write-Verbose "Initiating authentication flow to $SecurityPortalUri"
    $SecurityPortal = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $SecurityPortalUri -Verbose:$false

    # Errorhandling for special cases
    if ( $SecurityPortal.InputFields.name -notcontains "code" ) {
        try {
            $SecurityPortal.Content -match '{(.*)}' | Out-Null
            $SessionInformation = $Matches[0] | ConvertFrom-Json
            $Sessionid = $SessionInformation.arrSessions.id
            $UrlLogin = $SessionInformation.urlLogin
            $NextUri = $UrlLogin + '&sessionid=' + $Sessionid
            Write-Verbose "Additional authentication step detected, performing secondary request to $NextUri"
            $SecurityPortal = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $NextUri -Verbose:$false
        } catch {
            throw "Failed to complete authentication flow. Please verify the ESTSAUTHPERSISTENT cookie value."
        }
    }

    # Extract urlResume and required fields from the response
    if ( $SecurityPortal.InputFields.name -notcontains "code" ) {
        $SecurityPortal.Content -match '{(.*)}' | Out-Null
        $SessionInformation = $Matches[0] | ConvertFrom-Json
        $Sessionid = $SessionInformation.arrSessions.id
        $ResumeUrl = $SessionInformation.urlResume + '&sessionid=' + $Sessionid
        Write-Verbose "Resuming authentication flow at $ResumeUrl"
        $SecurityPortal = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $ResumeUrl -Verbose:$false
    }

    # If still no code field, extract error message and throw error
    if ( $SecurityPortal.InputFields.name -notcontains "code" ) {
        $SecurityPortal.Content -match '{(.*)}' | Out-Null
        $SessionInformation = $Matches[0] | ConvertFrom-Json
        $ErrorDescription = $SessionInformation.desktopSsoConfig.redirectDssoErrorPostParams.error_description
        Write-Verbose "$($SessionInformation | ConvertTo-Json -Depth 5)"
        throw "Failed to complete authentication flow. Please verify the ESTSAUTHPERSISTENT cookie value. Error description: $ErrorDescription"
    }

    $requiredFields = @("code", "id_token", "state", "session_state", "correlation_id")
    Write-Verbose "Input fields received: $($SecurityPortal.InputFields.name -join ', ')"

    # Check if all required fields are present in returned input fields
    foreach ($field in $requiredFields) {
        if (-not ($SecurityPortal.InputFields.name -contains $field)) {
            $SecurityPortal.Content -match '{(.*)}' | Out-Null
            $SessionInformation = $Matches[0] | ConvertFrom-Json
            Write-Verbose "Session information received: $($SessionInformation | ConvertTo-Json -Depth 5)"
            throw "Required field '$field' is missing from the response."
        }
    }
    $SessionCookies = $session.Cookies.GetCookies('https://security.microsoft.com') | Select-Object -ExpandProperty Name
    Write-Verbose "Session cookies: $( $SessionCookies -join ', ' )"
    Write-Host "Successfully signed into to XDR portal using ESTSAUTHPERSISTENT cookie."
    Write-Host "Exchange the received authorization code for session cookies."

    # Invoke a POST request to get the session cookies for security.microsoft.com
    $Body = @{
        code           = $SecurityPortal.InputFields | Where-Object { $_.name -eq "code" } | Select-Object -ExpandProperty value
        id_token       = $SecurityPortal.InputFields | Where-Object { $_.name -eq "id_token" } | Select-Object -ExpandProperty value
        state          = $SecurityPortal.InputFields | Where-Object { $_.name -eq "state" } | Select-Object -ExpandProperty value
        session_state  = $SecurityPortal.InputFields | Where-Object { $_.name -eq "session_state" } | Select-Object -ExpandProperty value
        correlation_id = $SecurityPortal.InputFields | Where-Object { $_.name -eq "correlation_id" } | Select-Object -ExpandProperty value
    }
    Write-Verbose "POST Headers: $($Headers | Out-String)"
    $null = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $session -Method Post -Uri $SecurityPortalUri -Body $Body -Verbose:$false
    $SessionCookies = $session.Cookies.GetCookies('https://security.microsoft.com') | Select-Object -ExpandProperty Name
    Write-Verbose "Session cookies: $( $SessionCookies -join ', ' )"
    Write-Host "Successfully obtained XDR session cookies."
    # Save session and headers in script scope
    Set-XdrConnectionSettings -WebSession $session
}