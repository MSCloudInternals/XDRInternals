function Connect-XdrByEstsCookie {
    <#
    .SYNOPSIS
        Establishes an authenticated session to the Microsoft Defender XDR portal.

    .DESCRIPTION
        Connects to security.microsoft.com using an ESTSAUTHPERSISTENT cookie value to establish
        an authenticated web session. This function creates global session and headers variables
        that can be used by other XDR cmdlets to interact with the portal APIs.

        You can provide the cookie value as either a plain string or as a secure string.

    .PARAMETER EstsAuthCookieValue
        The ESTSAUTHPERSISTENT cookie value from an authenticated browser session as a plain string.
        Use this parameter set when you have the cookie as a plain text value.

    .PARAMETER SecureEstsAuthCookieValue
        The ESTSAUTHPERSISTENT cookie value from an authenticated browser session as a secure string.
        Use this parameter set when you want to pass the cookie value securely (e.g., from credential object).

    .PARAMETER TenantId
        The Tenant ID to use for the connection. If not provided, the default tenant will be used.

    .PARAMETER UserAgent
        The User-Agent string to use for the web requests. Defaults to Edge browser user agent.

    .EXAMPLE
        Connect-XdrByEstsCookie -EstsAuthCookieValue "your_cookie_value_here"
        Connects to the XDR portal using the provided authentication cookie as plain text.

    .EXAMPLE
        $secureCookie = ConvertTo-SecureString -String "your_cookie_value_here" -AsPlainText -Force
        Connect-XdrByEstsCookie -SecureEstsAuthCookieValue $secureCookie
        Connects to the XDR portal using the provided authentication cookie as a secure string.

    .EXAMPLE
        Read-Host -AsSecureString "Enter ESTSAUTHPERSISTENT cookie" | Connect-XdrByEstsCookie
        Prompts for the cookie value securely via pipeline and connects to the XDR portal.

    .OUTPUTS
        String
        Returns a confirmation message when successfully connected.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding(DefaultParameterSetName = 'PlainText')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'PlainText', ValueFromPipeline)]
        [string]$EstsAuthCookieValue,

        [Parameter(Mandatory, ParameterSetName = 'SecureString', ValueFromPipeline)]
        [System.Security.SecureString]$SecureEstsAuthCookieValue,

        [Parameter(ParameterSetName = 'PlainText')]
        [Parameter(ParameterSetName = 'SecureString')]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'PlainText')]
        [Parameter(ParameterSetName = 'SecureString')]
        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
    )

    begin {
        # Clear cache if existing
        Clear-XdrCache
    }

    process {
        # Convert secure string to plain text if provided
        if ($PSCmdlet.ParameterSetName -eq 'SecureString') {
            #$EstsAuthCookieValue = [System.Net.NetworkCredential]::new('', $SecureEstsAuthCookieValue).Password
            $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureEstsAuthCookieValue)
            try {
                $EstsAuthCookieValue = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
            }
        }

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
        }
        else {
            $SecurityPortalUri = "https://security.microsoft.com/"
        }
        Write-Verbose "Initiating authentication flow to $SecurityPortalUri"
        $SecurityPortal = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri $SecurityPortalUri -Verbose:$false

        # Error handling for missing for edge cases
        if ( $SecurityPortal.InputFields.name -notcontains "code" ) {
            try {
                $SecurityPortal.Content -match '{(.*)}' | Out-Null
                $SessionInformation_SecurityPortal = $Matches[0] | ConvertFrom-Json
            }
            catch {
                throw "Failed to complete authentication flow. Please verify the ESTSAUTHPERSISTENT cookie value."
            }
            if ($SessionInformation_SecurityPortal.sErrorCode -eq "50058") {
                throw "Session information is not sufficient for single-sign-on. Please use a incognito/private browsing session to obtain a new ESTSAUTHPERSISTENT cookie value."
            }
            elseif ($SessionInformation_SecurityPortal.sErrorCode) {
                throw "Authentication flow failed with error code: $($SessionInformation_SecurityPortal.sErrorCode). Please verify the ESTSAUTHPERSISTENT cookie value."
            }
            else {
                throw "Authentication flow failed. Please verify the ESTSAUTHPERSISTENT cookie value."
            }
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
}