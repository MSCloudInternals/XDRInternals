function Connect-XdrByEstsCookie {
    <#
    .SYNOPSIS
        Establishes an authenticated session to the Microsoft Defender XDR portal.

    .DESCRIPTION
        Connects to security.microsoft.com using an ESTSAUTH cookie value to establish
        an authenticated web session. This function creates global session and headers variables
        that can be used by other XDR cmdlets to interact with the portal APIs.

        You can provide the cookie value as either a plain string or as a secure string.

    .PARAMETER EstsAuthCookieValue
        The ESTSAUTH cookie value from an authenticated browser session as a plain string.
        Use this parameter set when you have the cookie as a plain text value.

    .PARAMETER SecureEstsAuthCookieValue
        The ESTSAUTH cookie value from an authenticated browser session as a secure string.
        Use this parameter set when you want to pass the cookie value securely (e.g., from credential object).

    .PARAMETER TenantId
        The Tenant ID to use for the connection. If not provided, the default tenant will be used.

    .PARAMETER UserAgent
        The User-Agent string to use for the web requests. By default, uses the value returned by Get-XdrDefaultUserAgent.

    .EXAMPLE
        Connect-XdrByEstsCookie -EstsAuthCookieValue "your_cookie_value_here"
        Connects to the XDR portal using the provided authentication cookie as plain text.

    .EXAMPLE
        $secureCookie = ConvertTo-SecureString -String "your_cookie_value_here" -AsPlainText -Force
        Connect-XdrByEstsCookie -SecureEstsAuthCookieValue $secureCookie
        Connects to the XDR portal using the provided authentication cookie as a secure string.

    .EXAMPLE
        Read-Host -AsSecureString "Enter ESTSAUTH cookie" | Connect-XdrByEstsCookie
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
        [string]$UserAgent = (Get-XdrDefaultUserAgent)
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
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
            }
        }

        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $session.UserAgent = $UserAgent
        # Bootstrap the session by making an initial request to login.microsoftonline.com
        $null = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 99 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/error" -Verbose:$false

        foreach ($cookieName in @('ESTSAUTH', 'ESTSAUTHPERSISTENT')) {
            $cookie = [System.Net.Cookie]::new($cookieName, $EstsAuthCookieValue)
            $session.Cookies.Add('https://login.microsoftonline.com/', $cookie)
        }
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
        try {
            $SecurityPortal = Invoke-WebRequest -UseBasicParsing -ErrorAction Stop -WebSession $session -Method Get -Uri $SecurityPortalUri -Verbose:$false
        } catch {
            $failure = Get-XdrAuthenticationFailure -ErrorRecord $_ -AuthenticationMethod EstsCookie -Stage PortalAuthorize -DefaultCode BootstrapFailed
            throw (New-XdrAuthenticationErrorRecord -Failure $failure -ErrorRecord $_)
        }

        if ($SecurityPortal.InputFields.name -notcontains 'code') {
            $portalState = Get-XdrAuthStateFromResponse -Response $SecurityPortal
            $failure = Get-XdrAuthenticationFailure -AuthState $portalState -Response $SecurityPortal -AuthenticationMethod EstsCookie -Stage PortalAuthorize -DefaultCode ProviderRejected
            throw (New-XdrAuthenticationErrorRecord -Failure $failure)
        }

        $requiredFields = @("code", "id_token", "state", "session_state", "correlation_id")
        Write-Verbose "Input fields received: $($SecurityPortal.InputFields.name -join ', ')"

        # Check if all required fields are present in returned input fields
        foreach ($field in $requiredFields) {
            if (-not ($SecurityPortal.InputFields.name -contains $field)) {
                $failure = Get-XdrAuthenticationFailure -AuthenticationMethod EstsCookie -Stage PortalAuthorize -DefaultCode RequestInvalid -SafeEvidence @{ Field = $field }
                throw (New-XdrAuthenticationErrorRecord -Failure $failure)
            }
        }
        $SessionCookies = $session.Cookies.GetCookies('https://security.microsoft.com') | Select-Object -ExpandProperty Name
        Write-Verbose "Session cookies: $( $SessionCookies -join ', ' )"
        Write-Host "Successfully signed into to XDR portal using ESTSAUTH cookie."
        Write-Host "Exchange the received authorization code for session cookies."

        # Invoke a POST request to get the session cookies for security.microsoft.com
        $Body = @{
            code           = $SecurityPortal.InputFields | Where-Object { $_.name -eq "code" } | Select-Object -ExpandProperty value
            id_token       = $SecurityPortal.InputFields | Where-Object { $_.name -eq "id_token" } | Select-Object -ExpandProperty value
            state          = $SecurityPortal.InputFields | Where-Object { $_.name -eq "state" } | Select-Object -ExpandProperty value
            session_state  = $SecurityPortal.InputFields | Where-Object { $_.name -eq "session_state" } | Select-Object -ExpandProperty value
            correlation_id = $SecurityPortal.InputFields | Where-Object { $_.name -eq "correlation_id" } | Select-Object -ExpandProperty value
        }
        try {
            $null = Invoke-WebRequest -UseBasicParsing -ErrorAction Stop -WebSession $session -Method Post -Uri $SecurityPortalUri -Body $Body -Verbose:$false
        } catch {
            $failure = Get-XdrAuthenticationFailure -ErrorRecord $_ -AuthenticationMethod EstsCookie -Stage PortalBootstrap -DefaultCode BootstrapFailed
            throw (New-XdrAuthenticationErrorRecord -Failure $failure -ErrorRecord $_)
        }
        $SessionCookies = $session.Cookies.GetCookies('https://security.microsoft.com') | Select-Object -ExpandProperty Name
        Write-Verbose "Session cookies: $( $SessionCookies -join ', ' )"
        Write-Host "Successfully obtained XDR session cookies."
        # Save session and headers in script scope
        Set-XdrConnectionSettings -WebSession $session
    }
}
