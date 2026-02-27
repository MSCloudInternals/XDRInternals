function Set-XdrConnectionSettings {
    <#
    .SYNOPSIS
        Creates XDR connection settings using authentication cookies.

    .DESCRIPTION
        Creates global session and headers variables for XDR API calls using the provided
        sccauth value and optionally an XSRF token value. If xsrf is not provided, the
        function will bootstrap the session against security.microsoft.com to obtain
        XSRF-TOKEN automatically.

    .PARAMETER sccauth
        The sccauth cookie value from an authenticated session to security.microsoft.com.

    .PARAMETER xsrf
        The XSRF-TOKEN cookie value from an authenticated session to security.microsoft.com.
        If not provided, XSRF-TOKEN is obtained automatically using the provided sccauth
        and an initial request to security.microsoft.com.

    .PARAMETER TenantId
        The Tenant ID to use for XDR API requests. If not provided, the Tenant ID will be
        determined automatically from the XDR portal.

    .PARAMETER WebSession
        An optional WebRequestSession object to use for the requests. If not provided,
        a new session will be created.

    .PARAMETER ResetWebSession
        If specified, resets the existing WebSession by creating a new one while retaining
        the existing authentication cookies.

    .EXAMPLE
        Set-XdrConnectionSettings -sccauth "your_sccauth_value" -xsrf "your_xsrf_value"
        Creates XDR connection settings using the provided authentication cookies.

    .EXAMPLE
        Set-XdrConnectionSettings -sccauth "your_sccauth_value" -TenantId "your_tenant_id"
        Creates XDR connection settings and automatically obtains XSRF-TOKEN.

    .OUTPUTS
        String
        Returns a confirmation message when connection settings are created.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'ConnectionSettings is singular by design')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state is changed outside of the current session')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        $SccAuth,

        [Parameter(ParameterSetName = 'Manual')]
        $Xsrf,

        $TenantId,

        [Parameter(Mandatory, ParameterSetName = 'Websession')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory, ParameterSetName = 'ResetWebSession')]
        [switch]$ResetWebSession
    )

    # Determine sccauth and xsrf format, then create session and cookies
    Write-Verbose "Setting session cookies for XDR webpage requests"
    if ($PSBoundParameters.ContainsKey('SccAuth')) {
        if ($SccAuth -is [System.Security.SecureString]) {
            Write-Verbose "SccAuth is secure string, converting to plain text"
            $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SccAuth)
            try {
                $SccAuthValue = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
            }
        } else {
            $SccAuthValue = $SccAuth
        }
        # Create session and cookies
        $script:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $script:session.Cookies.Add((New-Object System.Net.Cookie("sccauth", $SccAuthValue, "/", "security.microsoft.com")))

        if ($PSBoundParameters.ContainsKey('Xsrf')) {
            if ($Xsrf -is [System.Security.SecureString]) {
                Write-Verbose "Xsrf is secure string, converting to plain text"
                $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Xsrf)
                try {
                    $XsrfValue = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
                }
            } else {
                $XsrfValue = $Xsrf
            }
            $script:session.Cookies.Add((New-Object System.Net.Cookie("XSRF-TOKEN", $XsrfValue, "/", "security.microsoft.com")))
        } else {
            if ($TenantId) {
                $SecurityPortalUri = "https://security.microsoft.com/" + "?tid=$TenantId"
            } else {
                $SecurityPortalUri = "https://security.microsoft.com/"
            }
            Write-Verbose "Obtaining XSRF token from $SecurityPortalUri"
            $null = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $script:session -Method Get -Uri $SecurityPortalUri -Verbose:$false
            $XsrfValue = $script:session.Cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value
            if ([string]::IsNullOrWhiteSpace($XsrfValue)) {
                throw "Failed to obtain XSRF-TOKEN cookie from security.microsoft.com. Verify the provided sccauth value."
            }
        }
    }


    if ($PSBoundParameters.ContainsKey('WebSession')) {
        # Use the provided WebSession instead of creating a new one
        $script:session = $WebSession
    }

    if ($PSBoundParameters.ContainsKey('ResetWebSession')) {
        # Set tenant id
        $TenantId = $script:headers["x-tid"]
        # Reset the existing WebSession by creating a new one
        Write-Verbose "Resetting existing WebSession to remove old headers and cookies"
        $SccAuthValue = $script:session.cookies.GetCookies("https://security.microsoft.com")['sccauth'].Value
        $XsrfValue = $script:session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value
        # Create session and cookies
        $script:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $script:session.Cookies.Add((New-Object System.Net.Cookie("sccauth", $SccAuthValue, "/", "security.microsoft.com")))
        $script:session.Cookies.Add((New-Object System.Net.Cookie("XSRF-TOKEN", $XsrfValue, "/", "security.microsoft.com")))
    }

    # Set the headers to include the xsrf token
    [Hashtable]$script:headers = @{}
    Write-Verbose "Setting headers for XDR API proxy requests"
    $script:headers["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value)

    # Set TenantId in cache and headers
    Write-Verbose "Caching TenantId with 1 day TTL"
    if ( $TenantId ) {
        Set-XdrCache -CacheKey "XdrTenantId" -Value $TenantId -TTLMinutes 1440
    } else {
        # Retrieve TenantId from XDR portal without using cache or dedicated function to avoid circular dependency
        Write-Verbose "Retrieving TenantId from XDR portal"
        $XdrTenantContext = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/sccManagement/mgmt/TenantContext?realTime=true" -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        $TenantId = $XdrTenantContext.AuthInfo.TenantId
        Set-XdrCache -CacheKey "XdrTenantId" -Value $TenantId -TTLMinutes 1440
    }
    if ( -not [string]::IsNullOrWhiteSpace($TenantId)) {
        $script:headers["x-tid"] = $TenantId
        $script:headers["tenant-id"] = $TenantId
    }

    # Cache the XSRF token with 5 minute TTL
    Write-Verbose "Caching XSRF token with 5 minute TTL"
    Set-XdrCache -CacheKey "XsrfToken" -Value $script:headers["X-XSRF-TOKEN"] -TTLMinutes 5 -TenantId $TenantId
    if ($PSBoundParameters.ContainsKey('ResetWebSession')) {
        # Keep silent
    } else {
        Write-Host "XDR Connection Settings created"
        Write-Host "You can now run other XDRInternals cmdlets to interact with the XDR portal."
    }
}
