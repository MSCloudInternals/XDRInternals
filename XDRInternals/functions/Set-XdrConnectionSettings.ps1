function Set-XdrConnectionSettings {
    <#
    .SYNOPSIS
        Creates XDR connection settings using authentication cookies.
    
    .DESCRIPTION
        Creates global session and headers variables for XDR API calls using the provided
        sccauth and XSRF token values. This function sets up the necessary authentication
        context for other XDR cmdlets to interact with the Microsoft Defender XDR portal.
    
    .PARAMETER sccauth
        The sccauth cookie value from an authenticated session to security.microsoft.com.
    
    .PARAMETER xsrf
        The XSRF-TOKEN cookie value from an authenticated session to security.microsoft.com.

    .PARAMETER TenantId
        The Tenant ID to use for XDR API requests. If not provided, the Tenant ID will be
        determined automatically from the XDR portal.

    .PARAMETER WebSession
        An optional WebRequestSession object to use for the requests. If not provided,
        a new session will be created.
    
    .EXAMPLE
        Set-XdrConnectionSettings -sccauth "your_sccauth_value" -xsrf "your_xsrf_value"
        Creates XDR connection settings using the provided authentication cookies.
    
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

        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        $Xsrf,

        [Parameter(ParameterSetName = 'Manual')]
        [Parameter(ParameterSetName = 'TenantId')]
        $TenantId,

        [Parameter(Mandatory, ParameterSetName = 'Websession')]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession
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

        # Create session and cookies
        $script:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $script:session.Cookies.Add((New-Object System.Net.Cookie("sccauth", $SccAuthValue, "/", "security.microsoft.com")))
        $script:session.Cookies.Add((New-Object System.Net.Cookie("XSRF-TOKEN", $XsrfValue, "/", "security.microsoft.com")))
    }
    
    
    if ($PSBoundParameters.ContainsKey('WebSession')) {
        # Use the provided WebSession instead of creating a new one
        $script:session = $WebSession
    }

    # Set TenantId in cache and headers
    Write-Verbose "Caching TenantId with 1 day TTL"
    if ($PSBoundParameters.ContainsKey('TenantId')) {
        Set-XdrCache -CacheKey "XdrTenantId" -Value $TenantId -TTLMinutes 1440
    } else {
        $TenantId = (Get-XdrTenantContext).AuthInfo.TenantId
        Set-XdrCache -CacheKey "XdrTenantId" -Value $TenantId -TTLMinutes 1440
    }
    [Hashtable]$script:headers = @{}
    $script:headers["X-Tid"] = $TenantId

    # Set the headers to include the xsrf token
    Write-Verbose "Setting headers for XDR API proxy requests"
    $script:headers["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value)

    # Cache the XSRF token with 5 minute TTL
    Write-Verbose "Caching XSRF token with 5 minute TTL"
    Set-XdrCache -CacheKey "XsrfToken" -Value $script:headers["X-XSRF-TOKEN"] -TTLMinutes 5
    
    Write-Host "XDR Connection Settings created"
    Write-Host "You can now run other XDRInternals cmdlets to interact with the XDR portal."
}