function Update-XdrConnectionSettings {
    <#
    .SYNOPSIS
        Updates XDR connection session cookies and authentication tokens.

    .DESCRIPTION
        Refreshes the web session cookies and XSRF tokens for Microsoft Defender XDR by making a request to the portal.
        This function is called automatically by other XDR cmdlets to ensure the session remains valid.

    .EXAMPLE
        Update-XdrConnectionSettings
        Updates the XDR session cookies and headers.

    .NOTES
        This function requires an existing connection established by Connect-XdrByEstsCookie or Set-XdrConnectionSettings.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'ConnectionSettings is singular by design')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state is changed outside of the current session')]
    [CmdletBinding()]
    param (

    )

    Write-Verbose "Checking cached XSRF token validity"
    # Check if cached XSRF token is still valid
    $cachedXsrfToken = Get-XdrCache -CacheKey "XsrfToken" -ErrorAction SilentlyContinue
    if ($cachedXsrfToken -and $cachedXsrfToken.NotValidAfter -gt (Get-Date)) {
        Write-Verbose "Cached XSRF token is still valid. Skipping session update."
        return
    }

    Write-Verbose "Cached XSRF token expired or not found. Updating session cookies for XDR webpage requests"

    $TenantId = Get-XdrCache -CacheKey "XdrTenantId" -ErrorAction SilentlyContinue
    # Normalize TenantId from cache: use .Value when present, otherwise keep existing string
    if ($TenantId -and -not ($TenantId -is [string])) {
        $valueProperty = $TenantId.PSObject.Properties['Value']
        if ($valueProperty) {
            $TenantId = $valueProperty.Value
        }
    }
    # Check if script variables exist
    if (Test-Path variable:script:session) {
        # Update session and headers in script scope
        $PreviousXSRFValue = $script:session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value
        $PreviousSccAuthValue = $script:session.cookies.GetCookies("https://security.microsoft.com")['sccauth'].Value
        if ($TenantId) {
            $SecurityPortalUri = "https://security.microsoft.com/" + "?tid=$TenantId"
        } else {
            $SecurityPortalUri = "https://security.microsoft.com/"
        }
        $null = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $script:session -Method Get -Uri $SecurityPortalUri -Verbose:$false
    } else {
        throw "Not connected to XDR. Please run Connect-XdrByEstsCookie or Set-XdrConnectionSettings first."
    }

    if ($PreviousXSRFValue -ne $script:session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value) {
        Write-Verbose "XSRF token has been updated."
        [Hashtable]$script:headers = @{}
        $script:headers["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value)

        # Cache the updated XSRF token with 5 minute TTL
        Write-Verbose "Caching updated XSRF token with 5 minute TTL"
        Set-XdrCache -CacheKey "XsrfToken" -Value $script:headers["X-XSRF-TOKEN"] -TTLMinutes 5
    } else {
        Write-Verbose "XSRF token remains unchanged."
    }
    if ($PreviousSccAuthValue -ne $script:session.cookies.GetCookies("https://security.microsoft.com")['sccauth'].Value) {
        Write-Verbose "sccauth cookie has been updated."
    } else {
        Write-Verbose "sccauth cookie remains unchanged."
    }
}