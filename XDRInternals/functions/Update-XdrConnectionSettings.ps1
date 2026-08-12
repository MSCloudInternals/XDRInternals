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

    if (-not (Test-Path variable:script:session) -or $null -eq $script:session) {
        throw "Not connected to XDR. Please run Connect-XdrByEstsCookie or Set-XdrConnectionSettings first."
    }

    $TenantId = Get-XdrCache -CacheKey "XdrTenantId" -ErrorAction SilentlyContinue
    # Normalize TenantId from cache: use .Value when present, otherwise keep existing string
    if ($TenantId -and -not ($TenantId -is [string])) {
        $valueProperty = $TenantId.PSObject.Properties['Value']
        if ($valueProperty) {
            $TenantId = $valueProperty.Value
        }
    }

    Write-Verbose "Checking cached XSRF token validity"
    $cachedXsrfToken = Get-XdrCache -CacheKey "XsrfToken" -TenantId $TenantId -ErrorAction SilentlyContinue
    $currentXsrfValue = $script:session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value
    $decodedCurrentXsrfValue = [System.Net.WebUtility]::UrlDecode($currentXsrfValue)
    $hasCurrentXsrfHeader = (Test-Path variable:script:headers) -and
        $null -ne $script:headers -and
        $script:headers.ContainsKey('X-XSRF-TOKEN') -and
        $script:headers['X-XSRF-TOKEN'] -eq $decodedCurrentXsrfValue
    if ($cachedXsrfToken -and $cachedXsrfToken.NotValidAfter -gt (Get-Date) -and
        -not [string]::IsNullOrWhiteSpace($currentXsrfValue) -and $hasCurrentXsrfHeader) {
        Write-Verbose "Cached XSRF token is still valid. Skipping session update."
        return
    }

    Write-Verbose "Cached XSRF token expired or session state was incomplete. Updating session cookies for XDR webpage requests"
    $PreviousXSRFValue = $currentXsrfValue
    $PreviousSccAuthValue = $script:session.cookies.GetCookies("https://security.microsoft.com")['sccauth'].Value
    if ($TenantId) {
        $SecurityPortalUri = "https://security.microsoft.com/" + "?tid=$TenantId"
    } else {
        $SecurityPortalUri = "https://security.microsoft.com/"
    }
    $null = Invoke-WebRequest -UseBasicParsing -ErrorAction Stop -WebSession $script:session -Method Get -Uri $SecurityPortalUri -Verbose:$false

    $updatedXsrfValue = $script:session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value
    if ([string]::IsNullOrWhiteSpace($updatedXsrfValue)) {
        throw 'The Defender XDR session refresh did not return an XSRF-TOKEN cookie.'
    }

    if ($PreviousXSRFValue -ne $updatedXsrfValue) {
        Write-Verbose "XSRF token has been updated."
    } else {
        Write-Verbose "XSRF token remains unchanged."
    }

    if (-not (Test-Path variable:script:headers) -or $null -eq $script:headers) {
        [Hashtable]$script:headers = @{}
    }
    $script:headers["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($updatedXsrfValue)

    Write-Verbose "Caching updated XSRF token with 5 minute TTL"
    Set-XdrCache -CacheKey "XsrfToken" -Value $script:headers["X-XSRF-TOKEN"] -TTLMinutes 5 -TenantId $TenantId
    if ($PreviousSccAuthValue -ne $script:session.cookies.GetCookies("https://security.microsoft.com")['sccauth'].Value) {
        Write-Verbose "sccauth cookie has been updated."
    } else {
        Write-Verbose "sccauth cookie remains unchanged."
    }
}
