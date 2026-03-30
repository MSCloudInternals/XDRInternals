function Get-XdrRequestContextSnapshot {
    <#
    .SYNOPSIS
        Captures the current XDR web request context for worker runspaces.

    .DESCRIPTION
        Extracts the current base URL, request headers, and relevant cookies from the
        active XDR session so background runspaces can recreate authenticated web requests.

    .EXAMPLE
        $context = Get-XdrRequestContextSnapshot
        Captures the current XDR request context for reuse by parallel workers.

    .OUTPUTS
        PSCustomObject
        Returns an object with BaseUrl, CookieData, and HeadersData properties.
    #>
    [CmdletBinding()]
    param ()

    if (-not (Test-Path variable:script:session) -or $null -eq $script:session) {
        throw 'No active XDR web session is available. Authenticate first.'
    }

    if (-not (Test-Path variable:script:headers) -or $null -eq $script:headers) {
        throw 'No active XDR request headers are available. Authenticate first.'
    }

    $baseUrl = if ((Test-Path variable:script:XdrBaseUrl) -and $script:XdrBaseUrl) {
        "$($script:XdrBaseUrl)".TrimEnd('/')
    } else {
        'https://security.microsoft.com'
    }

    $cookieData = @()
    $cookieUri = [System.Uri]$baseUrl
    foreach ($cookie in $script:session.Cookies.GetCookies($cookieUri)) {
        $cookieData += [PSCustomObject]@{
            Name   = $cookie.Name
            Value  = $cookie.Value
            Domain = $cookie.Domain
            Path   = $cookie.Path
        }
    }

    $headersData = @{}
    foreach ($key in $script:headers.Keys) {
        $headersData[$key] = $script:headers[$key]
    }

    [PSCustomObject]@{
        BaseUrl     = $baseUrl
        CookieData  = @($cookieData)
        HeadersData = $headersData
    }
}