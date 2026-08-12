function Get-XdrSafeUriDescription {
    <#
    .SYNOPSIS
        Produces a diagnostic-safe description of a URI.

    .DESCRIPTION
        Returns an HTTP or HTTPS URI without user information, query parameters, or fragments.
        Other absolute URIs are reduced to their scheme so authorization callbacks cannot expose
        codes or tokens through verbose and error output.

    .PARAMETER Uri
        The URI value to describe without exposing sensitive components.

    .EXAMPLE
        Get-XdrSafeUriDescription -Uri 'https://security.microsoft.com/path?code=secret'

        Returns https://security.microsoft.com/path.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Uri
    )

    if ($null -eq $Uri -or [string]::IsNullOrWhiteSpace([string]$Uri)) {
        return 'unavailable URI'
    }

    try {
        $parsedUri = [uri]$Uri
    } catch {
        return 'unparseable URI'
    }

    if (-not $parsedUri.IsAbsoluteUri) {
        return 'relative URI'
    }

    if ($parsedUri.Scheme -notin @('http', 'https')) {
        return "$($parsedUri.Scheme):"
    }

    $safeComponents = [System.UriComponents]::SchemeAndServer -bor [System.UriComponents]::Path
    return $parsedUri.GetComponents($safeComponents, [System.UriFormat]::UriEscaped)
}
