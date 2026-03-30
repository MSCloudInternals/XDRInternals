function Get-XdrDefaultUserAgent {
    <#
    .SYNOPSIS
        Returns the default browser-compatible User-Agent string used by non-browser auth flows.

    .DESCRIPTION
        Returns the shared Windows Edge-style User-Agent string used by the non-browser
        authentication helpers when the caller does not explicitly override -UserAgent.
        This avoids the native PowerShell User-Agent, which can be blocked by Conditional Access.

    .OUTPUTS
        String. The default User-Agent value.

    .EXAMPLE
        Get-XdrDefaultUserAgent

        Returns the default browser-compatible User-Agent string.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param()

    # The native WebRequestSession default advertises PowerShell/<version>, which can be blocked by Conditional Access.
    # Use a browser-compatible Windows Edge UA for the non-browser auth flows unless the caller explicitly overrides it.
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
}