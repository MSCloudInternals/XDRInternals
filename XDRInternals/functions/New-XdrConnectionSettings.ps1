function New-XdrConnectionSettings {
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
        Should be 347 characters in length.
    
    .EXAMPLE
        New-XdrConnectionSettings -sccauth "your_sccauth_value" -xsrf "your_xsrf_value"
        Creates XDR connection settings using the provided authentication cookies.
    
    .OUTPUTS
        String
        Returns a confirmation message when connection settings are created.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$sccauth,

        [Parameter()]
        [string]$xsrf
    )
    
    if ($xsrf.Length -ne 347) { Write-Warning "xsrf was $($xsrf.Length) characters and may be incorrect" }

    # Create session and cookies
    $global:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $global:session.Cookies.Add((New-Object System.Net.Cookie("sccauth", $sccauth, "/", "security.microsoft.com")))
    $global:session.Cookies.Add((New-Object System.Net.Cookie("XSRF-TOKEN", $xsrf, "/", "security.microsoft.com")))

    # Set the headers to include the xsrf token
    [Hashtable]$global:headers = @{}
    $global:headers["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value)
    Write-Output "XDR Connection Settings created"
    Write-Output "You can now run other XDRInternals cmdlets to interact with the XDR portal."
}