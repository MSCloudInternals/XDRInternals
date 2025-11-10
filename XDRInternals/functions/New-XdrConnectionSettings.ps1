function New-XdrConnectionSettings {
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
}