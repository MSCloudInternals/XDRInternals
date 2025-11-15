function Update-XdrConnectionSettings {
    [CmdletBinding()]
    param (

    )
    
    Write-Verbose "Updating session cookies for XDR webpage requests"
    # Check if script variables exist
    if (Test-Path variable:script:session) {
        # Update session and headers in script scope
        $PreviousXSRFValue = $script:session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value
        $PreviousSccAuthValue = $script:session.cookies.GetCookies("https://security.microsoft.com")['sccauth'].Value
        $null = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $script:session -Method Get -Uri "https://security.microsoft.com/" -Verbose:$false
    } else {
        throw "Not connected to XDR. Please run Connect-XdrByEstsCookie or Set-XdrConnectionSettings first."
    }

    if ($PreviousXSRFValue -ne $script:session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value) {
        Write-Verbose "XSRF token has been updated."
        [Hashtable]$script:headers = @{}
        $script:headers["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value)
    } else {
        Write-Verbose "XSRF token remains unchanged."
    }
    if ($PreviousSccAuthValue -ne $script:session.cookies.GetCookies("https://security.microsoft.com")['sccauth'].Value) {
        Write-Verbose "sccauth cookie has been updated."
    } else {
        Write-Verbose "sccauth cookie remains unchanged."
    }
}