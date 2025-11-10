
function Connect-XdrWebsite {
    <#
    .SYNOPSIS
        Establishes an authenticated session to the Microsoft Defender XDR portal.
    
    .DESCRIPTION
        Connects to security.microsoft.com using an ESTSAUTHPERSISTENT cookie value to establish
        an authenticated web session. This function creates global session and headers variables
        that can be used by other XDR cmdlets to interact with the portal APIs.
    
    .PARAMETER ESTSAUTHCookieValue
        The ESTSAUTHPERSISTENT cookie value from an authenticated browser session.
    
    .PARAMETER UserAgent
        The User-Agent string to use for the web requests. Defaults to Edge browser user agent.
    
    .EXAMPLE
        Connect-XdrWebsite -ESTSAUTHCookieValue "your_cookie_value_here"
        Connects to the XDR portal using the provided authentication cookie.
    
    .OUTPUTS
        String
        Returns a confirmation message when successfully connected.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ESTSAUTHCookieValue,

        [Parameter()]
        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
    )

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = $UserAgent
    # Bootstrap the session by making an initial request to login.microsoftonline.com
    $null = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 99 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/error"

    $cookie = [System.Net.Cookie]::new("ESTSAUTHPERSISTENT", $ESTSAUTHCookieValue)
    $session.Cookies.Add('https://login.microsoftonline.com/', $cookie)
    $SessionCookies = $session.Cookies.GetCookies('https://login.microsoftonline.com') | Select-Object -ExpandProperty Name
    Write-Verbose "Session cookies: $( $SessionCookies -join ', ' )"

    # Invoke a GET request to security.microsoft.com to initiate the authentication flow
    $SecurityPortal = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://security.microsoft.com/"
    $requiredFields = @("code", "id_token", "state", "session_state", "correlation_id")
    # Check if all required fields are present in returned input fields
    foreach ($field in $requiredFields) {
        if (-not ($SecurityPortal.InputFields.name -contains $field)) {
            throw "Required field '$field' is missing from the response."
        }
    }
    $SessionCookies = $session.Cookies.GetCookies('https://security.microsoft.com') | Select-Object -ExpandProperty Name
    Write-Verbose "Session cookies: $( $SessionCookies -join ', ' )"

    # Invoke a POST request to get the session cookies for security.microsoft.com
    $Headers = @{
        code           = $SecurityPortal.InputFields | Where-Object { $_.name -eq "code" } | Select-Object -ExpandProperty value
        id_token       = $SecurityPortal.InputFields | Where-Object { $_.name -eq "id_token" } | Select-Object -ExpandProperty value
        state          = $SecurityPortal.InputFields | Where-Object { $_.name -eq "state" } | Select-Object -ExpandProperty value
        session_state  = $SecurityPortal.InputFields | Where-Object { $_.name -eq "session_state" } | Select-Object -ExpandProperty value
        correlation_id = $SecurityPortal.InputFields | Where-Object { $_.name -eq "correlation_id" } | Select-Object -ExpandProperty value
    }
    $AuthResponse = Invoke-WebRequest -UseBasicParsing -ErrorAction SilentlyContinue -WebSession $session -Method Post -Uri "https://security.microsoft.com/" -Headers $Headers
    $SessionCookies = $session.Cookies.GetCookies('https://security.microsoft.com') | Select-Object -ExpandProperty Name
    Write-Verbose "Session cookies: $( $SessionCookies -join ', ' )"

    $sccauth = $session.cookies.GetCookies("https://security.microsoft.com")['sccauth'].Value
    $xsrf = $session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value

    # Create session and cookies
    New-XdrConnectionSettings -sccauth $sccauth -xsrf $xsrf
}