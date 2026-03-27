function Connect-XdrByPhoneSignIn {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Defender XDR using Microsoft Authenticator phone sign-in.

    .DESCRIPTION
        Starts the Defender portal phone sign-in flow without launching a browser, shows the
        number returned by Entra ID when available, waits for Microsoft Authenticator approval,
        captures the resulting ESTSAUTH cookie, and then passes it to Connect-XdrByEstsCookie
        to establish the Defender XDR session.

    .PARAMETER Username
        Optional username to use for phone sign-in.
        If omitted, you are prompted interactively.

    .PARAMETER TenantId
        Optional tenant ID to use when bootstrapping the Defender XDR session.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for the browser sign-in to complete.

    .PARAMETER UserAgent
        User-Agent string for HTTP requests. Defaults to Edge browser user agent.

    .EXAMPLE
        Connect-XdrByPhoneSignIn -Username 'admin@contoso.com'

        Starts the headless phone sign-in flow and connects to Defender XDR.

    .EXAMPLE
        Connect-XdrByPhoneSignIn -Username 'admin@contoso.com' -TenantId '847b5907-ca15-40f4-b171-eb18619dbfab'

        Starts the headless phone sign-in flow and connects to the specified tenant.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [string]$Username,

        [string]$TenantId,

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 300,

        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
    )

    process {
        $resolvedUsername = $Username
        if (-not $resolvedUsername) {
            $resolvedUsername = Read-Host 'Username'
        }

        if (-not $resolvedUsername) {
            throw 'No username provided.'
        }

        $estsAuth = Invoke-XdrPhoneSignInAuthentication -Username $resolvedUsername -TimeoutSeconds $TimeoutSeconds -UserAgent $UserAgent
        if (-not $estsAuth) {
            throw 'Phone sign-in failed - no ESTS cookie was returned.'
        }

        $connectParams = @{ EstsAuthCookieValue = $estsAuth }
        if ($TenantId) {
            $connectParams.TenantId = $TenantId
        }

        Connect-XdrByEstsCookie @connectParams
    }
}