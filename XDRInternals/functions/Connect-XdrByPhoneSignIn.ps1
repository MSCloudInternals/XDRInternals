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
        Maximum time to wait for the phone sign-in approval to complete.

    .PARAMETER UserAgent
        User-Agent string for HTTP requests. Defaults to a browser-compatible Edge user agent.

    .EXAMPLE
        Connect-XdrByPhoneSignIn -Username 'admin@contoso.com'

        Starts the headless phone sign-in flow and connects to Defender XDR.

    .EXAMPLE
        Connect-XdrByPhoneSignIn -Username 'admin@contoso.com' -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2'

        Starts the headless phone sign-in flow and connects to the specified tenant.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [string]$Username,

        [string]$TenantId,

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 300,

        [string]$UserAgent = (Get-XdrDefaultUserAgent)
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

        Connect-XdrAuthArtifactSet -EstsAuthCookieValue $estsAuth -TenantId $TenantId -UserAgent $UserAgent -FailureLabel 'Phone sign-in'
    }
}
