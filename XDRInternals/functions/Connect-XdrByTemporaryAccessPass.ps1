function Connect-XdrByTemporaryAccessPass {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Defender XDR using a Temporary Access Pass (TAP).

    .DESCRIPTION
        Performs the Entra ID TAP web sign-in flow programmatically (no browser required),
        extracts the ESTSAUTH cookie, and then passes it to Connect-XdrByEstsCookie to
        establish an authenticated Defender XDR session.

        TAP sign-in is tenant-scoped, so TenantId is required and is used both for the Entra
        authorize request and for the Defender XDR tenant bootstrap.

    .PARAMETER Username
        The user principal name (e.g., admin@contoso.com).
        If omitted, you are prompted interactively.

    .PARAMETER TemporaryAccessPass
        The Temporary Access Pass as a SecureString.
        If omitted, you are prompted interactively.

    .PARAMETER TenantId
        The Entra tenant ID used for TAP authentication and the Defender XDR connection.

    .PARAMETER UserAgent
        User-Agent string for HTTP requests. Defaults to Edge browser user agent.

    .EXAMPLE
        $tap = ConvertTo-SecureString '+&YZuead' -AsPlainText -Force
        Connect-XdrByTemporaryAccessPass -Username 'admin@contoso.com' -TemporaryAccessPass $tap -TenantId '847b5907-ca15-40f4-b171-eb18619dbfab'

        Authenticates using the supplied TAP and connects to Defender XDR.

    .EXAMPLE
        Connect-XdrByTemporaryAccessPass -TenantId '847b5907-ca15-40f4-b171-eb18619dbfab'

        Prompts for username and TAP, then authenticates and connects.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param (
        [string]$Username,

        [Alias('TAP')]
        [SecureString]$TemporaryAccessPass,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0'
    )

    process {
        $resolvedUsername = $Username
        $resolvedTap = $TemporaryAccessPass

        if (-not $resolvedUsername) {
            $resolvedUsername = Read-Host 'Username'
        }

        if (-not $resolvedTap) {
            $resolvedTap = Read-Host -AsSecureString "Temporary Access Pass for $resolvedUsername"
        }

        if (-not $resolvedUsername) {
            throw 'No username provided.'
        }

        if (-not $resolvedTap) {
            throw 'No Temporary Access Pass provided.'
        }

        Write-Host "Authenticating as $resolvedUsername with Temporary Access Pass..."

        $tapParams = @{
            Username            = $resolvedUsername
            TemporaryAccessPass = $resolvedTap
            TenantId            = $TenantId
            UserAgent           = $UserAgent
        }

        $estsAuth = Invoke-XdrTemporaryAccessPassAuthentication @tapParams
        if (-not $estsAuth) {
            throw 'Temporary Access Pass authentication failed - no ESTS cookie was returned.'
        }

        Connect-XdrByEstsCookie -EstsAuthCookieValue $estsAuth -TenantId $TenantId -UserAgent $UserAgent
    }
}