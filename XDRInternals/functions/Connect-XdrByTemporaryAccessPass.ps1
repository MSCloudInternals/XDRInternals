function Connect-XdrByTemporaryAccessPass {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Defender XDR using a Temporary Access Pass (TAP).

    .DESCRIPTION
        Performs the Entra ID TAP web sign-in flow programmatically (no browser required),
        extracts the ESTSAUTH cookie, and then passes it to Connect-XdrByEstsCookie to
        establish an authenticated Defender XDR session.

        TAP sign-in is tenant-scoped. If TenantId is omitted, the cmdlet attempts to resolve the
        tenant automatically from the supplied username before starting the Entra authorize flow.

    .PARAMETER Username
        The user principal name (e.g., admin@contoso.com).
        If omitted, you are prompted interactively.

    .PARAMETER TemporaryAccessPass
        The Temporary Access Pass as a SecureString.
        If omitted, you are prompted interactively.

    .PARAMETER TenantId
        The Entra tenant ID used for TAP authentication and the Defender XDR connection.
        If omitted, the cmdlet resolves the tenant from Username.

    .PARAMETER UserAgent
        User-Agent string for HTTP requests. Defaults to a browser-compatible Edge user agent.

    .EXAMPLE
        $tap = ConvertTo-SecureString '+&YZuead' -AsPlainText -Force
        Connect-XdrByTemporaryAccessPass -Username 'admin@contoso.com' -TemporaryAccessPass $tap -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2'

        Authenticates using the supplied TAP and connects to Defender XDR.

    .EXAMPLE
        Connect-XdrByTemporaryAccessPass -TenantId '8612f621-73ca-4c12-973c-0da732bc44c2'

        Prompts for username and TAP, then authenticates and connects.

    .EXAMPLE
        Connect-XdrByTemporaryAccessPass -Username 'admin@contoso.com'

        Prompts for the TAP, resolves the tenant automatically from the username, then authenticates
        and connects.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param (
        [string]$Username,

        [Alias('TAP')]
        [SecureString]$TemporaryAccessPass,

        [string]$TenantId,

        [string]$UserAgent = (Get-XdrDefaultUserAgent)
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
            $failure = Get-XdrAuthenticationFailure -AuthenticationMethod TemporaryAccessPass -Stage InputValidation -DefaultCode RequestInvalid
            throw (New-XdrAuthenticationErrorRecord -Failure $failure)
        }

        if (-not $resolvedTap) {
            $failure = Get-XdrAuthenticationFailure -AuthenticationMethod TemporaryAccessPass -Stage InputValidation -DefaultCode RequestInvalid
            throw (New-XdrAuthenticationErrorRecord -Failure $failure)
        }

        $resolvedTenantId = $TenantId
        if (-not $resolvedTenantId) {
            try {
                $resolvedTenantId = Resolve-XdrTenantIdFromUsername -Username $resolvedUsername -UserAgent $UserAgent
            } catch {
                $failure = Get-XdrAuthenticationFailure -ErrorRecord $_ -AuthenticationMethod TemporaryAccessPass -Stage TenantResolution -DefaultCode InvalidTenant
                throw (New-XdrAuthenticationErrorRecord -Failure $failure -ErrorRecord $_)
            }
        }

        Write-Host "Authenticating as $resolvedUsername with Temporary Access Pass..."

        $tapParams = @{
            Username            = $resolvedUsername
            TemporaryAccessPass = $resolvedTap
            TenantId            = $resolvedTenantId
            UserAgent           = $UserAgent
        }

        try {
            $estsAuth = Invoke-XdrTemporaryAccessPassAuthentication @tapParams
        } catch {
            $failure = Get-XdrAuthenticationFailure -ErrorRecord $_ -AuthenticationMethod TemporaryAccessPass -Stage SignIn
            throw (New-XdrAuthenticationErrorRecord -Failure $failure -ErrorRecord $_)
        }
        if (-not $estsAuth) {
            $failure = Get-XdrAuthenticationFailure -AuthenticationMethod TemporaryAccessPass -Stage ArtifactCapture -DefaultCode NoAuthenticationArtifact
            throw (New-XdrAuthenticationErrorRecord -Failure $failure)
        }

        Connect-XdrAuthArtifactSet -EstsAuthCookieValue $estsAuth -TenantId $resolvedTenantId -UserAgent $UserAgent -FailureLabel 'Temporary Access Pass authentication'
    }
}
