function Connect-XdrByBrowser {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Defender XDR using an interactive browser sign-in.

    .DESCRIPTION
        Launches a dedicated Chromium-based browser profile, waits for you to complete the
        browser sign-in flow, captures the resulting authentication cookies, and establishes
        the Defender XDR session.

        This browser-driven flow is intended for interactive authentication branches such as
        FIDO2/passkeys and Temporary Access Pass.

        By default the cmdlet uses a dedicated secondary Chromium profile named XDRInternals so
        browser and device state can participate in authentication without reusing the user's
        primary profile. That dedicated profile is configured to open cleanly instead of restoring
        tabs from previous runs.

        On macOS and Linux, this cmdlet remains interactive. Complete any browser prompts until
        Microsoft Defender XDR finishes loading so the cmdlet can capture the final session cookies.

    .PARAMETER Username
        Optional username to display while completing the browser sign-in.
        If omitted, the browser sign-in flow lets you choose an account interactively.

    .PARAMETER TenantId
        Optional tenant ID to use when bootstrapping the Defender XDR session.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for the browser sign-in to complete.

    .PARAMETER BrowserPath
        Optional browser executable path or command name.
        When omitted, a supported Chromium-based browser is auto-discovered.

    .PARAMETER ProfilePath
        Optional dedicated browser user data directory.
        When omitted, a default secondary profile location is used for the XDRInternals profile.

    .PARAMETER ResetProfile
        Clears the dedicated browser profile before launching the sign-in flow.

    .PARAMETER PrivateSession
        Uses a temporary private/incognito browser session instead of the default dedicated profile.

    .PARAMETER UserAgent
        Optional User-Agent override for the launched browser.

    .EXAMPLE
        Connect-XdrByBrowser -Username 'admin@contoso.com'

        Launches the browser sign-in flow and connects to Defender XDR.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [string]$Username,

        [string]$TenantId,

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 300,

        [string]$BrowserPath,

        [string]$ProfilePath,

        [switch]$ResetProfile,

        [switch]$PrivateSession,

        [string]$UserAgent
    )

    process {
        if ($PrivateSession -and $ProfilePath) {
            throw 'Do not combine -PrivateSession with -ProfilePath. Private session uses a temporary profile automatically.'
        }

        $authParams = @{
            TimeoutSeconds = $TimeoutSeconds
        }
        if ($PSBoundParameters.ContainsKey('Username')) {
            $authParams.Username = $Username
        }
        if ($TenantId) {
            $authParams.TenantId = $TenantId
        }
        if ($BrowserPath) {
            $authParams.BrowserPath = $BrowserPath
        }
        if ($ProfilePath) {
            $authParams.ProfilePath = $ProfilePath
        }
        if ($ResetProfile) {
            $authParams.ResetProfile = $true
        }
        if ($PrivateSession) {
            $authParams.PrivateSession = $true
        }
        if ($UserAgent) {
            $authParams.UserAgent = $UserAgent
        }

        $browserAuth = Invoke-XdrBrowserAuthentication @authParams
        if (-not $browserAuth) {
            throw 'Browser sign-in failed - no authentication cookies were returned.'
        }

        $estsAuthCookieValue = if ($browserAuth -is [string]) { $browserAuth } else { $browserAuth.EstsAuthCookieValue }
        $sccAuthCookieValue = if ($browserAuth -is [string]) { $null } else { $browserAuth.SccAuthCookieValue }
        $xsrfToken = if ($browserAuth -is [string]) { $null } else { $browserAuth.XsrfToken }

        return Connect-XdrAuthArtifactSet -EstsAuthCookieValue $estsAuthCookieValue -SccAuthCookieValue $sccAuthCookieValue -XsrfToken $xsrfToken -TenantId $TenantId -ConnectionPreference PreferEsts -FallbackToPortalOnEstsBootstrapFailure -FailureLabel 'Browser sign-in'
    }
}