function Connect-XdrBySSO {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Defender XDR using browser-based single sign-on.

    .DESCRIPTION
        Starts a dedicated browser profile, attempts silent sign-in using the local browser and
        operating-system account state, captures Defender portal cookies, and configures the
        XDR session. This cmdlet is intended for Windows-first SSO scenarios, but it can also
        reuse existing Chromium browser session state on macOS and Linux when that browser state
        is already available.

        Use -Visible when validating or troubleshooting the flow so you can confirm the browser
        reaches the Defender portal before the cmdlet captures the resulting session cookies.

    .PARAMETER TenantId
        Optional tenant ID (GUID) to select from the authenticated SSO session.
        If only an ESTS cookie is captured, the requested tenant ID is passed to the ESTS
        bootstrap step.

    .PARAMETER Visible
        Shows the browser window instead of using the default headless launch.

    .PARAMETER SkipTenantSelection
        Automatically uses the selected tenant or the first available tenant when multiple tenants are available.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for SSO authentication to complete.

    .PARAMETER BrowserPath
        Optional browser executable path or command name.

    .PARAMETER ProfilePath
        Optional persistent browser profile path used for SSO.

    .PARAMETER UserAgent
        Optional User-Agent override for the launched browser.

    .EXAMPLE
        Connect-XdrBySSO

        Attempts browser-based SSO using the default dedicated profile.

    .EXAMPLE
        Connect-XdrBySSO -Visible

        Shows the browser window while the SSO flow completes.
    #>
    [CmdletBinding()]
    param(
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$TenantId,

        [switch]$Visible,

        [switch]$SkipTenantSelection,

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 180,

        [string]$BrowserPath,

        [string]$ProfilePath,

        [string]$UserAgent
    )

    process {
        $authParams = @{
            Visible             = $Visible
            SkipTenantSelection = $SkipTenantSelection
            TimeoutSeconds      = $TimeoutSeconds
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
        if ($UserAgent) {
            $authParams.UserAgent = $UserAgent
        }

        $ssoAuth = Invoke-XdrSsoAuthentication @authParams
        if (-not $ssoAuth) {
            throw 'SSO authentication failed - no authentication cookies were returned.'
        }

        $resolvedTenantId = if ($ssoAuth.SelectedTenantId) {
            $ssoAuth.SelectedTenantId
        } elseif (-not $ssoAuth.SccAuthCookieValue -and $TenantId) {
            $TenantId
        } else {
            $null
        }

        return Connect-XdrAuthArtifactSet -EstsAuthCookieValue $ssoAuth.EstsAuthCookieValue -SccAuthCookieValue $ssoAuth.SccAuthCookieValue -XsrfToken $ssoAuth.XsrfToken -TenantId $resolvedTenantId -ConnectionPreference PreferPortal -FailureLabel 'SSO authentication'
    }
}