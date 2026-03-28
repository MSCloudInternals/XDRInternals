function Connect-XdrBySSO {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Defender XDR using browser-based single sign-on.

    .DESCRIPTION
        Starts a dedicated browser profile, attempts silent sign-in using the local browser and
        operating-system account state, captures Defender portal cookies, and configures the
        XDR session. This cmdlet is intended for Windows-first SSO scenarios and keeps the
        interactive browser cmdlets focused on explicit sign-in flows.

    .PARAMETER TenantId
        Optional tenant identifier or partial tenant name used to select the final tenant.

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

        Attempts silent browser SSO using the default dedicated profile.

    .EXAMPLE
        Connect-XdrBySSO -Visible

        Shows the browser window while the SSO flow completes.
    #>
    [CmdletBinding()]
    param(
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

        $resolvedTenantId = if ($ssoAuth.SelectedTenantId) { $ssoAuth.SelectedTenantId } else { $null }

        return Connect-XdrAuthArtifactSet -EstsAuthCookieValue $ssoAuth.EstsAuthCookieValue -SccAuthCookieValue $ssoAuth.SccAuthCookieValue -XsrfToken $ssoAuth.XsrfToken -TenantId $resolvedTenantId -ConnectionPreference PreferPortal -FailureLabel 'SSO authentication'
    }
}