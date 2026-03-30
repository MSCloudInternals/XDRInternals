function Connect-XdrAuthArtifactSet {
    [CmdletBinding()]
    param(
        [string]$EstsAuthCookieValue,

        [string]$SccAuthCookieValue,

        [string]$XsrfToken,

        [string]$TenantId,

        [string]$UserAgent,

        [ValidateSet('PreferEsts', 'PreferPortal')]
        [string]$ConnectionPreference = 'PreferEsts',

        [switch]$FallbackToPortalOnEstsBootstrapFailure,

        [string]$FailureLabel = 'Authentication'
    )

    $hasEsts = -not [string]::IsNullOrWhiteSpace($EstsAuthCookieValue)
    $hasPortalCookies = -not [string]::IsNullOrWhiteSpace($SccAuthCookieValue)

    if (-not $hasEsts -and -not $hasPortalCookies) {
        throw "$FailureLabel failed - no supported authentication cookies were returned."
    }

    $estsConnectParams = $null
    if ($hasEsts) {
        $estsConnectParams = @{ EstsAuthCookieValue = $EstsAuthCookieValue }
        if ($TenantId) {
            $estsConnectParams.TenantId = $TenantId
        }
        if (-not [string]::IsNullOrWhiteSpace($UserAgent)) {
            $estsConnectParams.UserAgent = $UserAgent
        }
    }

    $portalConnectParams = $null
    if ($hasPortalCookies) {
        $portalConnectParams = @{ SccAuth = $SccAuthCookieValue }
        if ($XsrfToken) {
            $portalConnectParams.Xsrf = $XsrfToken
        }
        if ($TenantId) {
            $portalConnectParams.TenantId = $TenantId
        }
    }

    $attemptOrder = if ($ConnectionPreference -eq 'PreferPortal') {
        @('Portal', 'Ests')
    } else {
        @('Ests', 'Portal')
    }

    foreach ($attempt in $attemptOrder) {
        switch ($attempt) {
            'Ests' {
                if (-not $estsConnectParams) {
                    continue
                }

                try {
                    return Connect-XdrByEstsCookie @estsConnectParams
                } catch {
                    if (-not $FallbackToPortalOnEstsBootstrapFailure -or -not $portalConnectParams) {
                        throw
                    }

                    if ($_.Exception.Message -notmatch 'Session information is not sufficient for single-sign-on') {
                        throw
                    }

                    Write-Verbose 'ESTS bootstrap was not sufficient for Defender SSO. Falling back to the captured Defender portal session cookies.'
                    return Set-XdrConnectionSettings @portalConnectParams
                }
            }

            'Portal' {
                if (-not $portalConnectParams) {
                    continue
                }

                return Set-XdrConnectionSettings @portalConnectParams
            }
        }
    }

    throw "$FailureLabel failed - no supported authentication cookies were returned."
}