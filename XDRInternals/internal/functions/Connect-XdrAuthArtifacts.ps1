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
        $failure = Get-XdrAuthenticationFailure -AuthenticationMethod $FailureLabel -Stage ArtifactCapture -DefaultCode NoAuthenticationArtifact
        throw (New-XdrAuthenticationErrorRecord -Failure $failure)
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

    $attemptFailures = [ordered]@{}
    $lastError = $null
    foreach ($attempt in $attemptOrder) {
        switch ($attempt) {
            'Ests' {
                if (-not $estsConnectParams) {
                    continue
                }

                try {
                    return Connect-XdrByEstsCookie @estsConnectParams
                } catch {
                    $lastError = $_
                    $attemptFailure = Get-XdrAuthenticationFailure -ErrorRecord $_ -AuthenticationMethod $FailureLabel -Stage EstsBootstrap -DefaultCode BootstrapFailed
                    $attemptFailures['ESTS'] = $attemptFailure.Code
                    if ($attemptFailures.Count -ge 2) {
                        continue
                    }
                    if (-not $FallbackToPortalOnEstsBootstrapFailure -or -not $portalConnectParams) {
                        throw (New-XdrAuthenticationErrorRecord -Failure $attemptFailure -ErrorRecord $_)
                    }

                    if ($attemptFailure.Code -eq 'SessionUnavailable') {
                        Write-Verbose 'ESTS bootstrap was not sufficient for Defender SSO. Falling back to the captured Defender portal session cookies.'
                    } else {
                        Write-Verbose "ESTS bootstrap failed with classification $($attemptFailure.Code). Falling back to the captured Defender portal session cookies."
                    }

                    continue
                }
            }

            'Portal' {
                if (-not $portalConnectParams) {
                    continue
                }

                try {
                    return Set-XdrConnectionSettings @portalConnectParams
                } catch {
                    $lastError = $_
                    $attemptFailure = Get-XdrAuthenticationFailure -ErrorRecord $_ -AuthenticationMethod $FailureLabel -Stage PortalBootstrap -DefaultCode BootstrapFailed
                    $attemptFailures['Portal'] = $attemptFailure.Code
                    if ($attemptFailures.Count -ge 2) {
                        continue
                    }
                    if (-not $estsConnectParams -or $ConnectionPreference -ne 'PreferPortal') {
                        throw (New-XdrAuthenticationErrorRecord -Failure $attemptFailure -ErrorRecord $_)
                    }

                    Write-Verbose "Defender portal bootstrap failed with classification $($attemptFailure.Code). Falling back to ESTS cookie bootstrap."
                    continue
                }
            }
        }
    }

    $attemptSummary = @($attemptFailures.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)" }) -join '; '
    $failure = Get-XdrAuthenticationFailure -AuthenticationMethod $FailureLabel -Stage Bootstrap -DefaultCode BootstrapFailed -SafeEvidence @{ Attempt = $attemptSummary }
    throw (New-XdrAuthenticationErrorRecord -Failure $failure -ErrorRecord $lastError)
}
