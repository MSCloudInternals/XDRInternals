function Get-XdrCloudAppsWindowsDefenderStreamAvailable {
    <#
    .SYNOPSIS
        Checks if Windows Defender stream is available for Cloud Discovery.

    .DESCRIPTION
        Determines whether the Windows Defender ATP stream is available for Cloud Discovery
        in Microsoft Defender for Cloud Apps. This stream provides endpoint-based discovery
        data from devices managed by Microsoft Defender for Endpoint.

    .PARAMETER Force
        Bypasses the cache and forces a fresh API call to check availability.

    .EXAMPLE
        Get-XdrCloudAppsWindowsDefenderStreamAvailable

        Checks if the Windows Defender stream is available (uses cached result if available).

    .EXAMPLE
        Get-XdrCloudAppsWindowsDefenderStreamAvailable -Force

        Forces a fresh check of Windows Defender stream availability, bypassing the cache.

    .EXAMPLE
        if (Get-XdrCloudAppsWindowsDefenderStreamAvailable) {
            Write-Host "Windows Defender stream is available for Cloud Discovery"
        }

        Uses the result to conditionally execute code based on stream availability.

    .NOTES
        This cmdlet requires an active XDR session. Use Connect-XdrByEstsCookie to authenticate.
        Results are cached for 15 minutes to reduce API calls. Use -Force to bypass the cache.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/discovery/streams/windows-defender-stream-available/"
        $CacheKey = "XdrCloudAppsWindowsDefenderStreamAvailable"
    }

    process {
        # Check cache unless Force is specified
        if (-not $Force) {
            $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Returning cached Windows Defender stream availability"
                return $cache.Value
            }
        }

        Write-Verbose "Checking Windows Defender stream availability"

        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Write-Verbose "Successfully retrieved Windows Defender stream availability"

            # Cache the result for 15 minutes
            Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15

            return $result
        }
        catch {
            Write-Error "Failed to check Windows Defender stream availability: $_"
        }
    }
}
