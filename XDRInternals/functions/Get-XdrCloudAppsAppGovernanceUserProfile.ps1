function Get-XdrCloudAppsAppGovernanceUserProfile {
    <#
    .SYNOPSIS
        Retrieves the current user's App Governance profile.

    .DESCRIPTION
        Gets the current user's profile information from Microsoft Defender for
        Cloud Apps App Governance. This includes user-specific settings and
        permissions within the App Governance feature.
        This function includes caching support with a 15-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernanceUserProfile
        Retrieves the current user's App Governance profile using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernanceUserProfile -Force
        Forces a fresh retrieval of the user profile, bypassing the cache.

    .EXAMPLE
        $profile = Get-XdrCloudAppsAppGovernanceUserProfile
        $profile | Format-List
        Retrieves the user profile and displays all properties in list format.

    .OUTPUTS
        XdrCloudAppsAppGovernanceUserProfile
        Returns an object containing the current user's App Governance profile.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCloudAppsAppGovernanceUserProfile"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached App Governance user profile"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "App Governance user profile cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/getUserProfile"

        Write-Verbose "Retrieving App Governance user profile"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppGovernanceUserProfile')
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve App Governance user profile: $_"
        }
    }

    end {
    }
}
