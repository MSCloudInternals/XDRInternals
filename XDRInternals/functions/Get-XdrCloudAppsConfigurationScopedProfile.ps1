function Get-XdrCloudAppsConfigurationScopedProfile {
    <#
    .SYNOPSIS
        Retrieves scoped profiles from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the scoped profiles from Microsoft Defender for Cloud Apps.
        Scoped profiles allow you to define groups of users or organizational units
        for targeted policy application. Optionally retrieves tagged apps associated
        with a specific profile.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER ProfileId
        The ID of a specific scoped profile to retrieve tagged apps for.
        Required when using the -GetTaggedApps switch.

    .PARAMETER GetTaggedApps
        When specified, retrieves the tagged apps associated with the profile
        specified by ProfileId. Requires ProfileId parameter.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedProfile
        Retrieves all scoped profiles using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedProfile -Force
        Forces a fresh retrieval of all scoped profiles, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedProfile -ProfileId "abc123" -GetTaggedApps
        Retrieves the tagged apps associated with the specified profile.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationScopedProfile | Where-Object { $_.name -like '*Sales*' }
        Retrieves all scoped profiles and filters for those with 'Sales' in the name.

    .OUTPUTS
        XdrCloudAppsConfigurationScopedProfile[]
        Returns an array of scoped profile objects or tagged app objects.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$ProfileId,

        [Parameter()]
        [switch]$GetTaggedApps,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings

        if ($GetTaggedApps -and [string]::IsNullOrEmpty($ProfileId)) {
            throw "ProfileId is required when using the -GetTaggedApps switch."
        }
    }

    process {
        if ($GetTaggedApps) {
            $CacheKey = "XdrCloudAppsConfigurationScopedProfileTaggedApps_$ProfileId"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps scoped profile tagged apps for profile $ProfileId"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps scoped profile tagged apps cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/scoped_profiles/get_tagged_apps_for_profile/?profileId=$ProfileId"
            Write-Verbose "Retrieving Cloud Apps scoped profile tagged apps for profile $ProfileId"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                if ($null -ne $result) {
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps scoped profile tagged apps: $_"
            }
        } else {
            $CacheKey = "XdrCloudAppsConfigurationScopedProfile"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps scoped profiles"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps scoped profiles cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/scoped_profiles/"
            $Body = @{
                skip              = 0
                limit             = 100
                filters           = @{}
                performAsyncTotal = $false
                sortDirection     = "desc"
                sortField         = "name"
            } | ConvertTo-Json -Compress

            Write-Verbose "Retrieving Cloud Apps scoped profiles"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = $response.data
                if ($null -ne $result) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationScopedProfile')
                    }
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps scoped profiles: $_"
            }
        }
    }

    end {
    }
}
