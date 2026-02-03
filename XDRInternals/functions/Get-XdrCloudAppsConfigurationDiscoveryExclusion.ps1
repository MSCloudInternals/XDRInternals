function Get-XdrCloudAppsConfigurationDiscoveryExclusion {
    <#
    .SYNOPSIS
        Retrieves discovery exclusions from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured discovery exclusions from Microsoft Defender for Cloud Apps.
        Discovery exclusions define users, devices, or IP addresses that should be
        excluded from cloud app discovery analysis.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER EntityType
        Specifies the type of exclusions to retrieve.
        Valid values are 'User', 'Device', 'IP', or 'All'.
        Default is 'All' which retrieves all exclusion types.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryExclusion
        Retrieves all discovery exclusions using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryExclusion -EntityType User
        Retrieves only user exclusions.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryExclusion -EntityType IP
        Retrieves only IP address exclusions.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryExclusion -Force
        Forces a fresh retrieval of all discovery exclusions, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsConfigurationDiscoveryExclusion[]
        Returns an array of discovery exclusion objects containing exclusion configuration details.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('User', 'Device', 'IP', 'All')]
        [string]$EntityType = 'All',

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCloudAppsConfigurationDiscoveryExclusion-$EntityType"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps discovery exclusions"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps discovery exclusions cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/exclude_entities/"
        $Body = @{
            skip              = 0
            limit             = 100
            filters           = @{}
            performAsyncTotal = $false
        } | ConvertTo-Json -Compress

        Write-Verbose "Retrieving Cloud Apps discovery exclusions (EntityType: $EntityType)"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }

            # Filter by EntityType if not 'All'
            if ($EntityType -ne 'All' -and $null -ne $result) {
                $result = $result | Where-Object {
                    $_.entityType -eq $EntityType -or
                    $_.type -eq $EntityType -or
                    $_.excludeType -eq $EntityType
                }
            }

            if ($null -ne $result) {
                foreach ($item in $result) {
                    $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationDiscoveryExclusion')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps discovery exclusions: $_"
        }
    }

    end {
    }
}
