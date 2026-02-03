function Get-XdrCloudAppsConfigurationConnectedService {
    <#
    .SYNOPSIS
        Retrieves connected services from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the connected services from Microsoft Defender for Cloud Apps,
        including app hierarchy or service instances depending on the parameter.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER GetHierarchy
        When true (default), retrieves the connected services app hierarchy.
        When false, retrieves the connected service instances.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationConnectedService
        Retrieves the Cloud Apps connected services app hierarchy using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationConnectedService -GetHierarchy $false
        Retrieves the Cloud Apps connected service instances.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationConnectedService -Force
        Forces a fresh retrieval of the Cloud Apps connected services, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsConfigurationConnectedService
        Returns the Cloud Apps connected services object.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [bool]$GetHierarchy = $true,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($GetHierarchy) {
            $CacheKey = "XdrCloudAppsConfigurationConnectedServiceHierarchy"
            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/connected_services/apps/?getHierarchy=true"
            Write-Verbose "Retrieving Cloud Apps connected services app hierarchy"
        } else {
            $CacheKey = "XdrCloudAppsConfigurationConnectedServiceInstances"
            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/connected_services/instances/"
            Write-Verbose "Retrieving Cloud Apps connected service instances"
        }

        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps connected services"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps connected services cache is missing or expired"
        }

        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            if ($null -ne $result) {
                foreach ($item in $result) {
                    $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationConnectedService')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps connected services: $_"
        }
    }

    end {
    }
}
