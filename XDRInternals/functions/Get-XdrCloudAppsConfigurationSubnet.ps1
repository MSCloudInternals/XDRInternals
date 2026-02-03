function Get-XdrCloudAppsConfigurationSubnet {
    <#
    .SYNOPSIS
        Retrieves subnet configurations from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured subnets from Microsoft Defender for Cloud Apps.
        Subnets allow you to define IP address ranges for categorization,
        policy application, and location-based reporting.
        Use the -Metadata switch to retrieve filter and sorting field definitions.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Metadata
        Returns metadata about available filters and sorting options instead of subnets.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSubnet
        Retrieves all subnet configurations using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSubnet -Force
        Forces a fresh retrieval of all subnet configurations, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSubnet | Where-Object { $_.name -like '*Corporate*' }
        Retrieves all subnets and filters for those with 'Corporate' in the name.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSubnet -Metadata
        Retrieves metadata about available filters and sorting options for subnets.

    .OUTPUTS
        XdrCloudAppsConfigurationSubnet[]
        Returns an array of subnet objects, or metadata if -Metadata is specified.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Metadata is a common term in the API naming convention')]
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Metadata,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($Metadata) {
            $CacheKey = "XdrCloudAppsConfigurationSubnetMetadata"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps subnet metadata"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps subnet metadata cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/subnet/metadata/"
            Write-Verbose "Retrieving Cloud Apps subnet metadata"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                if ($null -ne $result) {
                    $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationSubnetMetadata')
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps subnet metadata: $_"
            }
        } else {
            $CacheKey = "XdrCloudAppsConfigurationSubnet"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps subnet configurations"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps subnet configurations cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/subnet/"
            $Body = @{
                skip              = 0
                limit             = 100
                filters           = @{}
                performAsyncTotal = $false
                sortDirection     = "desc"
                sortField         = "name"
            } | ConvertTo-Json -Compress

            Write-Verbose "Retrieving Cloud Apps subnet configurations"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = $response.data
                if ($null -ne $result) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationSubnet')
                    }
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps subnet configurations: $_"
            }
        }
    }

    end {
    }
}
