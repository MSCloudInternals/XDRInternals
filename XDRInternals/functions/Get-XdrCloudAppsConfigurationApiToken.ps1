function Get-XdrCloudAppsConfigurationApiToken {
    <#
    .SYNOPSIS
        Retrieves API tokens from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured API tokens from Microsoft Defender for Cloud Apps,
        including token details, creation dates, and associated permissions.
        Use the -Metadata switch to retrieve filter and sorting field definitions
        instead of the actual tokens.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Metadata
        Returns metadata about available filters and sorting options instead of tokens.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationApiToken
        Retrieves the Cloud Apps API tokens using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationApiToken -Force
        Forces a fresh retrieval of the Cloud Apps API tokens, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationApiToken -Metadata
        Retrieves metadata about available filters and sorting options for API tokens.

    .OUTPUTS
        XdrCloudAppsConfigurationApiToken
        Returns the Cloud Apps API token objects, or metadata if -Metadata is specified.
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
            $CacheKey = "XdrCloudAppsConfigurationApiTokenMetadata"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps API token metadata"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps API token metadata cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/tokens/metadata/"
            Write-Verbose "Retrieving Cloud Apps API token metadata"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                if ($null -ne $result) {
                    $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationApiTokenMetadata')
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps API token metadata: $_"
            }
        } else {
            $CacheKey = "XdrCloudAppsConfigurationApiToken"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps API tokens"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps API tokens cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/tokens/"
            $Body = @{
                skip              = 0
                limit             = 100
                filters           = @{}
                performAsyncTotal = $false
                sortDirection     = "desc"
                sortField         = "created"
            } | ConvertTo-Json -Compress

            Write-Verbose "Retrieving Cloud Apps API tokens"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                $result = $response.data

                if ($null -ne $result) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationApiToken')
                    }
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps API tokens: $_"
            }
        }
    }

    end {
    }
}
