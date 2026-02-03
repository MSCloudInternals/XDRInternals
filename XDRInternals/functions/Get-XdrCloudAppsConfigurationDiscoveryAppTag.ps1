function Get-XdrCloudAppsConfigurationDiscoveryAppTag {
    <#
    .SYNOPSIS
        Retrieves discovery app tags from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured discovery app tags from Microsoft Defender for Cloud Apps.
        App tags are used to categorize and label discovered cloud applications
        for organization and filtering purposes.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryAppTag
        Retrieves all discovery app tags using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryAppTag -Force
        Forces a fresh retrieval of all discovery app tags, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryAppTag | Select-Object name, _id
        Retrieves all discovery app tags and displays name and ID.

    .OUTPUTS
        XdrCloudAppsConfigurationDiscoveryAppTag[]
        Returns an array of discovery app tag objects containing tag configuration details.
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
        $CacheKey = "XdrCloudAppsConfigurationDiscoveryAppTag"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps discovery app tags"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps discovery app tags cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/app_tags/"
        $Body = @{
            skip              = 0
            limit             = 100
            filters           = @{}
            performAsyncTotal = $false
        } | ConvertTo-Json -Compress

        Write-Verbose "Retrieving Cloud Apps discovery app tags"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                foreach ($item in $result) {
                    $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationDiscoveryAppTag')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps discovery app tags: $_"
        }
    }

    end {
    }
}
