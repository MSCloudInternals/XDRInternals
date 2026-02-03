function Get-XdrCloudAppsConfigurationCustomParser {
    <#
    .SYNOPSIS
        Retrieves custom parsers from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the configured custom parsers from Microsoft Defender for Cloud Apps.
        Custom parsers define how traffic logs from non-standard sources are
        parsed and interpreted for cloud app discovery analysis.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationCustomParser
        Retrieves all custom parsers using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationCustomParser -Force
        Forces a fresh retrieval of all custom parsers, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationCustomParser | Select-Object name, _id
        Retrieves all custom parsers and displays name and ID.

    .OUTPUTS
        XdrCloudAppsConfigurationCustomParser[]
        Returns an array of custom parser objects containing parser configuration details.
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
        $CacheKey = "XdrCloudAppsConfigurationCustomParser"
        $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Cloud Apps custom parsers"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps custom parsers cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/custom_parsers/"
        $Body = @{
            skip              = 0
            limit             = 100
            filters           = @{}
            performAsyncTotal = $false
        } | ConvertTo-Json -Compress

        Write-Verbose "Retrieving Cloud Apps custom parsers"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result) {
                foreach ($item in $result) {
                    $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationCustomParser')
                }
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 30
            }

            return $result
        } catch {
            Write-Error "Failed to retrieve Cloud Apps custom parsers: $_"
        }
    }

    end {
    }
}
