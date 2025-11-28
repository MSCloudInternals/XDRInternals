function Get-XdrStreamingApiConfiguration {
    <#
    .SYNOPSIS
        Retrieves Streaming API configuration from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the Streaming API data export settings from the Microsoft Defender XDR portal,
        including workspace properties and log streaming configuration.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrStreamingApiConfiguration
        Retrieves the Streaming API configuration using cached data if available.

    .EXAMPLE
        Get-XdrStreamingApiConfiguration -Force
        Forces a fresh retrieval of the Streaming API configuration, bypassing the cache.

    .OUTPUTS
        Array
        Returns the value property containing streaming API export settings.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrStreamingApiConfiguration" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Streaming API configuration"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrStreamingApiConfiguration"
        } else {
            Write-Verbose "XDR Streaming API configuration cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/wdatpApi/dataexportsettings"
            Write-Verbose "Retrieving XDR Streaming API configuration"
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            # Return only the value property
            $streamingApiConfig = $result.value

            Set-XdrCache -CacheKey "XdrStreamingApiConfiguration" -Value $streamingApiConfig -TTLMinutes 30
            return $streamingApiConfig
        } catch {
            Write-Error "Failed to retrieve Streaming API configuration: $_"
        }
    }

    end {

    }
}
