function Get-XdrEndpointConfigurationCustomCollectionModel {
    <#
    .SYNOPSIS
        Retrieves the available custom data collection platforms and tables for Defender for Endpoint.

    .DESCRIPTION
        Gets the custom collection model from the Defender XDR portal. Results are cached for 30 minutes.

    .PARAMETER Force
        Bypasses the cache and retrieves the current model.

    .EXAMPLE
        Get-XdrEndpointConfigurationCustomCollectionModel -Force

    .OUTPUTS
        Object
        Returns the API response with platforms, each containing its tables.
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
        $cacheKey = 'GetXdrEndpointConfigurationCustomCollectionModel'
        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            return $currentCacheValue.Value
        } elseif ($Force) {
            Clear-XdrCache -CacheKey $cacheKey
        }

        try {
            $uri = 'https://security.microsoft.com/apiproxy/mtp/mdeCustomCollection/model'
            $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve endpoint custom collection model: $_"
        }
    }
}