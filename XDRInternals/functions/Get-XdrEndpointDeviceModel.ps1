function Get-XdrEndpointDeviceModel {
    <#
    .SYNOPSIS
        Retrieves all device models from Microsoft Defender for Endpoint.

    .DESCRIPTION
        Gets a list of all device models (hardware models) from the Microsoft Defender XDR portal.
        This function includes caching support with a 15-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointDeviceModel
        Retrieves all device models using cached data if available.

    .EXAMPLE
        Get-XdrEndpointDeviceModel -Force
        Forces a fresh retrieval of device models, bypassing the cache.

    .OUTPUTS
        Array
        Returns an array of device model names.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointDeviceModels" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint device models"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointDeviceModels"
        } else {
            Write-Verbose "XDR Endpoint device models cache is missing or expired"
        }
        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allModels"
        Write-Verbose "Retrieving XDR Endpoint device models"
        $XdrEndpointDeviceModels = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        Set-XdrCache -CacheKey "XdrEndpointDeviceModels" -Value $XdrEndpointDeviceModels -TTLMinutes 15
        return $XdrEndpointDeviceModels

    }

    end {

    }
}