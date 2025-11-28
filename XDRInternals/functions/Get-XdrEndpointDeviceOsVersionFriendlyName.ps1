function Get-XdrEndpointDeviceOsVersionFriendlyName {
    <#
    .SYNOPSIS
        Retrieves all OS version friendly names from Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets a list of all operating system version friendly names from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointDeviceOsVersionFriendlyName
        Retrieves all OS version friendly names using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointDeviceOsVersionFriendlyName -Force
        Forces a fresh retrieval of OS version friendly names, bypassing the cache.
    
    .OUTPUTS
        Array
        Returns an array of OS version friendly name strings.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointDeviceOsVersionFriendlyNames" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint device OS version friendly names"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointDeviceOsVersionFriendlyNames"
        } else {
            Write-Verbose "XDR Endpoint device OS version friendly names cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allOsVersionFriendlyNames"
            Write-Verbose "Retrieving XDR Endpoint device OS version friendly names"
            $XdrEndpointDeviceOsVersionFriendlyNames = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrEndpointDeviceOsVersionFriendlyNames" -Value $XdrEndpointDeviceOsVersionFriendlyNames -TTLMinutes 30
            return $XdrEndpointDeviceOsVersionFriendlyNames
        } catch {
            Write-Error "Failed to retrieve endpoint device OS version friendly names: $_"
        }
    }
    
    end {
    }
}