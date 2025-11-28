function Get-XdrEndpointDeviceWindowsReleaseVersion {
    <#
    .SYNOPSIS
        Retrieves all Windows release versions from Microsoft Defender for Endpoint.
    
    .DESCRIPTION
        Gets a list of all Windows release versions (e.g., 21H2, 22H2) from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrEndpointDeviceWindowsReleaseVersion
        Retrieves all Windows release versions using cached data if available.
    
    .EXAMPLE
        Get-XdrEndpointDeviceWindowsReleaseVersion -Force
        Forces a fresh retrieval of Windows release versions, bypassing the cache.
    
    .OUTPUTS
        Array
        Returns an array of Windows release version strings.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointDeviceWindowsReleaseVersions" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint device Windows release versions"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointDeviceWindowsReleaseVersions"
        } else {
            Write-Verbose "XDR Endpoint device Windows release versions cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allWindowsReleaseVersions"
            Write-Verbose "Retrieving XDR Endpoint device Windows release versions"
            $XdrEndpointDeviceWindowsReleaseVersions = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrEndpointDeviceWindowsReleaseVersions" -Value $XdrEndpointDeviceWindowsReleaseVersions -TTLMinutes 30
            return $XdrEndpointDeviceWindowsReleaseVersions
        } catch {
            Write-Error "Failed to retrieve endpoint device Windows release versions: $_"
        }
    }
    
    end {
        
    }
}