function Set-XdrCache {
    <#
    .SYNOPSIS
        Sets a value in the XDR cache store with a time-to-live (TTL).
    
    .DESCRIPTION
        Stores a value in the cache with a specified cache key and TTL in minutes. The cached object includes the value and an expiration timestamp.
    
    .PARAMETER CacheKey
        The unique key to identify the cached item.
    
    .PARAMETER Value
        The value to store in the cache.
    
    .PARAMETER TTLMinutes
        The time-to-live in minutes for the cached item. After this time, the cache is considered expired.
    
    .EXAMPLE
        Set-XdrCache -CacheKey "XdrEndpointDeviceModels" -Value $deviceModels -TTLMinutes 15
        Caches device models for 15 minutes.
    
    .EXAMPLE
        Set-XdrCache -CacheKey "TenantInfo" -Value $tenantData -TTLMinutes 60
        Caches tenant information for 1 hour.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state is changed outside of the current session')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CacheKey,
        
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [Parameter(Mandatory = $true)]
        [int]$TTLMinutes
    )
    
    process {
        # Initialize cache store if it doesn't exist
        if (-not $script:XdrCacheStore) {
            Write-Verbose "Initializing XDR cache store"
            $script:XdrCacheStore = @{}
        }
        
        $cacheObject = [PSCustomObject]@{
            Value         = $Value
            CachedAt      = Get-Date
            NotValidAfter = (Get-Date).AddMinutes($TTLMinutes)
        }
        
        $script:XdrCacheStore[$CacheKey] = $cacheObject
        Write-Verbose "Cached key '$CacheKey' with TTL of $TTLMinutes minutes (valid until $($cacheObject.NotValidAfter))"
    }
}
