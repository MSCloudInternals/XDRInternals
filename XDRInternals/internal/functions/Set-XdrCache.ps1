function Set-XdrCache {
    <#
    .SYNOPSIS
        Sets a value in the XDR cache store with a time-to-live (TTL).
    
    .DESCRIPTION
        Stores a value in the cache with a specified cache key and TTL in minutes. The cached object includes the value and an expiration timestamp.
        Supports multi-tenant caching by incorporating the tenant ID into the cache key.
    
    .PARAMETER CacheKey
        The unique key to identify the cached item.
    
    .PARAMETER Value
        The value to store in the cache.
    
    .PARAMETER TTLMinutes
        The time-to-live in minutes for the cached item. After this time, the cache is considered expired.
    
    .PARAMETER TenantId
        The Tenant ID to use for the cache key. If not provided, defaults to the currently cached tenant ID.
        This enables multi-tenant caching support.
    
    .EXAMPLE
        Set-XdrCache -CacheKey "XdrEndpointDeviceModels" -Value $deviceModels -TTLMinutes 15
        Caches device models for the current tenant for 15 minutes.
    
    .EXAMPLE
        Set-XdrCache -CacheKey "TenantInfo" -Value $tenantData -TTLMinutes 60 -TenantId "12345678-1234-1234-1234-123456789012"
        Caches tenant information for a specific tenant for 1 hour.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No state is changed outside of the current session')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CacheKey,
        
        [Parameter(Mandatory = $true)]
        [object]$Value,
        
        [Parameter(Mandatory = $true)]
        [int]$TTLMinutes,
        
        [Parameter()]
        [string]$TenantId
    )
    
    process {
        # Get current tenant ID if not provided and cache key is not XdrTenantId itself
        if (-not $TenantId -and $CacheKey -ne "XdrTenantId") {
            $cachedTenantId = Get-XdrCache -CacheKey "XdrTenantId" -ErrorAction SilentlyContinue
            if ($cachedTenantId) {
                $TenantId = $cachedTenantId.Value
                Write-Verbose "Using cached tenant ID: $TenantId"
            }
        }
        
        # Build the full cache key with tenant ID prefix
        $fullCacheKey = if ($TenantId) {
            "${TenantId}_${CacheKey}"
        } else {
            $CacheKey
        }
        
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
        
        $script:XdrCacheStore[$fullCacheKey] = $cacheObject
        Write-Verbose "Cached key '$fullCacheKey' with TTL of $TTLMinutes minutes (valid until $($cacheObject.NotValidAfter))"
    }
}
