function Get-XdrCache {
    <#
    .SYNOPSIS
        Retrieves a cached value from the XDR cache store.
    
    .DESCRIPTION
        Gets a cached value based on the provided cache key. Returns the cached object which includes the Value and NotValidAfter properties.
        Supports multi-tenant caching by incorporating the tenant ID into the cache key.
    
    .PARAMETER CacheKey
        The unique key to identify the cached item.
    
    .PARAMETER TenantId
        The Tenant ID to use for the cache key. If not provided, defaults to the currently cached tenant ID.
        This enables multi-tenant caching support.
    
    .EXAMPLE
        Get-XdrCache -CacheKey "XdrEndpointDeviceModels"
        Retrieves the cached device models for the current tenant if they exist.
    
    .EXAMPLE
        Get-XdrCache -CacheKey "XdrEndpointDeviceModels" -TenantId "12345678-1234-1234-1234-123456789012"
        Retrieves the cached device models for a specific tenant.
    
    .EXAMPLE
        $cache = Get-XdrCache -CacheKey "XdrEndpointDeviceModels" -ErrorAction SilentlyContinue
        if ($cache.NotValidAfter -gt (Get-Date)) { return $cache.Value }
        Retrieves cached data and checks if it's still valid.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CacheKey,
        
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
        
        if (-not $script:XdrCacheStore) {
            Write-Verbose "Cache store does not exist"
            throw "Cache store is not initialized. Cache key '$fullCacheKey' not found."
        }
        
        if ($script:XdrCacheStore.ContainsKey($fullCacheKey)) {
            Write-Verbose "Cache hit for key: $fullCacheKey"
            return $script:XdrCacheStore[$fullCacheKey]
        } else {
            Write-Verbose "Cache miss for key: $fullCacheKey"
        }
    }
}
