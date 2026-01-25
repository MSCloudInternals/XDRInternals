function Clear-XdrCache {
    <#
    .SYNOPSIS
        Clears cached values from the XDR cache store.
    
    .DESCRIPTION
        Removes cached items from the cache store. Can clear a specific cache key, all cache items for a tenant, or all cached items.
        Supports multi-tenant caching by incorporating the tenant ID into the cache key.
    
    .PARAMETER CacheKey
        The unique key of the cached item to remove. If not specified along with TenantId, all cache items will be cleared.
    
    .PARAMETER TenantId
        The Tenant ID to use for the cache key. If not provided, defaults to the currently cached tenant ID.
        If provided without CacheKey, clears all cache entries for that tenant.
        This enables multi-tenant caching support.
    
    .EXAMPLE
        Clear-XdrCache -CacheKey "XdrEndpointDeviceModels"
        Clears only the cached device models for the current tenant.
    
    .EXAMPLE
        Clear-XdrCache -CacheKey "XdrEndpointDeviceModels" -TenantId "12345678-1234-1234-1234-123456789012"
        Clears the cached device models for a specific tenant.
    
    .EXAMPLE
        Clear-XdrCache -TenantId "12345678-1234-1234-1234-123456789012"
        Clears all cached items for a specific tenant.
    
    .EXAMPLE
        Clear-XdrCache
        Clears all cached items from the cache store.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$CacheKey,
        
        [Parameter()]
        [string]$TenantId
    )
    
    process {
        if (-not $script:XdrCacheStore) {
            Write-Verbose "Cache store does not exist, nothing to clear"
            return
        }
        
        if ($CacheKey) {
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
            
            if ($script:XdrCacheStore.ContainsKey($fullCacheKey)) {
                $script:XdrCacheStore.Remove($fullCacheKey)
                Write-Verbose "Cleared cache key: $fullCacheKey"
            } else {
                Write-Verbose "Cache key '$fullCacheKey' not found"
            }
        } elseif ($TenantId) {
            # Clear all cache entries for the specified tenant
            $tenantPrefix = "${TenantId}_"
            $keysToRemove = @($script:XdrCacheStore.Keys | Where-Object { $_ -like "${tenantPrefix}*" })
            foreach ($key in $keysToRemove) {
                $script:XdrCacheStore.Remove($key)
                Write-Verbose "Cleared cache key: $key"
            }
            if ($keysToRemove.Count -gt 0) {
                Write-Verbose "Cleared $($keysToRemove.Count) cache entries for tenant: $TenantId"
            } else {
                Write-Verbose "No cache entries found for tenant: $TenantId"
            }
        } else {
            # Clear all cache entries
            $script:XdrCacheStore.Clear()
            Write-Verbose "Cleared all cache entries"
        }
    }
}
