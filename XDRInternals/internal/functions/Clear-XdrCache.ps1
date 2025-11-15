function Clear-XdrCache {
    <#
    .SYNOPSIS
        Clears cached values from the XDR cache store.
    
    .DESCRIPTION
        Removes cached items from the cache store. Can clear a specific cache key or all cached items.
    
    .PARAMETER CacheKey
        The unique key of the cached item to remove. If not specified, all cache items will be cleared.
    
    .EXAMPLE
        Clear-XdrCache -CacheKey "XdrEndpointDeviceModels"
        Clears only the cached device models.
    
    .EXAMPLE
        Clear-XdrCache
        Clears all cached items from the cache store.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$CacheKey
    )
    
    process {
        if (-not $script:XdrCacheStore) {
            Write-Verbose "Cache store does not exist, nothing to clear"
            return
        }
        
        if ($CacheKey) {
            if ($script:XdrCacheStore.ContainsKey($CacheKey)) {
                $script:XdrCacheStore.Remove($CacheKey)
                Write-Verbose "Cleared cache key: $CacheKey"
            } else {
                Write-Verbose "Cache key '$CacheKey' not found"
            }
        } else {
            $script:XdrCacheStore.Clear()
            Write-Verbose "Cleared all cache entries"
        }
    }
}
