function Get-XdrCache {
    <#
    .SYNOPSIS
        Retrieves a cached value from the XDR cache store.
    
    .DESCRIPTION
        Gets a cached value based on the provided cache key. Returns the cached object which includes the Value and NotValidAfter properties.
    
    .PARAMETER CacheKey
        The unique key to identify the cached item.
    
    .EXAMPLE
        Get-XdrCache -CacheKey "XdrEndpointDeviceModels"
        Retrieves the cached device models if they exist.
    
    .EXAMPLE
        $cache = Get-XdrCache -CacheKey "XdrEndpointDeviceModels" -ErrorAction SilentlyContinue
        if ($cache.NotValidAfter -gt (Get-Date)) { return $cache.Value }
        Retrieves cached data and checks if it's still valid.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CacheKey
    )
    
    process {
        if (-not $script:XdrCacheStore) {
            Write-Verbose "Cache store does not exist"
            throw "Cache store is not initialized. Cache key '$CacheKey' not found."
        }
        
        if ($script:XdrCacheStore.ContainsKey($CacheKey)) {
            Write-Verbose "Cache hit for key: $CacheKey"
            return $script:XdrCacheStore[$CacheKey]
        } else {
            Write-Verbose "Cache miss for key: $CacheKey"
            throw "Cache key '$CacheKey' not found in cache store."
        }
    }
}
