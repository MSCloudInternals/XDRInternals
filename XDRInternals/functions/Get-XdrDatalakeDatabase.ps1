function Get-XdrDatalakeDatabase {
    <#
    .SYNOPSIS
        Retrieves databases from Microsoft Defender XDR datalake.
    
    .DESCRIPTION
        Gets a list of databases from the Microsoft Defender XDR datalake.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrDatalakeDatabase
        Retrieves the datalake databases using cached data if available.
    
    .EXAMPLE
        Get-XdrDatalakeDatabase -Force
        Forces a fresh retrieval of the datalake databases, bypassing the cache.
    
    .OUTPUTS
        Array
        Returns an array of database objects from the datalake.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrDatalakeDatabases" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR datalake databases"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrDatalakeDatabases"
        } else {
            Write-Verbose "XDR datalake databases cache is missing or expired"
        }
        $Uri = "https://security.microsoft.com/apiproxy/securityplatform/lake/databases?api-version=2024-07-01"
        Write-Verbose "Retrieving XDR datalake databases"
        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            $XdrDatalakeDatabases = $result.value
            Set-XdrCache -CacheKey "XdrDatalakeDatabases" -Value $XdrDatalakeDatabases -TTLMinutes 5
            return $XdrDatalakeDatabases
        } catch {
            Write-Error "Failed to retrieve datalake databases: $_"
        }
    }
    
    end {
        
    }
}
