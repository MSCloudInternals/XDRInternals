function Get-XdrDatalakeTableSchema {
    <#
    .SYNOPSIS
        Retrieves database entities schema from Microsoft Defender XDR datalake.
    
    .DESCRIPTION
        Gets the database entities schema from the Microsoft Defender XDR datalake using a Kusto query.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrDatalakeTableSchema
        Retrieves the database entities schema using cached data if available.
    
    .EXAMPLE
        Get-XdrDatalakeTableSchema -Force
        Forces a fresh retrieval of the database entities schema, bypassing the cache.
    
    .OUTPUTS
        Object
        Returns the database entities schema from the datalake.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrDatalakeTableSchema" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR datalake table schema"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrDatalakeTableSchema"
        } else {
            Write-Verbose "XDR datalake table schema cache is missing or expired"
        }
        $Uri = "https://security.microsoft.com/apiproxy/securityplatform/lake/kql/v1/rest/mgmt"
        $Body = '{"csl":".show databases entities"}'
        Write-Verbose "Retrieving XDR datalake table schema"
        $XdrDatalakeTableSchema = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        Set-XdrCache -CacheKey "XdrDatalakeTableSchema" -Value $XdrDatalakeTableSchema -TTLMinutes 30
        return $XdrDatalakeTableSchema
    }
    
    end {
        
    }
}
