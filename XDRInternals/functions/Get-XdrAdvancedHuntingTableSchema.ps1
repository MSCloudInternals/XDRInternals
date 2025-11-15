function Get-XdrAdvancedHuntingTableSchema {
    <#
    .SYNOPSIS
        Retrieves the Advanced Hunting table schema from Microsoft Defender XDR.
    
    .DESCRIPTION
        Gets the schema for Advanced Hunting tables from the Microsoft Defender XDR portal.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrAdvancedHuntingTableSchema
        Retrieves the Advanced Hunting table schema using cached data if available.
    
    .EXAMPLE
        Get-XdrAdvancedHuntingTableSchema -Force
        Forces a fresh retrieval of the Advanced Hunting table schema, bypassing the cache.
    
    .OUTPUTS
        Object
        Returns the Advanced Hunting table schema from the hunting service.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrAdvancedHuntingTableSchema" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Advanced Hunting table schema"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrAdvancedHuntingTableSchema"
        } else {
            Write-Verbose "XDR Advanced Hunting table schema cache is missing or expired"
        }
        $Uri = "https://security.microsoft.com/apiproxy/mtp/huntingService/schema"
        Write-Verbose "Retrieving XDR Advanced Hunting table schema"
        $XdrAdvancedHuntingTableSchema = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers | Select-Object -ExpandProperty Tables
        Set-XdrCache -CacheKey "XdrAdvancedHuntingTableSchema" -Value $XdrAdvancedHuntingTableSchema -TTLMinutes 30
        return $XdrAdvancedHuntingTableSchema
    }
    
    end {
        
    }
}
