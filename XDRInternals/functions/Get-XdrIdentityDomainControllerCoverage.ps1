function Get-XdrIdentityDomainControllerCoverage {
    <#
    .SYNOPSIS
        Retrieves domain controller coverage from Microsoft Defender for Identity.
    
    .DESCRIPTION
        Gets the domain controller coverage information from Microsoft Defender for Identity.
        This function includes caching support with a 30-minute TTL to reduce API calls.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrIdentityDomainControllerCoverage
        Retrieves the domain controller coverage using cached data if available.
    
    .EXAMPLE
        Get-XdrIdentityDomainControllerCoverage -Force
        Forces a fresh retrieval of the domain controller coverage, bypassing the cache.
    
    .OUTPUTS
        Object
        Returns the domain controller coverage information from Defender for Identity.
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
        # Check if Microsoft Defender for Identity is active
        $mdiStatus = Get-XdrTenantWorkloadStatus -Workload "IsMdiActive"
        if (-not $mdiStatus.IsActive) {
            Write-Warning "Microsoft Defender for Identity is not active in this tenant. Cannot retrieve domain controller coverage."
            return
        }

        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityDomainControllerCoverage" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity domain controller coverage"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityDomainControllerCoverage"
        } else {
            Write-Verbose "XDR Identity domain controller coverage cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/aatp/api/sensors/domainControllerCoverage"
            Write-Verbose "Retrieving XDR Identity domain controller coverage"
            $XdrIdentityDomainControllerCoverage = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrIdentityDomainControllerCoverage" -Value $XdrIdentityDomainControllerCoverage -TTLMinutes 30
            return $XdrIdentityDomainControllerCoverage
        } catch {
            Write-Error "Failed to retrieve Identity domain controller coverage: $_"
        }
    }
    
    end {
        
    }
}
