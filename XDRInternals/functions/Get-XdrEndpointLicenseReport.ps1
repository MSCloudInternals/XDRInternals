function Get-XdrEndpointLicenseReport {
    <#
    .SYNOPSIS
        Retrieves license usage report for Microsoft Defender for Endpoint.

    .DESCRIPTION
        Retrieves license usage report for Microsoft Defender for Endpoint.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointLicenseReport
        Retrieves license usage report for Microsoft Defender for Endpoint.

    .EXAMPLE
        Get-XdrEndpointLicenseReport -Force
        Forces a fresh retrieval, bypassing the cache.

    .OUTPUTS
        Object
        Returns the API response.
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
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrEndpointLicenseReport" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached GetXdrEndpointLicenseReport data"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrEndpointLicenseReport"
        } else {
            Write-Verbose "GetXdrEndpointLicenseReport cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/k8sMachineApi/ine/machineapiservice/machines/skuReport"
            Write-Verbose "Retrieving GetXdrEndpointLicenseReport data"
            $result = (Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers).sums

            Set-XdrCache -CacheKey "GetXdrEndpointLicenseReport" -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve endpoint license report: $_"
        }
    }

    end {
    }
}