function Get-XdrEndpointConfigurationAuthenticatedTelemetry {
    <#
    .SYNOPSIS
        Retrieves the Authenticated Telemetry status for Microsoft Defender for Endpoint.

    .DESCRIPTION
        Gets the Authenticated Telemetry status for Microsoft Defender for Endpoint.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointConfigurationAuthenticatedTelemetry
        Retrieves the Authenticated Telemetry status for Microsoft Defender for Endpoint.

    .EXAMPLE
        Get-XdrEndpointConfigurationAuthenticatedTelemetry -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrEndpointConfigurationAuthenticatedTelemetry" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached GetXdrEndpointConfigurationAuthenticatedTelemetry data"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrEndpointConfigurationAuthenticatedTelemetry"
        } else {
            Write-Verbose "GetXdrEndpointConfigurationAuthenticatedTelemetry cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/senseauth/allownonauthsense"
        Write-Verbose "Retrieving Defender for Endpoint Authenticated Telemetry configuration"
        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "GetXdrEndpointConfigurationAuthenticatedTelemetry" -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve authenticated telemetry configuration: $_"
        }
    }

    end {
    }
}