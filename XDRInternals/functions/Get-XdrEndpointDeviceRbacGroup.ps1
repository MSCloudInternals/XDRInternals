function Get-XdrEndpointDeviceRbacGroup {
    <#
    .SYNOPSIS
        Retrieves device groups for Defender for Endpoint.

    .DESCRIPTION
        Retrieves device groups for Defender for Endpoint.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointDeviceRbacGroup
        Retrieves device groups for Defender for Endpoint.

    .EXAMPLE
        Get-XdrEndpointDeviceRbacGroup -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrEndpointDeviceRbacGroup" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Get-XdrEndpointDeviceRbacGroup data"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrEndpointDeviceRbacGroup"
        } else {
            Write-Verbose "Get-XdrEndpointDeviceRbacGroup cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/rbacManagementApi/rbac/machine_groups?addAadGroupNames=true&addMachineGroupCount=false"
        Write-Verbose "Retrieving Get-XdrEndpointDeviceRbacGroup data"
        $result = (Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers).items

        Set-XdrCache -CacheKey "GetXdrEndpointDeviceRbacGroup" -Value $result -TTLMinutes 30
        return $result
    }

    end {

    }
}