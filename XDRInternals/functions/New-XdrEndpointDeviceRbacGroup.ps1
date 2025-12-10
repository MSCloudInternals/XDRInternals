function New-XdrEndpointDeviceRbacGroup {
    <#
    .SYNOPSIS
        Creates a device group in Defender for Endpoint used for RBAC and policies.

    .DESCRIPTION
        Creates a device group in Defender for Endpoint used for RBAC and policies.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Body
        The request body to send. If not provided, uses a default structure.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        New-XdrEndpointDeviceRbacGroup
        Creates a device group in Defender for Endpoint used for RBAC and policies.

    .EXAMPLE
        New-XdrEndpointDeviceRbacGroup -Body $customBody
        Creates a device group in Defender for Endpoint used for RBAC and policies with a custom request body.

    .EXAMPLE
        New-XdrEndpointDeviceRbacGroup -Force
        Forces a fresh retrieval, bypassing the cache.

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [object]$GroupObject,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $currentCacheValue = Get-XdrCache -CacheKey "NewXdrEndpointDeviceRbacGroup" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached New-XdrEndpointDeviceRbacGroup data"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "NewXdrEndpointDeviceRbacGroup"
        } else {
            Write-Verbose "New-XdrEndpointDeviceRbacGroup cache is missing or expired"
        }

        Write-Verbose "Retrieving New-XdrEndpointDeviceRbacGroup data"

        $existingGroups = Get-XdrEndpointDeviceRbacGroup -Force
        if ($existingGroups.count -eq 1) {
            $GroupObject.Priority = 0
        } else {
            $GroupObject.Priority = $existingGroups.Priority[-2] + 1
        }
        [array]$newGroups = $existingGroups
        $newGroups += $GroupObject
        $result = Set-XdrEndpointDeviceRbacGroup -GroupObject $newGroups -Force

        Set-XdrCache -CacheKey "NewXdrEndpointDeviceRbacGroup" -Value $result -TTLMinutes 30
        return $result
    }

    end {

    }
}