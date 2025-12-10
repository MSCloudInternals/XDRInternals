function Set-XdrEndpointDeviceRbacGroup {
    <#
    .SYNOPSIS
        Updates Defender for Endpoint device groups.

    .DESCRIPTION
        Updates Defender for Endpoint device groups.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Body
        The request body to send. If not provided, uses a default structure.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Set-XdrEndpointDeviceRbacGroup
        Updates Defender for Endpoint device groups.

    .EXAMPLE
        Set-XdrEndpointDeviceRbacGroup -Body $customBody
        Updates Defender for Endpoint device groups with a custom request body.

    .EXAMPLE
        Set-XdrEndpointDeviceRbacGroup -Force
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
        $currentCacheValue = Get-XdrCache -CacheKey "SetXdrEndpointDeviceRbacGroup" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached Set-XdrEndpointDeviceRbacGroup data"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "SetXdrEndpointDeviceRbacGroup"
        } else {
            Write-Verbose "Set-XdrEndpointDeviceRbacGroup cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/rbacManagementApi/rbac/machine_groups"
        Write-Verbose "Retrieving Set-XdrEndpointDeviceRbacGroup data"
        $result = (Invoke-RestMethod -Uri $Uri -Method PUT -ContentType "application/json" -Body ($GroupObject | ConvertTo-Json -Depth 10) -WebSession $script:session -Headers $script:headers).items

        Set-XdrCache -CacheKey "SetXdrEndpointDeviceRbacGroup" -Value $result -TTLMinutes 30
        return $result

        Write-Output "Updating Defender for Endpoint device groups..."
        Start-Sleep -Seconds 5
    }

    end {
        
    }
}