function New-XdrEndpointDeviceRbacGroup {
    <#
    .SYNOPSIS
        Creates a device group in Defender for Endpoint used for RBAC and policies.

    .DESCRIPTION
        Creates a device group in Defender for Endpoint used for RBAC and policies.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER GroupObject
        The GroupObject to send. If not provided, uses a default structure.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

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
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter()]
        [object]$GroupObject
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        Write-Verbose "Retrieving New-XdrEndpointDeviceRbacGroup data"
        $existingGroups = Get-XdrEndpointDeviceRbacGroup -Force
        if ($existingGroups.count -eq 1) {
            $GroupObject.Priority = 0
        } else {
            $GroupObject.Priority = $existingGroups.Priority[-2] + 1
        }
        [array]$newGroups = $existingGroups
        $newGroups += $GroupObject
        if ($PSCmdlet.ShouldProcess("DeviceRbacGroups", "Create")) {
            try {
                $result = Set-XdrEndpointDeviceRbacGroup -GroupObject $newGroups
            } catch {
                Write-Error "Failed to update DeviceRbacGroups: $_"
            }
        }

        Set-XdrCache -CacheKey "NewXdrEndpointDeviceRbacGroup" -Value $result -TTLMinutes 30
        return $result
    }

    end {

    }
}