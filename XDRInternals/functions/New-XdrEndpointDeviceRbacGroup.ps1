function New-XdrEndpointDeviceRbacGroup {
    <#
    .SYNOPSIS
        Creates a device group in Defender for Endpoint used for RBAC and policies.

    .DESCRIPTION
        Creates a device group in Defender for Endpoint used for RBAC and policies.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER GroupObject
        The group object to add to the existing RBAC group collection.
        This cmdlet does not build a default group object when the parameter is omitted.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .EXAMPLE
        New-XdrEndpointDeviceRbacGroup -GroupObject $customBody
        Creates a device group in Defender for Endpoint used for RBAC and policies with a custom request body.

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter()]
        [ValidateNotNull()]
        [object]$GroupObject
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        Write-Verbose "Retrieving New-XdrEndpointDeviceRbacGroup data"
        if ($null -eq $GroupObject) {
            throw "GroupObject is required. This cmdlet does not generate a default group object."
        }

        $existingGroups = @(Get-XdrEndpointDeviceRbacGroup -Force | Where-Object { $null -ne $_ })
        $groupPriority = if ($existingGroups.Count -le 1) {
            0
        } else {
            $existingGroups.Priority[-2] + 1
        }

        if ($GroupObject.PSObject.Properties['Priority']) {
            $GroupObject.Priority = $groupPriority
        } else {
            $GroupObject | Add-Member -MemberType NoteProperty -Name Priority -Value $groupPriority -Force
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
