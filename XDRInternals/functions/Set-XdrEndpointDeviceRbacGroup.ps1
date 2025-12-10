function Set-XdrEndpointDeviceRbacGroup {
    <#
    .SYNOPSIS
        Updates Defender for Endpoint device groups.

    .DESCRIPTION
        Updates Defender for Endpoint device groups.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER GroupObject
        The GroupObject to send. If not provided, uses a default structure.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

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
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter()]
        [object]$GroupObject
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {

        if ($PSCmdlet.ShouldProcess("DeviceRbacGroups", "Update")) {
            try {
                $Uri = "https://security.microsoft.com/apiproxy/mtp/rbacManagementApi/rbac/machine_groups"
                Write-Verbose "Retrieving Set-XdrEndpointDeviceRbacGroup data"
                $result = (Invoke-RestMethod -Uri $Uri -Method PUT -ContentType "application/json" -Body ($GroupObject | ConvertTo-Json -Depth 10) -WebSession $script:session -Headers $script:headers).items
                return $result
            } catch {
                Write-Error "Failed to update DeviceRbacGroups: $_"
            }
        }
    }

    end {
        
    }
}