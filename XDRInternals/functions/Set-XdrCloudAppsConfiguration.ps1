function Set-XdrCloudAppsConfiguration {
    <#
    .SYNOPSIS
        Updates supported Microsoft Defender for Cloud Apps configuration objects and settings.

    .DESCRIPTION
        Updates supported Cloud Apps configuration objects and tenant settings using a grouped command.

    .PARAMETER Type
        Configuration type to update.

    .PARAMETER Id
        Identifier for item-specific updates.

    .PARAMETER Properties
        API properties to include in the update request.

    .PARAMETER WhatIf
        Shows what would happen without updating the object.

    .PARAMETER Confirm
        Prompts for confirmation before updating the object.

    .EXAMPLE
        Set-XdrCloudAppsConfiguration -Type LCNC -Properties @{ enabled = $true }

        Updates LCNC settings.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DiscoveryEncryption', 'DiscoveryWeight', 'LCNC', 'Notifications', 'ProxyTrafficLogs', 'ScopedDeployment', 'ScopedProfile', 'Subnet', 'TenantConfig')]
        [string]$Type,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('_id')]
        [string]$Id,

        [Parameter()]
        [hashtable]$Properties = @{}
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $endpointMap = @{
            DiscoveryEncryption = '/mcas/cas/api/v1/discovery/encryption_settings/'
            DiscoveryWeight     = '/mcas/cas/api/v1/discovery/discovered_app_weights/'
            LCNC                = '/mcas/cas/api/v1/lcnc_settings/'
            Notifications       = '/mcas/cas/api/v1/user_config/set_notifications_center_settings/'
            ProxyTrafficLogs    = '/mcas/cas/api/v1/tenant_config/enableProxyTrafficLogs/'
            TenantConfig        = '/mcas/cas/api/v1/tenant_config/'
            ScopedDeployment    = '/mcas/cas/api/v1/scoped_deployments/{0}/'
            ScopedProfile       = '/mcas/cas/api/v1/scoped_profiles/{0}/'
            Subnet              = '/mcas/cas/api/v1/subnet/{0}/'
        }

        $path = $endpointMap[$Type]
        if ($path -like '*{0}*') {
            if ([string]::IsNullOrWhiteSpace($Id)) {
                throw "Id is required when setting Cloud Apps configuration type '$Type'."
            }
            $path = $path -f $Id
        }

        $target = if ($Id) { "$Type/$Id" } else { $Type }
        if ($PSCmdlet.ShouldProcess($target, 'Update Cloud Apps configuration')) {
            Invoke-XdrCloudAppsRequest -Path $path -Method Post -Body $Properties -TypeName "XdrCloudAppsConfiguration$Type" -Raw
        }
    }
}

