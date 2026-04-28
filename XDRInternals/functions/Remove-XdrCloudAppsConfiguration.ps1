function Remove-XdrCloudAppsConfiguration {
    <#
    .SYNOPSIS
        Removes supported Microsoft Defender for Cloud Apps configuration objects.

    .DESCRIPTION
        Removes supported Cloud Apps configuration objects using a grouped command.

    .PARAMETER Type
        Configuration object type to remove.

    .PARAMETER Id
        Identifier of the configuration object to remove.

    .PARAMETER RemoveFromAllApps
        Removes a scoped profile from all apps before deleting it.

    .PARAMETER WhatIf
        Shows what would happen without removing the object.

    .PARAMETER Confirm
        Prompts for confirmation before removing the object.

    .EXAMPLE
        Remove-XdrCloudAppsConfiguration -Type Subnet -Id "subnet-id"

        Removes a Cloud Apps subnet configuration.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DiscoveryAppTag', 'DiscoveryDataSource', 'DiscoveryExclusion', 'LogCollector', 'ScopedDeployment', 'ScopedProfile', 'Subnet', 'UserTag')]
        [string]$Type,

        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('_id')]
        [string]$Id,

        [Parameter()]
        [switch]$RemoveFromAllApps
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $endpointMap = @{
            DiscoveryAppTag    = '/mcas/cas/api/v1/discovery/tags/{0}/'
            DiscoveryDataSource = '/mcas/cas/api/v1/discovery/data_sources/{0}/'
            DiscoveryExclusion = '/mcas/cas/api/v1/discovery/exclusions/{0}/'
            LogCollector       = '/mcas/cas/api/v1/discovery/log_collectors/{0}/'
            ScopedDeployment   = '/mcas/cas/api/v1/scoped_deployments/{0}/'
            ScopedProfile      = '/mcas/cas/api/v1/scoped_profiles/{0}/'
            Subnet             = '/mcas/cas/api/v1/subnet/{0}/'
            UserTag            = '/mcas/cas/api/v1/tags/{0}/'
        }

        if ($Type -eq 'ScopedProfile' -and $RemoveFromAllApps) {
            $removePath = '/mcas/cas/api/v1/scoped_profiles/{0}/remove_from_all_apps/' -f $Id
            if ($PSCmdlet.ShouldProcess($Id, 'Remove scoped profile from all apps')) {
                Invoke-XdrCloudAppsRequest -Path $removePath -Method Post -Raw
            }
        }

        $path = $endpointMap[$Type] -f $Id
        if ($PSCmdlet.ShouldProcess($Id, "Remove Cloud Apps $Type")) {
            Invoke-XdrCloudAppsRequest -Path $path -Method Delete -Raw
        }
    }
}

