function New-XdrCloudAppsConfiguration {
    <#
    .SYNOPSIS
        Creates supported Microsoft Defender for Cloud Apps configuration objects.

    .DESCRIPTION
        Creates supported Cloud Apps configuration objects using a grouped command.

    .PARAMETER Type
        Configuration object type to create.

    .PARAMETER Name
        Name for the new configuration object.

    .PARAMETER Properties
        Additional API properties to include in the create request.

    .PARAMETER WhatIf
        Shows what would happen without creating the object.

    .PARAMETER Confirm
        Prompts for confirmation before creating the object.

    .EXAMPLE
        New-XdrCloudAppsConfiguration -Type UserTag -Name "Reviewed"

        Creates a Cloud Apps user tag.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Function uses ShouldProcess')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ApiToken', 'DiscoveryAppTag', 'DiscoveryExclusion', 'ScopedDeployment', 'ScopedProfile', 'Subnet', 'UserTag')]
        [string]$Type,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [hashtable]$Properties = @{}
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $endpointMap = @{
            ApiToken           = '/mcas/cas/api/v1/tokens/'
            DiscoveryAppTag    = '/mcas/cas/api/v1/discovery/tags/'
            DiscoveryExclusion = '/mcas/cas/api/v1/discovery/exclusions/'
            ScopedDeployment   = '/mcas/cas/api/v1/scoped_deployments/'
            ScopedProfile      = '/mcas/cas/api/v1/scoped_profiles/'
            Subnet             = '/mcas/cas/api/v1/subnet/'
            UserTag            = '/mcas/cas/api/v1/tags/'
        }

        $body = $Properties.Clone()
        $body.name = $Name

        if ($PSCmdlet.ShouldProcess($Name, "Create Cloud Apps $Type")) {
            Invoke-XdrCloudAppsRequest -Path $endpointMap[$Type] -Method Post -Body $body -TypeName "XdrCloudAppsConfiguration$Type" -Raw
        }
    }
}

