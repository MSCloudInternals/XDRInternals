function New-XdrCloudAppsPolicy {
    <#
    .SYNOPSIS
        Creates Microsoft Defender for Cloud Apps policies.

    .DESCRIPTION
        Creates supported Cloud Apps Discovery and File policies.

    .PARAMETER Type
        Policy type to create.

    .PARAMETER Name
        Policy name.

    .PARAMETER Description
        Policy description.

    .PARAMETER AlertSeverity
        Alert severity for the policy.

    .PARAMETER EnableAlerts
        Enables alert generation for the policy.

    .PARAMETER Enabled
        Sets whether the policy is enabled.

    .PARAMETER Filters
        Policy filter definition.

    .PARAMETER Properties
        Additional API properties to include in the create request.

    .PARAMETER WhatIf
        Shows what would happen without creating the policy.

    .PARAMETER Confirm
        Prompts for confirmation before creating the policy.

    .EXAMPLE
        New-XdrCloudAppsPolicy -Type Discovery -Name "High Risk Apps" -EnableAlerts

        Creates a Cloud Discovery policy.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Discovery', 'File')]
        [string]$Type,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [string]$Description,

        [Parameter()]
        [ValidateSet('LOW', 'MEDIUM', 'HIGH')]
        [string]$AlertSeverity = 'MEDIUM',

        [Parameter()]
        [switch]$EnableAlerts,

        [Parameter()]
        [bool]$Enabled = $true,

        [Parameter()]
        [hashtable]$Filters = @{},

        [Parameter()]
        [hashtable]$Properties = @{}
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $path = if ($Type -eq 'File') {
            '/mcas/cas/api/v1/policy/file/'
        }
        else {
            '/mcas/cas/api/v1/policy/discovery/'
        }

        $body = $Properties.Clone()
        $body.name = $Name
        $body.policyType = if ($Type -eq 'File') { 'FILE' } else { 'DISCOVERY' }
        $body.severity = $AlertSeverity
        $body.alertsEnabled = $EnableAlerts.IsPresent
        $body.enabled = $Enabled
        if ($Description) { $body.description = $Description }
        if ($Filters.Count -gt 0) { $body.filters = $Filters }

        if ($PSCmdlet.ShouldProcess($Name, "Create Cloud Apps $Type policy")) {
            Invoke-XdrCloudAppsRequest -Path $path -Method Post -Body $body -TypeName "XdrCloudAppsPolicy$Type" -Raw
        }
    }
}

