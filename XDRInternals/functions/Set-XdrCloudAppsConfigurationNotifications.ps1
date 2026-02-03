function Set-XdrCloudAppsConfigurationNotifications {
    <#
    .SYNOPSIS
        Sets notification center settings in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Configures the notification preferences for the current user in Microsoft Defender for Cloud Apps.
        This controls email notification settings including whether to receive emails,
        minimum severity level for notifications, and specific notification categories.

    .PARAMETER Settings
        A hashtable containing the notification settings to save.
        The hashtable should include keys such as:
        - allowMails: "true" or "false" to enable/disable email notifications
        - selectedMinimumSeverity: "LOW", "MEDIUM", or "HIGH" for minimum alert severity
        - system_alerts: Hashtable with email key (e.g., @{ email = "true" })
        - sla: Hashtable with email key (e.g., @{ email = "false" })

    .PARAMETER AllowMails
        Enables or disables email notifications. Use $true to allow emails, $false to disable.

    .PARAMETER MinimumSeverity
        Sets the minimum severity level for notifications. Valid values: LOW, MEDIUM, HIGH.

    .PARAMETER SystemAlerts
        Enables or disables system alert notifications. Use $true to enable, $false to disable.

    .PARAMETER SlaNotifications
        Enables or disables SLA notifications. Use $true to enable, $false to disable.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        $settings = @{
            allowMails = "true"
            selectedMinimumSeverity = "MEDIUM"
            system_alerts = @{ email = "true" }
            sla = @{ email = "false" }
        }
        Set-XdrCloudAppsConfigurationNotifications -Settings $settings
        Updates notification settings using a hashtable configuration.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationNotifications -AllowMails $true -MinimumSeverity "HIGH"
        Enables email notifications with HIGH minimum severity.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationNotifications -AllowMails $false
        Disables all email notifications.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationNotifications -SystemAlerts $true -SlaNotifications $false
        Enables system alerts but disables SLA notifications.

    .OUTPUTS
        System.Object
        Returns the API response confirming the update.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Settings')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Settings')]
        [ValidateNotNull()]
        [hashtable]$Settings,

        [Parameter(ParameterSetName = 'Individual')]
        [bool]$AllowMails,

        [Parameter(ParameterSetName = 'Individual')]
        [ValidateSet('LOW', 'MEDIUM', 'HIGH')]
        [string]$MinimumSeverity,

        [Parameter(ParameterSetName = 'Individual')]
        [bool]$SystemAlerts,

        [Parameter(ParameterSetName = 'Individual')]
        [bool]$SlaNotifications
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Build the request body based on parameter set
        if ($PSCmdlet.ParameterSetName -eq 'Settings') {
            $Body = $Settings
        } else {
            # Build body from individual parameters
            $Body = @{}

            if ($PSBoundParameters.ContainsKey('AllowMails')) {
                $Body['allowMails'] = $AllowMails.ToString().ToLower()
            }

            if ($PSBoundParameters.ContainsKey('MinimumSeverity')) {
                $Body['selectedMinimumSeverity'] = $MinimumSeverity
            }

            if ($PSBoundParameters.ContainsKey('SystemAlerts')) {
                $Body['system_alerts'] = @{ email = $SystemAlerts.ToString().ToLower() }
            }

            if ($PSBoundParameters.ContainsKey('SlaNotifications')) {
                $Body['sla'] = @{ email = $SlaNotifications.ToString().ToLower() }
            }

            if ($Body.Count -eq 0) {
                Write-Warning "No parameters specified. Please provide notification settings."
                return
            }
        }

        $target = "Cloud Apps Notification Settings"
        $action = "Update notification preferences"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Updating notification center settings"
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/user_config/set_notifications_center_settings/"

                $JsonBody = $Body | ConvertTo-Json -Depth 5

                Write-Verbose "Request body: $JsonBody"

                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $JsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear cache after successful update (if notifications cache exists)
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationNotifications" -ErrorAction SilentlyContinue
                Write-Verbose "Notification settings updated successfully"

                return $result
            } catch {
                Write-Error "Failed to update notification settings: $_"
            }
        }
    }

    end {
    }
}
