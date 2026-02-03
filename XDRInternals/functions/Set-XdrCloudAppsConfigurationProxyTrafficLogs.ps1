function Set-XdrCloudAppsConfigurationProxyTrafficLogs {
    <#
    .SYNOPSIS
        Enables or disables proxy traffic logging in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Enables or disables proxy traffic logging in Microsoft Defender for Cloud Apps.
        Proxy traffic logs capture detailed information about traffic flowing through
        the Conditional Access App Control proxy, useful for troubleshooting and analysis.

        This setting is found in the XDR portal under Cloud Apps > Settings > Cloud Discovery > Automatic log upload.

    .PARAMETER Enabled
        Specifies whether to enable ($true) or disable ($false) proxy traffic logging.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The setting is not changed.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationProxyTrafficLogs -Enabled $true
        Enables proxy traffic logging.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationProxyTrafficLogs -Enabled $false
        Disables proxy traffic logging.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationProxyTrafficLogs -Enabled $true -WhatIf
        Shows what would happen if proxy traffic logging were enabled.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationProxyTrafficLogs -Enabled $true -Confirm:$false
        Enables proxy traffic logging without prompting for confirmation.

    .OUTPUTS
        System.Object
        Returns the API response confirming the change, if any.

    .NOTES
        This cmdlet clears the tenant configuration cache after a successful update.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Matches API naming convention')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $status = if ($Enabled) { "Enable" } else { "Disable" }
        $target = "Proxy Traffic Logs"
        $action = "$status proxy traffic logging"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "$($action)..."
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/tenant_config/enableProxyTrafficLogs/"

                # Build the request body
                $Body = @{
                    value = $Enabled
                }

                $BodyJson = $Body | ConvertTo-Json -Depth 10

                Write-Verbose "Request body: $BodyJson"

                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $BodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear cache after successful update
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationTenantConfig" -ErrorAction SilentlyContinue
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationInfo" -ErrorAction SilentlyContinue
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationProxyTrafficLogs" -ErrorAction SilentlyContinue
                Write-Verbose "Proxy traffic logging $($status.ToLower())d successfully"

                return $result
            } catch {
                Write-Error "Failed to $($status.ToLower()) proxy traffic logging: $_"
            }
        }
    }

    end {
    }
}
