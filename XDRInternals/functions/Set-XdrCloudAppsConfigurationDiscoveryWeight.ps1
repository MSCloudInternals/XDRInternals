function Set-XdrCloudAppsConfigurationDiscoveryWeight {
    <#
    .SYNOPSIS
        Sets or resets discovery weights in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Sets custom discovery weights or resets them to defaults in Microsoft Defender for Cloud Apps.
        Discovery weights define the relative importance of different risk factors
        used in cloud app risk scoring calculations.
        Use the -Reset switch to restore default weights instead of setting custom values.

    .PARAMETER Weights
        The weights configuration object to save. This should be the categories array
        from Get-XdrCloudAppsConfigurationDiscoveryWeight with modified weight values.
        Each category contains an enum, weight, and fields hashtable.

    .PARAMETER Reset
        Resets the discovery weights to their default values instead of setting custom values.
        When specified, the -Weights parameter is ignored.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        $weights = Get-XdrCloudAppsConfigurationDiscoveryWeight
        $weights.categories[0].weight = 4
        Set-XdrCloudAppsConfigurationDiscoveryWeight -Weights $weights.categories
        Retrieves current weights, modifies a category weight, and saves the changes.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationDiscoveryWeight -Reset
        Resets all discovery weights to their default values.

    .EXAMPLE
        Set-XdrCloudAppsConfigurationDiscoveryWeight -Reset -WhatIf
        Shows what would happen if discovery weights were reset to defaults.

    .OUTPUTS
        System.Object
        Returns the API response confirming the update.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Set')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Set')]
        [ValidateNotNull()]
        [object]$Weights,

        [Parameter(Mandatory = $true, ParameterSetName = 'Reset')]
        [switch]$Reset
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($Reset) {
            # Reset weights to defaults
            $target = "Cloud Apps Discovery Weights"
            $action = "Reset to defaults"

            if ($PSCmdlet.ShouldProcess($target, $action)) {
                try {
                    Write-Verbose "Resetting discovery weights to default values"
                    $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/weights/reset/"

                    $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    # Clear cache after successful update
                    Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationDiscoveryWeight" -ErrorAction SilentlyContinue
                    Write-Verbose "Discovery weights reset successfully"

                    return $result
                } catch {
                    Write-Error "Failed to reset discovery weights: $_"
                }
            }
        } else {
            # Set custom weights
            $target = "Cloud Apps Discovery Weights"
            $action = "Update custom weights"

            if ($PSCmdlet.ShouldProcess($target, $action)) {
                try {
                    Write-Verbose "Setting custom discovery weights"
                    $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/weights/save"

                    # Build the request body with the categories structure
                    $Body = @{
                        categories = $Weights
                    } | ConvertTo-Json -Depth 10

                    $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    # Clear cache after successful update
                    Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationDiscoveryWeight" -ErrorAction SilentlyContinue
                    Write-Verbose "Discovery weights updated successfully"

                    return $result
                } catch {
                    Write-Error "Failed to update discovery weights: $_"
                }
            }
        }
    }

    end {
    }
}
