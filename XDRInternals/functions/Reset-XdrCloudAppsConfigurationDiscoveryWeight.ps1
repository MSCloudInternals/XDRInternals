function Reset-XdrCloudAppsConfigurationDiscoveryWeight {
    <#
    .SYNOPSIS
        Resets discovery scoring weights to defaults in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Resets all discovery scoring weights to their default values in Microsoft Defender for Cloud Apps.
        Discovery weights determine how different security, compliance, and other factors contribute
        to the overall risk score of discovered cloud applications.

        This is a destructive operation that will reset all custom weight configurations.

    .PARAMETER Force
        Bypasses confirmation prompts and resets the weights without asking.

    .PARAMETER Confirm
        Prompts for confirmation before resetting the weights. Enabled by default due to high impact.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The weights are not reset.

    .EXAMPLE
        Reset-XdrCloudAppsConfigurationDiscoveryWeight
        Resets discovery weights to defaults after confirming the action.

    .EXAMPLE
        Reset-XdrCloudAppsConfigurationDiscoveryWeight -Force
        Resets discovery weights to defaults without prompting for confirmation.

    .EXAMPLE
        Reset-XdrCloudAppsConfigurationDiscoveryWeight -WhatIf
        Shows what would happen if the discovery weights were reset.

    .EXAMPLE
        Reset-XdrCloudAppsConfigurationDiscoveryWeight -Confirm:$false
        Resets discovery weights without confirmation (same as -Force).

    .OUTPUTS
        System.Object
        Returns the API response confirming the reset, which typically includes the default weight values.

    .NOTES
        This cmdlet requires confirmation by default due to its high impact.
        Use -Force or -Confirm:$false to bypass confirmation in scripts.
        This cmdlet clears the discovery weight cache after a successful reset.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess is implemented')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $target = "Discovery Scoring Weights"
        $action = "Reset to default values"

        if ($Force -or $PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Resetting discovery weights to defaults..."
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/weights/reset/"

                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear cache after successful reset
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationDiscoveryWeight" -ErrorAction SilentlyContinue
                Clear-XdrCache -CacheKey "*DiscoveryWeight*" -ErrorAction SilentlyContinue
                Write-Verbose "Discovery weights reset successfully"

                return $result
            } catch {
                Write-Error "Failed to reset discovery weights: $_"
            }
        }
    }

    end {
    }
}
