function Remove-XdrCloudAppsConfigurationLogCollector {
    <#
    .SYNOPSIS
        Removes a log collector from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Deletes a log collector configuration from Microsoft Defender for Cloud Apps.
        This permanently removes the log collector used for cloud discovery data ingestion.

    .PARAMETER LogCollectorId
        The unique identifier of the log collector to remove.
        Accepts pipeline input from the _id property of log collector objects.

    .PARAMETER Confirm
        Prompts for confirmation before removing the log collector.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The log collector is not removed.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationLogCollector -LogCollectorId "abc123def456"
        Removes the specified log collector.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationLogCollector | Where-Object { $_.name -eq 'Test Collector' } | Remove-XdrCloudAppsConfigurationLogCollector
        Finds a log collector by name and removes it through the pipeline.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationLogCollector | Remove-XdrCloudAppsConfigurationLogCollector -WhatIf
        Shows what would happen if all log collectors were removed.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationLogCollector | Remove-XdrCloudAppsConfigurationLogCollector -Confirm:$false
        Removes all log collectors without confirmation (use with caution).

    .OUTPUTS
        None
        This cmdlet does not return any output upon successful deletion.

    .NOTES
        This operation requires confirmation by default due to high impact.
        Use -Confirm:$false to bypass confirmation in scripts.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess is implemented')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('_id')]
        [string]$LogCollectorId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/api/v1/discovery/log_collectors/$LogCollectorId/"

        if ($PSCmdlet.ShouldProcess($LogCollectorId, "Remove log collector")) {
            Write-Verbose "Removing log collector: $LogCollectorId"

            try {
                $null = Invoke-RestMethod -Uri $Uri -Method Delete -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationLogCollector*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully removed log collector: $LogCollectorId"
            } catch {
                Write-Error "Failed to remove log collector '$LogCollectorId': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
