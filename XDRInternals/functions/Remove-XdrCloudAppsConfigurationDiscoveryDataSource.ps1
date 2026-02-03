function Remove-XdrCloudAppsConfigurationDiscoveryDataSource {
    <#
    .SYNOPSIS
        Removes a discovery data source from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Deletes a discovery data source configuration from Microsoft Defender for Cloud Apps.
        This permanently removes the data source used for cloud discovery reporting.

    .PARAMETER DataSourceId
        The unique identifier of the discovery data source to remove.
        Accepts pipeline input from the _id property of data source objects.

    .PARAMETER Confirm
        Prompts for confirmation before removing the discovery data source.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The discovery data source is not removed.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationDiscoveryDataSource -DataSourceId "abc123def456"
        Removes the specified discovery data source.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryDataSource | Where-Object { $_.name -eq 'Test Source' } | Remove-XdrCloudAppsConfigurationDiscoveryDataSource
        Finds a discovery data source by name and removes it through the pipeline.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryDataSource | Remove-XdrCloudAppsConfigurationDiscoveryDataSource -WhatIf
        Shows what would happen if all discovery data sources were removed.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryDataSource | Remove-XdrCloudAppsConfigurationDiscoveryDataSource -Confirm:$false
        Removes all discovery data sources without confirmation (use with caution).

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
        [string]$DataSourceId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/api/v1/discovery/data_sources/$DataSourceId/"

        if ($PSCmdlet.ShouldProcess($DataSourceId, "Remove discovery data source")) {
            Write-Verbose "Removing discovery data source: $DataSourceId"

            try {
                $null = Invoke-RestMethod -Uri $Uri -Method Delete -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationDiscoveryDataSource*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully removed discovery data source: $DataSourceId"
            } catch {
                Write-Error "Failed to remove discovery data source '$DataSourceId': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
