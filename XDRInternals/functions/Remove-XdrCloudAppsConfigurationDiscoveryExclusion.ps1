function Remove-XdrCloudAppsConfigurationDiscoveryExclusion {
    <#
    .SYNOPSIS
        Removes a discovery exclusion from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Deletes a discovery exclusion from Microsoft Defender for Cloud Apps.
        This permanently removes the exclusion rule for cloud discovery.

    .PARAMETER ExclusionId
        The unique identifier of the discovery exclusion to remove.
        Accepts pipeline input from the _id property of exclusion objects.

    .PARAMETER Confirm
        Prompts for confirmation before removing the discovery exclusion.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The discovery exclusion is not removed.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationDiscoveryExclusion -ExclusionId "abc123def456"
        Removes the specified discovery exclusion.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryExclusion | Where-Object { $_.name -eq 'Test Exclusion' } | Remove-XdrCloudAppsConfigurationDiscoveryExclusion
        Finds a discovery exclusion by name and removes it through the pipeline.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryExclusion | Remove-XdrCloudAppsConfigurationDiscoveryExclusion -WhatIf
        Shows what would happen if all discovery exclusions were removed.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryExclusion | Remove-XdrCloudAppsConfigurationDiscoveryExclusion -Confirm:$false
        Removes all discovery exclusions without confirmation (use with caution).

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
        [string]$ExclusionId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/api/v1/discovery/exclude_entities/$ExclusionId/"

        if ($PSCmdlet.ShouldProcess($ExclusionId, "Remove discovery exclusion")) {
            Write-Verbose "Removing discovery exclusion: $ExclusionId"

            try {
                $null = Invoke-RestMethod -Uri $Uri -Method Delete -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationDiscoveryExclusion*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully removed discovery exclusion: $ExclusionId"
            } catch {
                Write-Error "Failed to remove discovery exclusion '$ExclusionId': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
