function Remove-XdrCloudAppsConfigurationSubnet {
    <#
    .SYNOPSIS
        Removes a subnet (IP address range) from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Deletes a subnet configuration from Microsoft Defender for Cloud Apps.
        This permanently removes the IP address range and its associated metadata.

    .PARAMETER SubnetId
        The unique identifier of the subnet to remove.
        Accepts pipeline input from the _id property of subnet objects.

    .PARAMETER Confirm
        Prompts for confirmation before removing the subnet.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The subnet is not removed.

    .EXAMPLE
        Remove-XdrCloudAppsConfigurationSubnet -SubnetId "abc123def456"
        Removes the specified subnet.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSubnet | Where-Object { $_.name -eq 'Test Subnet' } | Remove-XdrCloudAppsConfigurationSubnet
        Finds a subnet by name and removes it through the pipeline.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSubnet | Where-Object { $_.category -eq 'Other' } | Remove-XdrCloudAppsConfigurationSubnet -WhatIf
        Shows what would happen if all subnets in the 'Other' category were removed.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationSubnet | Remove-XdrCloudAppsConfigurationSubnet -Confirm:$false
        Removes all subnets without confirmation (use with caution).

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
        [string]$SubnetId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/subnet/$SubnetId/"

        if ($PSCmdlet.ShouldProcess($SubnetId, "Remove subnet")) {
            Write-Verbose "Removing subnet: $SubnetId"

            try {
                $null = Invoke-RestMethod -Uri $Uri -Method Delete -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationSubnet*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully removed subnet: $SubnetId"
            } catch {
                Write-Error "Failed to remove subnet '$SubnetId': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
