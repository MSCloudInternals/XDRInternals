function Set-XdrCloudAppsDiscoveredApp {
    <#
    .SYNOPSIS
        Updates a discovered app note in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Updates the admin note for a discovered Cloud Apps application. This is
        the only live-validated discovered-app write surface currently exposed.

    .PARAMETER AppId
        The unique identifier of the discovered app to update.

    .PARAMETER Note
        The note text to set for the discovered app.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .PARAMETER Confirm
        Prompts for confirmation before updating the discovered app note.

    .EXAMPLE
        Set-XdrCloudAppsDiscoveredApp -AppId "12345" -Note "Approved for marketing team use"

        Sets a note on the discovered app.
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('pk', 'Id', '_id')]
        [string]$AppId,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Note
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $body = @{
            note = $Note
            pk   = $AppId
        }

        if ($PSCmdlet.ShouldProcess($AppId, 'Update Cloud Apps discovered app note')) {
            try {
                $result = Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/discovery_app/update_app_note/' -Method Post -Body $body -Raw
                Write-Verbose "Successfully updated note for discovered app: $AppId"
                return $result
            }
            catch {
                Write-Error "Failed to update note for discovered app '$AppId': $($_.Exception.Message)"
            }
        }
    }

    end {
    }
}
