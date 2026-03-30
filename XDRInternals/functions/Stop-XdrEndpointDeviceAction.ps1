function Stop-XdrEndpointDeviceAction {
    <#
    .SYNOPSIS
        Cancels a pending device action in Microsoft Defender XDR.

    .DESCRIPTION
        Cancels a device response action that is currently in a pending/submitted state.
        Uses the request GUID from the original action submission to identify the action to cancel.

    .PARAMETER RequestGuid
        The GUID of the request to cancel. This is returned when an action is submitted.

    .PARAMETER Comment
        A comment explaining the reason for the cancellation.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .EXAMPLE
        Stop-XdrEndpointDeviceAction -RequestGuid "b28b630c-d1a1-4b1d-9676-680c15366a52" -Comment "Action no longer needed"
        Cancels the specified device action with a comment.

    .EXAMPLE
        Stop-XdrEndpointDeviceAction -RequestGuid "b28b630c-d1a1-4b1d-9676-680c15366a52"
        Cancels the specified device action.

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$RequestGuid,

        [Parameter()]
        [string]$Comment = "Action cancelled - Performed by $env:USERNAME via XDRInternals"
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $encodedComment = [System.Uri]::EscapeDataString($Comment)

        if ($PSCmdlet.ShouldProcess("Request $RequestGuid", "Cancel device action")) {
            try {
                $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/cancelbyid?requestGuid=$RequestGuid&comment=$encodedComment"
                Write-Verbose "Cancelling device action request $RequestGuid"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                return $result
            } catch {
                Write-Error "Failed to cancel device action: $_"
            }
        }
    }

    end {
    }
}
