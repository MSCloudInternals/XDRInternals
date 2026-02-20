function Invoke-XdrEndpointDevicePolicySync {
    <#
    .SYNOPSIS
        Forces a policy sync on an endpoint device in Microsoft Defender XDR.

    .DESCRIPTION
        Triggers a forced policy synchronization for a managed endpoint device.
        This is useful when policy changes need to be applied immediately.

    .PARAMETER DeviceId
        The device ID (SenseMachineId) of the target device.

    .PARAMETER Comment
        A comment describing the reason for the policy sync.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .EXAMPLE
        Invoke-XdrEndpointDevicePolicySync -DeviceId "abc123"
        Forces a policy sync on the specified device.

    .EXAMPLE
        Invoke-XdrEndpointDevicePolicySync -DeviceId "abc123" -Comment "Apply new AV exclusions"
        Forces a policy sync with a descriptive comment.

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Comment is used in body construction')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40,40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$DeviceId,

        [Parameter()]
        [string]$Comment = "Force policy sync - Performed by $env:USERNAME via XDRInternals"
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $device = Get-XdrEndpointDevice -DeviceId $DeviceId
        $body = @{
            RequestorComment   = $Comment
            SenseClientVersion = $device.SenseClientVersion
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess("Device $($device.ComputerDnsName) ($DeviceId)", "Force policy sync")) {
            try {
                $Uri = "https://security.microsoft.com/apiproxy/mtp/siamApi/machines/$DeviceId/forceDeviceSync"
                Write-Verbose "Forcing policy sync on device $DeviceId"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                return $result
            } catch {
                Write-Error "Failed to force policy sync: $_"
            }
        }
    }

    end {
    }
}
