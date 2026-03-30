function Invoke-XdrEndpointDeviceAutomatedInvestigation {
    <#
    .SYNOPSIS
        Starts an automated investigation on an endpoint device in Microsoft Defender XDR.

    .DESCRIPTION
        Triggers an automated investigation (AutoIR) for the specified endpoint device.
        This initiates the Defender XDR automated investigation and remediation workflow.

    .PARAMETER DeviceId
        The device ID (SenseMachineId) of the target device.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAutomatedInvestigation -DeviceId "abc123"
        Starts an automated investigation on the specified device.

    .OUTPUTS
        Object
        Returns the API response with investigation details.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40,40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$DeviceId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $body = @{
            machine = $DeviceId
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess("Device $DeviceId", "Start automated investigation")) {
            try {
                $Uri = "https://security.microsoft.com/apiproxy/mtp/autoIr/ui/investigations/?useDotnetAutoIrUi=true"
                Write-Verbose "Starting automated investigation on device $DeviceId"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                return $result
            } catch {
                Write-Error "Failed to start automated investigation: $_"
            }
        }
    }

    end {
    }
}
