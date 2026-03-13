function Set-XdrEndpointDeviceExclusionState {
    <#
    .SYNOPSIS
        Sets the exclusion state on endpoint devices in Microsoft Defender XDR.

    .DESCRIPTION
        Updates the exclusion state for one or more endpoint devices.
        Devices can be excluded from or included in Defender for Endpoint monitoring.

    .PARAMETER DeviceId
        One or more device IDs (SenseMachineIds) identifying the target devices.

    .PARAMETER ExclusionState
        The exclusion state to set. Valid values: Excluded, Included.

    .PARAMETER Justification
        Justification for the exclusion state change. Required when excluding devices.

    .PARAMETER Notes
        Additional notes for the exclusion state change.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .EXAMPLE
        Set-XdrEndpointDeviceExclusionState -DeviceId "abc123" -ExclusionState Excluded -Justification "MachineOutOfScope" -Notes "Lab device"
        Excludes the device with a justification and notes.

    .EXAMPLE
        Set-XdrEndpointDeviceExclusionState -DeviceId "abc123" -ExclusionState Included
        Re-includes a previously excluded device.

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess implemented in process block')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40,40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$DeviceId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Excluded', 'Included')]
        [string]$ExclusionState,

        [Parameter()]
        [string]$Justification,

        [Parameter()]
        [string]$Notes
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($ExclusionState -eq 'Excluded' -and [string]::IsNullOrWhiteSpace($Justification)) {
            Write-Error "-Justification is required when ExclusionState is 'Excluded'."
            return
        }

        $body = @{
            ExclusionState  = $ExclusionState
            SenseMachineIds = $DeviceId
        }
        if ($Justification) { $body['Justification'] = $Justification }
        if ($Notes) { $body['Notes'] = $Notes }
        $bodyJson = $body | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess("Devices: $($DeviceId -join ', ')", "Set exclusion state to $ExclusionState")) {
            try {
                $Uri = "https://security.microsoft.com/apiproxy/mtp/k8s/machines/UpdateExclusionState"
                Write-Verbose "Setting exclusion state to $ExclusionState on $($DeviceId.Count) device(s)"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $bodyJson -WebSession $script:session -Headers $script:headers
                return $result
            } catch {
                Write-Error "Failed to set exclusion state: $_"
            }
        }
    }

    end {
    }
}
