function Set-XdrEndpointDeviceCriticalityLevel {
    <#
    .SYNOPSIS
        Sets the criticality level on endpoint devices in Microsoft Defender XDR.

    .DESCRIPTION
        Updates the criticality level for one or more endpoint devices.
        Criticality levels help prioritize security operations based on device importance.

    .PARAMETER DeviceId
        One or more device IDs (SenseMachineIds) identifying the target devices.

    .PARAMETER CriticalityLevel
        The criticality level to assign. Valid values: VeryHigh, High, Medium, Low, Reset.
        Reset removes the criticality level from the device.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .EXAMPLE
        Set-XdrEndpointDeviceCriticalityLevel -DeviceId "abc123" -CriticalityLevel High
        Sets the criticality level to High on the specified device.

    .EXAMPLE
        Set-XdrEndpointDeviceCriticalityLevel -DeviceId "abc123", "def456" -CriticalityLevel Medium
        Sets the criticality level to Medium on multiple devices.

    .EXAMPLE
        Set-XdrEndpointDeviceCriticalityLevel -DeviceId "abc123" -CriticalityLevel Reset
        Removes the criticality level from the specified device.

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'ShouldProcess implemented in process block')]
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40,40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string[]]$DeviceId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('VeryHigh', 'High', 'Medium', 'Low', 'Reset')]
        [string]$CriticalityLevel
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $levelMap = @{
            'VeryHigh' = 0
            'High'     = 1
            'Medium'   = 2
            'Low'      = 3
            'Reset'    = $null
        }
        $levelValue = $levelMap[$CriticalityLevel]

        $body = @{
            CriticalityLevel = $levelValue
            DeviceIds        = $DeviceId
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess("Devices: $($DeviceId -join ', ')", "Set criticality level to $CriticalityLevel")) {
            try {
                $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/criticalityLevel"
                Write-Verbose "Setting criticality level to $CriticalityLevel ($levelValue) on $($DeviceId.Count) device(s)"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                return $result
            } catch {
                Write-Error "Failed to set criticality level: $_"
            }
        }
    }

    end {
    }
}
