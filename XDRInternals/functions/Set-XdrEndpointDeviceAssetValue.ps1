function Set-XdrEndpointDeviceAssetValue {
    <#
    .SYNOPSIS
        Sets the asset value on endpoint devices in Microsoft Defender XDR.

    .DESCRIPTION
        Updates the asset value classification for one or more endpoint devices.
        Valid asset values are Low, Normal, and High.

    .PARAMETER DeviceId
        One or more device IDs (SenseMachineIds) identifying the target devices.

    .PARAMETER AssetValue
        The asset value to assign. Valid values: Low, Normal, High.

    .PARAMETER Confirm
        Prompts for confirmation before making changes.

    .PARAMETER WhatIf
        Shows what would happen if the command runs. The command is not run.

    .EXAMPLE
        Set-XdrEndpointDeviceAssetValue -DeviceId "abc123" -AssetValue High
        Sets the asset value to High on the specified device.

    .EXAMPLE
        Set-XdrEndpointDeviceAssetValue -DeviceId "abc123", "def456" -AssetValue Low
        Sets the asset value to Low on multiple devices.

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
        [ValidateSet('Low', 'Normal', 'High')]
        [string]$AssetValue
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $body = @{
            AssetValue      = $AssetValue
            SenseMachineIds = $DeviceId
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess("Devices: $($DeviceId -join ', ')", "Set asset value to $AssetValue")) {
            try {
                $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/assetValues"
                Write-Verbose "Setting asset value to $AssetValue on $($DeviceId.Count) device(s)"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                return $result
            } catch {
                Write-Error "Failed to set asset value: $_"
            }
        }
    }

    end {
    }
}
