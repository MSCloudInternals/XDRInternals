function Get-XdrEndpointDeviceTotals {
    <#
    .SYNOPSIS
        Retrieves the device totals from Microsoft Defender XDR.
    
    .DESCRIPTION
        Gets the total count of devices from the Microsoft Defender XDR portal with options to filter low fidelity devices and specify the lookback period.
    
    .PARAMETER HideLowFidelityDevices
        Whether to hide low fidelity devices from the results. Defaults to $true.
    
    .PARAMETER LookingBackInDays
        The number of days to look back for device data. Defaults to 30 days.
    
    .EXAMPLE
        Get-XdrEndpointDeviceTotals
        Retrieves device totals using default settings (hiding low fidelity devices, 30 days lookback).
    
    .EXAMPLE
        Get-XdrEndpointDeviceTotals -HideLowFidelityDevices $false -LookingBackInDays 90
        Retrieves device totals including low fidelity devices with a 90-day lookback period.
    
    .EXAMPLE
        Get-XdrEndpointDeviceTotals -LookingBackInDays 7
        Retrieves device totals for the last 7 days, hiding low fidelity devices.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [bool]$HideLowFidelityDevices = $true,
        
        [Parameter()]
        [int]$LookingBackInDays = 30
    )

    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/deviceTotals/?hideLowFidelityDevices=$($HideLowFidelityDevices.ToString().ToLower())&lookingBackIndays=$LookingBackInDays"
        Write-Verbose "Retrieving XDR Endpoint device totals (HideLowFidelity: $HideLowFidelityDevices, LookbackDays: $LookingBackInDays)"
        Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }
    
    end {
    }
}
