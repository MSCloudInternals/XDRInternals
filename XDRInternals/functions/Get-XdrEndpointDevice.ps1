function Get-XdrEndpointDevice {
    <#
    .SYNOPSIS
        Retrieves endpoint devices from Microsoft Defender XDR.

    .DESCRIPTION
        Gets a list of endpoint devices from the Microsoft Defender XDR portal with options to filter, sort, and paginate the results.

    .PARAMETER HideLowFidelityDevices
        Whether to hide low fidelity devices from the results. Defaults to $true.

    .PARAMETER LookingBackInDays
        The number of days to look back for device data. Defaults to 30 days.

    .PARAMETER PageIndex
        The page index for pagination. Defaults to 1.

    .PARAMETER PageSize
        The number of devices to return per page. Defaults to 25.

    .PARAMETER SortByField
        The field to sort devices by. Defaults to 'riskscore'.

    .PARAMETER SortOrder
        The sort order for results. Valid values are 'Ascending' or 'Descending'. Defaults to 'Descending'.

    .PARAMETER MachineSearchPrefix
        Optional. Search for devices by name prefix. Use this to filter devices whose names start with the specified string.

    .EXAMPLE
        Get-XdrEndpointDevice
        Retrieves the first 25 devices sorted by risk score in descending order using default settings.

    .EXAMPLE
        Get-XdrEndpointDevice -PageSize 100 -PageIndex 2
        Retrieves the second page of 100 devices.

    .EXAMPLE
        Get-XdrEndpointDevice -SortByField "lastSeen" -SortOrder "Ascending"
        Retrieves devices sorted by last seen date in ascending order.

    .EXAMPLE
        Get-XdrEndpointDevice -HideLowFidelityDevices $false -LookingBackInDays 90
        Retrieves devices including low fidelity devices with a 90-day lookback period.

    .EXAMPLE
        Get-XdrEndpointDevice -MachineSearchPrefix "DESKTOP"
        Retrieves devices whose names start with "DESKTOP".
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$MachineSearchPrefix,

        [Parameter()]
        [int]$LookingBackInDays = 30,

        [Parameter()]
        [int]$PageIndex = 1,

        [Parameter()]
        [int]$PageSize = 25,

        [Parameter()]
        [string]$SortByField = "riskscore",

        [Parameter()]
        [ValidateSet("Ascending", "Descending")]
        [string]$SortOrder = "Descending",

        [Parameter()]
        [bool]$HideLowFidelityDevices = $true
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines?hideLowFidelityDevices=$($HideLowFidelityDevices.ToString().ToLower())&lookingBackIndays=$LookingBackInDays&pageIndex=$PageIndex&pageSize=$PageSize&sortByField=$SortByField&sortOrder=$SortOrder"

        if ($PSBoundParameters.ContainsKey('MachineSearchPrefix')) {
            $Uri += "&machineSearchPrefix=$([System.Uri]::EscapeDataString($MachineSearchPrefix))"
        }
        try {
            Write-Verbose "Retrieving XDR Endpoint devices (Page: $PageIndex, Size: $PageSize, Sort: $SortByField $SortOrder$(if ($MachineSearchPrefix) { ", Search: $MachineSearchPrefix" }))"
            $result = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        } catch {
            Write-Error "Failed to retrieve endpoint devices: $_"
            return
        }
        
        # Add custom type name for formatting
        if ($result) {
            foreach ($machine in $result) {
                $machine.PSObject.TypeNames.Insert(0, 'XdrEndpointDevice')
            }
        }
        
        return $result
    }

    end {
    }
}
