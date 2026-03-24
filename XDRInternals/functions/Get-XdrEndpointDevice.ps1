function Get-XdrEndpointDevice {
    <#
    .SYNOPSIS
        Retrieves endpoint devices from Microsoft Defender XDR.

    .DESCRIPTION
        Gets endpoint devices from the Microsoft Defender XDR portal. Supports two modes:
        - List (default): Retrieves devices with options to filter, sort, and paginate results.
        - DeviceId: Retrieves detailed information for a single device by its identifier.
          Uses the getMachine API and caches results for 5 minutes.

    .PARAMETER DeviceId
        The device identifier (also known as MachineId or SenseMachineId). When specified,
        retrieves detailed information for a single device. Results are cached for 5 minutes.

    .PARAMETER Force
        Bypasses the cache when using -DeviceId and forces a fresh retrieval from the API.

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

    .EXAMPLE
        Get-XdrEndpointDevice -DeviceId "abc123def456"
        Retrieves detailed information for a single device by its identifier.
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(ParameterSetName = 'DeviceId', Mandatory = $true)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40,40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$DeviceId,

        [Parameter(ParameterSetName = 'DeviceId')]
        [switch]$Force,

        [Parameter(ParameterSetName = 'List')]
        [string]$MachineSearchPrefix,

        [Parameter(ParameterSetName = 'List')]
        [int]$LookingBackInDays = 30,

        [Parameter(ParameterSetName = 'List')]
        [int]$PageIndex = 1,

        [Parameter(ParameterSetName = 'List')]
        [int]$PageSize = 25,

        [Parameter(ParameterSetName = 'List')]
        [string]$SortByField = "riskscore",

        [Parameter(ParameterSetName = 'List')]
        [ValidateSet("Ascending", "Descending")]
        [string]$SortOrder = "Descending",

        [Parameter(ParameterSetName = 'List')]
        [bool]$HideLowFidelityDevices = $true
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'DeviceId') {
            $CacheKey = "XdrDeviceDetails_$DeviceId"
            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached device details for $DeviceId"
                    return $cache.Value
                }
            }

            $DeviceUri = "https://security.microsoft.com/apiproxy/mtp/getMachine/machines?machineId=$DeviceId&idType=SenseMachineId&readFromCache=false&lookingBackIndays=180"
            Write-Verbose "Retrieving device details for DeviceId: $DeviceId"

            try {
                $result = Invoke-RestMethod -Uri $DeviceUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            } catch {
                throw "Failed to retrieve device details for DeviceId '$DeviceId': $_"
            }

            if (-not $result) {
                throw "Device not found: $DeviceId"
            }

            Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
            return $result
        }

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
