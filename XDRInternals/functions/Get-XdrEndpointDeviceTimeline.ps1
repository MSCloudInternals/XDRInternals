function Get-XdrEndpointDeviceTimeline {
    <#
    .SYNOPSIS
        Retrieves the timeline of events for a specific device from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the timeline of security events for a device from the Microsoft Defender XDR portal with options to filter by date range and other parameters.

    .PARAMETER DeviceId
        The unique identifier of the device. Accepts pipeline input and can also be specified as MachineId. Use this parameter set when identifying the device by ID.

    .PARAMETER MachineDnsName
        The DNS name of the machine. Use this parameter set when identifying the device by DNS name.

    .PARAMETER SenseClientVersion
        Optional. The version of the Sense client.

    .PARAMETER GenerateIdentityEvents
        Whether to generate identity events. Defaults to $true.

    .PARAMETER IncludeIdentityEvents
        Whether to include identity events. Defaults to $true.

    .PARAMETER SupportMdiOnlyEvents
        Whether to support MDI-only events. Defaults to $true.

    .PARAMETER FromDate
        The start date for the timeline. Defaults to 1 hour before current time.

    .PARAMETER ToDate
        The end date for the timeline. Defaults to current time.

    .PARAMETER DoNotUseCache
        Whether to bypass the cache. Defaults to $false.

    .PARAMETER ForceUseCache
        Whether to force using the cache. Defaults to $false.

    .PARAMETER PageSize
        The number of events to return per page. Defaults to 200.

    .PARAMETER IncludeSentinelEvents
        Whether to include Sentinel events. Defaults to $false.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2"
        Retrieves the last hour of timeline events for the specified device.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -MachineDnsName "computer.contoso.com"
        Retrieves the last hour of timeline events using the machine DNS name.

    .EXAMPLE
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -FromDate (Get-Date).AddDays(-7) -ToDate (Get-Date)
        Retrieves timeline events for the last 7 days.

    .EXAMPLE
        "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" | Get-XdrEndpointDeviceTimeline
        Retrieves timeline events using pipeline input.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByDeviceId')]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'ByDeviceId')]
        [Alias('MachineId')]
        [string]$DeviceId,

        [Parameter(Mandatory, ParameterSetName = 'ByMachineDnsName')]
        [string]$MachineDnsName,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [string]$SenseClientVersion,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [bool]$GenerateIdentityEvents = $true,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [bool]$IncludeIdentityEvents = $true,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [bool]$SupportMdiOnlyEvents = $true,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [datetime]$FromDate = ((Get-Date).AddHours(-1)),

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [datetime]$ToDate = (Get-Date),

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [bool]$DoNotUseCache = $false,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [bool]$ForceUseCache = $false,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [int]$PageSize = 200,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [bool]$IncludeSentinelEvents = $false
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Generate a new correlation ID
        $correlationId = [guid]::NewGuid().ToString()

        # Build the URI with query parameters
        $queryParams = @(
            "generateIdentityEvents=$($GenerateIdentityEvents.ToString().ToLower())"
            "includeIdentityEvents=$($IncludeIdentityEvents.ToString().ToLower())"
            "supportMdiOnlyEvents=$($SupportMdiOnlyEvents.ToString().ToLower())"
            "fromDate=$([System.Uri]::EscapeDataString($FromDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))"
            "toDate=$([System.Uri]::EscapeDataString($ToDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))"
            "correlationId=$correlationId"
            "doNotUseCache=$($DoNotUseCache.ToString().ToLower())"
            "forceUseCache=$($ForceUseCache.ToString().ToLower())"
            "pageSize=$PageSize"
            "includeSentinelEvents=$($IncludeSentinelEvents.ToString().ToLower())"
        )

        if ($PSBoundParameters.ContainsKey('MachineDnsName')) {
            $queryParams = @("machineDnsName=$([System.Uri]::EscapeDataString($MachineDnsName))") + $queryParams
        }

        if ($PSBoundParameters.ContainsKey('SenseClientVersion')) {
            $queryParams = @("SenseClientVersion=$([System.Uri]::EscapeDataString($SenseClientVersion))") + $queryParams
        }

        # Determine the device identifier to use in the URI
        $deviceIdentifier = if ($PSCmdlet.ParameterSetName -eq 'ByDeviceId') { $DeviceId } else { (Get-XdrEndpointDevice -MachineSearchPrefix $MachineDnsName).MachineId }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/$deviceIdentifier/events/?$($queryParams -join '&')"

        Write-Verbose "Retrieving XDR Endpoint device timeline for device $deviceIdentifier (From: $FromDate, To: $ToDate, CorrelationId: $correlationId)"
        Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }

    end {
    }
}