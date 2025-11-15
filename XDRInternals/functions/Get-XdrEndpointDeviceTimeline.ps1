function Get-XdrEndpointDeviceTimeline {
    <#
    .SYNOPSIS
        Retrieves the timeline of events for a specific device from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the timeline of security events for a device from the Microsoft Defender XDR portal with options to filter by date range and other parameters.

    .PARAMETER DeviceId
        The unique identifier of the device. Accepts pipeline input and can also be specified as MachineId.

    .PARAMETER MachineDnsName
        Optional. The DNS name of the machine.

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
        Get-XdrEndpointDeviceTimeline -DeviceId "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" -FromDate (Get-Date).AddDays(-7) -ToDate (Get-Date)
        Retrieves timeline events for the last 7 days.

    .EXAMPLE
        "2bec169acc9def3ebd0bf8cdcbd9d16eb37e50e2" | Get-XdrEndpointDeviceTimeline
        Retrieves timeline events using pipeline input.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('MachineId')]
        [string]$DeviceId,

        [Parameter()]
        [string]$MachineDnsName,

        [Parameter()]
        [string]$SenseClientVersion,

        [Parameter()]
        [bool]$GenerateIdentityEvents = $true,

        [Parameter()]
        [bool]$IncludeIdentityEvents = $true,

        [Parameter()]
        [bool]$SupportMdiOnlyEvents = $true,

        [Parameter()]
        [datetime]$FromDate = ((Get-Date).AddHours(-1)),

        [Parameter()]
        [datetime]$ToDate = (Get-Date),

        [Parameter()]
        [bool]$DoNotUseCache = $false,

        [Parameter()]
        [bool]$ForceUseCache = $false,

        [Parameter()]
        [int]$PageSize = 200,

        [Parameter()]
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

        $Uri = "https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/$DeviceId/events/?$($queryParams -join '&')"

        Write-Verbose "Retrieving XDR Endpoint device timeline for device $DeviceId (From: $FromDate, To: $ToDate, CorrelationId: $correlationId)"
        Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }

    end {

    }
}