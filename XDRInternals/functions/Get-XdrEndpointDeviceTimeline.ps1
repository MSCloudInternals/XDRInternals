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

    .PARAMETER MarkedEventsOnly
        Only return events that have been marked in the timeline.

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

    .PARAMETER LastNDays
        Specifies the number of days to look back. Overrides FromDate and ToDate if specified.

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
    [OutputType([System.Object[]])]
    [CmdletBinding(DefaultParameterSetName = 'ByDeviceId')]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'ByDeviceId')]
        [Alias('MachineId')]
        [string]$DeviceId,

        [Parameter(Mandatory, ParameterSetName = 'ByMachineDnsName')]
        [string]$MachineDnsName,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [datetime]$FromDate = ((Get-Date).AddHours(-1)),

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [datetime]$ToDate = (Get-Date),

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [int]$LastNDays,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [ValidateRange(1, 1000)]
        [int]$PageSize = 200,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [switch]$MarkedEventsOnly,

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
        [bool]$DoNotUseCache = $false,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [bool]$ForceUseCache = $false,

        [Parameter(ParameterSetName = 'ByDeviceId')]
        [Parameter(ParameterSetName = 'ByMachineDnsName')]
        [bool]$IncludeSentinelEvents = $false
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($PSBoundParameters.ContainsKey('LastNDays')) {
            $ToDate = Get-Date
            $FromDate = $ToDate.AddDays(-$LastNDays)
        }

        if (($ToDate - $FromDate).TotalDays -gt 30) {
            throw "The time range between FromDate and ToDate cannot exceed 30 days."
        }

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

        if ($MarkedEventsOnly) {
            $queryParams = @("markedEventsOnly=true") + $queryParams
        }

        # Determine the device identifier to use in the URI
        $deviceIdentifier = if ($PSCmdlet.ParameterSetName -eq 'ByDeviceId') { $DeviceId } else { (Get-XdrEndpointDevice -MachineSearchPrefix $MachineDnsName).MachineId }

        try {
            $TimelineEvents = [System.Collections.Generic.List[object]]::new()
            $Uri = "https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/$deviceIdentifier/events/?$($queryParams -join '&')"
            do {
                # Parse Uri to extract fromDate, toDate, correlationId, and other parameters
                Write-Debug "URI: $Uri"
                $parsedUri = [System.Uri]::new($Uri)
                $query = [System.Web.HttpUtility]::ParseQueryString($parsedUri.Query)
                $fromDate = [datetime]$query["fromDate"]
                $toDate = [datetime]$query["toDate"]
                $correlationId = $query["correlationId"]
                Write-Verbose "Retrieving XDR Endpoint device timeline for device $deviceIdentifier (From: $fromDate, To: $toDate, CorrelationId: $correlationId)"
                # Try three times before giving up
                $attempt = 0
                do {
                    try {
                        $attempt++
                        $response = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                        break
                    } catch {
                        if ($attempt -lt 3) {
                            Write-Warning "Attempt $($attempt + 1) failed. Retrying..."
                            Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 10)
                        } else {
                            throw "Failed to retrieve endpoint device timeline after 3 attempts."
                        }
                    }
                } while ($attempt -lt 3)

                if ($response -and $response.Items) {
                    Write-Verbose "Retrieved $($response.Items.Count) timeline events for device $deviceIdentifier."
                    $TimelineEvents.AddRange($response.Items)
                } else {
                    Write-Verbose "No more timeline events found for device $deviceIdentifier."
                    return $TimelineEvents
                }

                if ([string]::IsNullOrWhiteSpace($response.Prev)) {
                    Write-Verbose "No more timeline events to retrieve for device $deviceIdentifier."
                    return $TimelineEvents
                } else {
                    Write-Debug "Previous page $($response.Prev)"
                    $Uri = "https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience$($response.Prev)"
                }

                # Add a random delay between 3 and 10 seconds to avoid hitting rate limits
                $SleepTime = Get-Random -Minimum 3 -Maximum 10
                Write-Debug "Sleeping for $SleepTime seconds to avoid rate limits."
                Start-Sleep -Seconds $SleepTime
            } while ($true)
        } catch {
            Write-Error "Failed to retrieve endpoint device timeline: $_"
        }
    }

    end {
    }
}