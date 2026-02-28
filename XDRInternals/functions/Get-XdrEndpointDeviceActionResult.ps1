function Get-XdrEndpointDeviceActionResult {
    <#
    .SYNOPSIS
        Gets device action results and download URIs from Microsoft Defender XDR.

    .DESCRIPTION
        Retrieves the latest device action results for a device, or downloads completed
        investigation package or support log collection results.

        When called with just -DeviceId, returns the latest action results for each action type
        including status, requestor, timestamps, and request GUIDs.

        When called with -DownloadInvestigationPackage or -DownloadSupportLogs, retrieves the
        download URI for completed collection results. You can provide either a DeviceId (which
        auto-resolves the latest RequestGuid from machine state) or a RequestGuid directly.

    .PARAMETER DeviceId
        The device identifier (SenseMachineId) to query action results for.
        Accepts pipeline input by property name and supports MachineId/SenseMachineId aliases.

    .PARAMETER DownloadInvestigationPackage
        Retrieve the download URI for the latest investigation package (forensics) collection.

    .PARAMETER DownloadSupportLogs
        Retrieve the download URI for the latest support logs collection.

    .PARAMETER RequestGuid
        The GUID of a specific request. When used with -DeviceId (List mode), filters the
        results to the matching request. When used with -DownloadInvestigationPackage or
        -DownloadSupportLogs, specifies the completed request to download results for.

    .EXAMPLE
        Get-XdrEndpointDeviceActionResult -DeviceId "55a5db7b474470725e0131dec38c07b2f54bf2ad"
        Gets the latest action results for the specified device.

    .EXAMPLE
        Get-XdrEndpointDeviceActionResult -DeviceId "55a5db7b474470725e0131dec38c07b2f54bf2ad" -RequestGuid "1b2010b8-143e-441b-b5e9-c0b56c090a24"
        Gets the action result for a specific request on the device.

    .EXAMPLE
        Get-XdrEndpointDevice -DeviceId $deviceId | Get-XdrEndpointDeviceActionResult
        Gets action results for a device using pipeline input.

    .EXAMPLE
        Get-XdrEndpointDeviceActionResult -DownloadInvestigationPackage -DeviceId "55a5db7b474470725e0131dec38c07b2f54bf2ad"
        Auto-resolves the latest investigation package request and returns its download URI.

    .EXAMPLE
        Get-XdrEndpointDevice -DeviceId $deviceId | Get-XdrEndpointDeviceActionResult -DownloadSupportLogs
        Gets the download URI for the latest support logs collection using pipeline input.

    .EXAMPLE
        Get-XdrEndpointDeviceActionResult -DownloadInvestigationPackage -RequestGuid "b28b630c-d1a1-4b1d-9676-680c15366a52"
        Downloads the investigation package for a specific request to the current working directory.

    .EXAMPLE
        Get-XdrEndpointDeviceActionResult -DownloadSupportLogs -RequestGuid "abc12345-6789-0123-4567-890abcdef012"
        Downloads the support logs for a specific request to the current working directory.

    .OUTPUTS
        PSCustomObject[]
        When listing: Returns an array of action result objects with Type, RequestStatus, Requestor, timestamps, etc.

        System.IO.FileInfo
        When downloading: Returns a FileInfo object for the downloaded file in the current working directory.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameter defines parameter set')]
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'List')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DownloadInvestigationPackageByDevice')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DownloadSupportLogsByDevice')]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40, 40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$DeviceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'DownloadInvestigationPackageByDevice')]
        [Parameter(Mandatory = $true, ParameterSetName = 'DownloadInvestigationPackageByRequest')]
        [switch]$DownloadInvestigationPackage,

        [Parameter(Mandatory = $true, ParameterSetName = 'DownloadSupportLogsByDevice')]
        [Parameter(Mandatory = $true, ParameterSetName = 'DownloadSupportLogsByRequest')]
        [switch]$DownloadSupportLogs,

        [Parameter(ParameterSetName = 'List')]
        [Parameter(Mandatory = $true, ParameterSetName = 'DownloadInvestigationPackageByRequest')]
        [Parameter(Mandatory = $true, ParameterSetName = 'DownloadSupportLogsByRequest')]
        [string]$RequestGuid
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        try {
            switch -Wildcard ($PSCmdlet.ParameterSetName) {
                'List' {
                    $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/latest?machineId=$DeviceId&tenantIds="
                    Write-Verbose "Retrieving latest action results for device $DeviceId"
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    if ($RequestGuid) {
                        Write-Verbose "Filtering results for RequestGuid: $RequestGuid"
                        $result = $result | Where-Object { $_.RequestGuid -eq $RequestGuid }
                    }
                    return $result
                }
                'DownloadInvestigationPackageBy*' {
                    if ($PSCmdlet.ParameterSetName -eq 'DownloadInvestigationPackageByDevice') {
                        $stateUri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/machinestate?machineId=$DeviceId&overrideCache=false"
                        Write-Verbose "Looking up latest investigation package request for device $DeviceId"
                        $state = Invoke-RestMethod -Uri $stateUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                        $RequestGuid = $state.RequestsIds.ForensicsRequest
                        if (-not $RequestGuid) {
                            Write-Error "No investigation package request found for device $DeviceId"
                            return
                        }
                        Write-Verbose "Resolved ForensicsRequest GUID: $RequestGuid (State: $($state.States.ForensicsRequest))"
                    }
                    $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/forensics/downloaduribyguid/V2?requestGuid=$RequestGuid&packageIdentity=null"
                    Write-Verbose "Retrieving investigation package download URI for request $RequestGuid"
                    $downloadUri = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $fileName = [System.IO.Path]::GetFileName(([System.Uri]$downloadUri).LocalPath)
                    if (-not $fileName) { $fileName = "InvestigationPackage-$RequestGuid.zip" }
                    $outFile = Join-Path $PWD $fileName
                    Write-Verbose "Downloading from:`n`n$downloadUri"
                    Invoke-WebRequest -Uri $downloadUri -OutFile $outFile
                    return Get-Item $outFile
                }
                'DownloadSupportLogsBy*' {
                    if ($PSCmdlet.ParameterSetName -eq 'DownloadSupportLogsByDevice') {
                        $stateUri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/machinestate?machineId=$DeviceId&overrideCache=false"
                        Write-Verbose "Looking up latest support logs request for device $DeviceId"
                        $state = Invoke-RestMethod -Uri $stateUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                        $RequestGuid = $state.RequestsIds.LogsCollectionRequest
                        if (-not $RequestGuid) {
                            Write-Error "No support logs request found for device $DeviceId"
                            return
                        }
                        Write-Verbose "Resolved LogsCollectionRequest GUID: $RequestGuid (State: $($state.States.LogsCollectionRequest))"
                    }
                    $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/logscollection/downloaduribyguid/V2?LogCollectionV2Migration=true&requestGuid=$RequestGuid"
                    Write-Verbose "Retrieving support logs download URI for request $RequestGuid"
                    $downloadUri = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $fileName = [System.IO.Path]::GetFileName(([System.Uri]$downloadUri).LocalPath)
                    if (-not $fileName) { $fileName = "SupportLogs-$RequestGuid.zip" }
                    $outFile = Join-Path $PWD $fileName
                    Write-Verbose "Downloading from:`n`n$downloadUri"
                    Invoke-WebRequest -Uri $downloadUri -OutFile $outFile
                    return Get-Item $outFile
                }
            }
        } catch {
            Write-Error "Failed to retrieve action result: $_"
        }
    }

    end {
    }
}
