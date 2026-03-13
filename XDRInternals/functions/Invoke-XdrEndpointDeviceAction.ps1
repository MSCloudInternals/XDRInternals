function Invoke-XdrEndpointDeviceAction {
    <#
    .SYNOPSIS
        Invokes response actions on an endpoint device in Microsoft Defender XDR.

    .DESCRIPTION
        Unified cmdlet for executing device response actions including antivirus scans,
        device isolation, app execution restriction, investigation package collection,
        support log collection, troubleshooting mode, tag management, asset value,
        criticality level, exclusion state, policy sync, automated investigation,
        and live response sessions.

        For responseApiPortal actions (Scan, Isolate, Restrict, etc.), the cmdlet
        auto-fetches OsPlatform and SenseClientVersion from the device.

        For other actions, the cmdlet wraps dedicated cmdlets like Set-XdrEndpointDeviceTag,
        Set-XdrEndpointDeviceAssetValue, etc.

    .PARAMETER DeviceId
        The device ID (SenseMachineId) of the target device. Required for all actions.

    .PARAMETER Comment
        A comment describing the reason for the action. Used as RequestorComment for API calls.

    .PARAMETER Scan
        Runs an antivirus scan on the device. Valid values: Quick, Full.

    .PARAMETER Isolate
        Isolates the device from the network. Valid values: Full, Selective.

    .PARAMETER ReleaseFromIsolation
        Releases the device from network isolation.

    .PARAMETER RestrictAppExecution
        Restricts application execution on the device to Microsoft-signed binaries only.
        macOS note: this action is currently unsupported and should be attempted only for
        capability detection/documentation.

    .PARAMETER RemoveAppExecutionRestriction
        Removes application execution restriction from the device.
        macOS note: this action is currently unsupported and should be attempted only for
        capability detection/documentation.

    .PARAMETER CollectInvestigationPackage
        Collects a forensic investigation package from the device.

    .PARAMETER CollectSupportLogs
        Collects support diagnostic logs from the device.

    .PARAMETER StartTroubleshoot
        Enables troubleshooting mode on the device.

    .PARAMETER TroubleshootDurationHours
        Duration in hours for troubleshooting mode. Defaults to 4. Maximum 12.

    .PARAMETER StopTroubleshoot
        Disables troubleshooting mode on the device.

    .PARAMETER SetTags
        Array of tag strings to set on the device. Replaces all existing user-defined tags.
        Wraps Set-XdrEndpointDeviceTag. For add/remove semantics, use Set-XdrEndpointDeviceTag -Add or -Remove directly.

    .PARAMETER SetAssetValue
        Sets the asset value of the device. Valid values: Low, Normal, High.
        Wraps Set-XdrEndpointDeviceAssetValue.

    .PARAMETER SetCriticalityLevel
        Sets the criticality level. Valid values: VeryHigh, High, Medium, Low, Reset.
        Reset removes the criticality level. Wraps Set-XdrEndpointDeviceCriticalityLevel.

    .PARAMETER SetExclusionState
        Sets the exclusion state. Valid values: Excluded, Included.
        Wraps Set-XdrEndpointDeviceExclusionState.

    .PARAMETER Justification
        Justification for exclusion state change.

    .PARAMETER Notes
        Additional notes for the exclusion state change.

    .PARAMETER ForceSync
        Forces a policy sync on the device. Wraps Invoke-XdrEndpointDevicePolicySync.

    .PARAMETER StartInvestigation
        Starts an automated investigation. Wraps Invoke-XdrEndpointDeviceAutomatedInvestigation.
        macOS note: this action is currently unsupported and should be attempted only for
        capability detection/documentation.

    .PARAMETER LiveResponse
        Starts an interactive Live Response session. Wraps Connect-XdrEndpointDeviceLiveResponse.

    .PARAMETER Confirm
        Prompts for confirmation before executing the operation.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs without actually performing the action.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAction -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2" -Scan Quick
        Runs a quick antivirus scan on the specified device.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAction -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2" -Scan Full -Comment "macOS validation full scan"
        Runs a full antivirus scan with a comment.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAction -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2" -Isolate Full -Comment "macOS containment test"
        Fully isolates the device from the network.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAction -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2" -ReleaseFromIsolation -Comment "macOS containment test rollback"
        Releases the device from isolation.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAction -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2" -CollectInvestigationPackage -Comment "macOS evidence collection"
        Collects a forensic investigation package from the device.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAction -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2" -LiveResponse
        Opens an interactive Live Response session to the device.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAction -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2" -SetAssetValue High
        Sets the asset value to High.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAction -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2" -ForceSync -Comment "macOS policy sync validation"
        Forces a policy sync on the device.

    .NOTES
        macOS validation baseline: February 24, 2026.

        Validated on macOS:
        Scan (Quick, Full), Isolate (Full, Selective), ReleaseFromIsolation,
        CollectInvestigationPackage, StartTroubleshoot, StopTroubleshoot, SetTags,
        SetAssetValue, SetCriticalityLevel, SetExclusionState, ForceSync, LiveResponse.

        Service-dependent on macOS:
        CollectSupportLogs (may return transient backend InternalServerError).

        Not currently supported on macOS:
        RestrictAppExecution, RemoveAppExecutionRestriction, StartInvestigation.

    .OUTPUTS
        PSCustomObject
        Returns the API response from the action. For Live Response, enters an interactive session.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Delegated to ShouldProcess in process block')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameters define parameter sets')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Scan')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40,40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$DeviceId,

        [Parameter()]
        [string]$Comment,

        # Scan
        [Parameter(Mandatory = $true, ParameterSetName = 'Scan')]
        [ValidateSet('Quick', 'Full')]
        [string]$Scan,

        # Isolate
        [Parameter(Mandatory = $true, ParameterSetName = 'Isolate')]
        [ValidateSet('Full', 'Selective')]
        [string]$Isolate,

        # Release From Isolation
        [Parameter(Mandatory = $true, ParameterSetName = 'ReleaseFromIsolation')]
        [switch]$ReleaseFromIsolation,

        # Restrict App Execution
        [Parameter(Mandatory = $true, ParameterSetName = 'RestrictAppExecution')]
        [switch]$RestrictAppExecution,

        # Remove App Execution Restriction
        [Parameter(Mandatory = $true, ParameterSetName = 'RemoveAppExecutionRestriction')]
        [switch]$RemoveAppExecutionRestriction,

        # Collect Investigation Package
        [Parameter(Mandatory = $true, ParameterSetName = 'CollectInvestigationPackage')]
        [switch]$CollectInvestigationPackage,

        # Collect Support Logs
        [Parameter(Mandatory = $true, ParameterSetName = 'CollectSupportLogs')]
        [switch]$CollectSupportLogs,

        # Troubleshoot
        [Parameter(Mandatory = $true, ParameterSetName = 'StartTroubleshoot')]
        [switch]$StartTroubleshoot,

        [Parameter(ParameterSetName = 'StartTroubleshoot')]
        [ValidateRange(1, 12)]
        [int]$TroubleshootDurationHours = 4,

        [Parameter(Mandatory = $true, ParameterSetName = 'StopTroubleshoot')]
        [switch]$StopTroubleshoot,

        # Set Tags
        [Parameter(Mandatory = $true, ParameterSetName = 'SetTags')]
        [string[]]$SetTags,

        # Set Asset Value
        [Parameter(Mandatory = $true, ParameterSetName = 'SetAssetValue')]
        [ValidateSet('Low', 'Normal', 'High')]
        [string]$SetAssetValue,

        # Set Criticality Level
        [Parameter(Mandatory = $true, ParameterSetName = 'SetCriticalityLevel')]
        [ValidateSet('VeryHigh', 'High', 'Medium', 'Low', 'Reset')]
        [string]$SetCriticalityLevel,

        # Set Exclusion State
        [Parameter(Mandatory = $true, ParameterSetName = 'SetExclusionState')]
        [ValidateSet('Excluded', 'Included')]
        [string]$SetExclusionState,

        [Parameter(ParameterSetName = 'SetExclusionState')]
        [string]$Justification,

        [Parameter(ParameterSetName = 'SetExclusionState')]
        [string]$Notes,

        # Force Sync
        [Parameter(Mandatory = $true, ParameterSetName = 'ForceSync')]
        [switch]$ForceSync,

        # Start Investigation
        [Parameter(Mandatory = $true, ParameterSetName = 'StartInvestigation')]
        [switch]$StartInvestigation,

        # Live Response
        [Parameter(Mandatory = $true, ParameterSetName = 'LiveResponse')]
        [switch]$LiveResponse
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Scan' {
                $device = Get-XdrEndpointDevice -DeviceId $DeviceId
                $commentText = if ($Comment) { $Comment } else { "$Scan Scan - Performed by $env:USERNAME via XDRInternals" }
                $body = @{
                    MachineId          = $DeviceId
                    RequestorComment   = $commentText
                    OsPlatform         = $device.OsPlatform
                    SenseClientVersion = $device.SenseClientVersion
                    Params             = @{ ScanType = $Scan }
                    Type               = 'ScanRequest'
                } | ConvertTo-Json -Depth 10

                if ($PSCmdlet.ShouldProcess("Device $($device.ComputerDnsName) ($DeviceId)", "$Scan Scan")) {
                    try {
                        $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/create"
                        Write-Verbose "Submitting $Scan scan for device $DeviceId"
                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                        $result.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceActionResult')
                        return $result
                    } catch {
                        $errorDetail = Get-XdrParsedErrorDetail -ErrorRecord $_
                        if ($errorDetail.error.code -eq 'ActiveRequestAlreadyExists' -or $errorDetail.Message -match 'pending|already|conflict|concurrent') {
                            Write-Error "A scan is already pending or running on this device. Wait for it to complete or cancel it first. API: $(if ($null -ne $errorDetail.error.message) { $errorDetail.error.message } else { $errorDetail.Message })"
                        } else {
                            Write-Error "Failed to submit $Scan scan: $_"
                        }
                    }
                }
            }

            'Isolate' {
                $device = Get-XdrEndpointDevice -DeviceId $DeviceId
                $commentText = if ($Comment) { $Comment } else { "Isolate device ($Isolate) - Performed by $env:USERNAME via XDRInternals" }
                $body = @{
                    MachineId          = $DeviceId
                    RequestorComment   = $commentText
                    OsPlatform         = $device.OsPlatform
                    SenseClientVersion = $device.SenseClientVersion
                    Type               = 'IsolationRequest'
                    IsolationType      = $Isolate
                    Action             = 'Isolate'
                } | ConvertTo-Json -Depth 10

                if ($PSCmdlet.ShouldProcess("Device $($device.ComputerDnsName) ($DeviceId)", "$Isolate Isolation")) {
                    try {
                        $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/create"
                        Write-Verbose "Submitting $Isolate isolation for device $DeviceId"
                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                        $result.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceActionResult')
                        return $result
                    } catch {
                        $errorDetail = Get-XdrParsedErrorDetail -ErrorRecord $_
                        if ($errorDetail.error.code -eq 'ActiveRequestAlreadyExists' -or $errorDetail.Message -match 'already isolated|pending isolation') {
                            Write-Error "Device is already isolated or has a pending isolation request. Release isolation first with -ReleaseFromIsolation. API: $(if ($null -ne $errorDetail.error.message) { $errorDetail.error.message } else { $errorDetail.Message })"
                        } else {
                            Write-Error "Failed to isolate device: $_"
                        }
                    }
                }
            }

            'ReleaseFromIsolation' {
                $device = Get-XdrEndpointDevice -DeviceId $DeviceId
                $commentText = if ($Comment) { $Comment } else { "Release from isolation - Performed by $env:USERNAME via XDRInternals" }
                $body = @{
                    MachineId          = $DeviceId
                    RequestorComment   = $commentText
                    OsPlatform         = $device.OsPlatform
                    SenseClientVersion = $device.SenseClientVersion
                    Type               = 'IsolationRequest'
                    Action             = 'Unisolate'
                } | ConvertTo-Json -Depth 10

                if ($PSCmdlet.ShouldProcess("Device $($device.ComputerDnsName) ($DeviceId)", "Release from isolation")) {
                    try {
                        $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/create"
                        Write-Verbose "Releasing device $DeviceId from isolation"
                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                        $result.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceActionResult')
                        return $result
                    } catch {
                        $errorDetail = Get-XdrParsedErrorDetail -ErrorRecord $_
                        if ($errorDetail.error.code -eq 'ActiveRequestAlreadyExists' -or $errorDetail.Message -match 'not isolated|not in isolation') {
                            Write-Error "Device is not currently isolated. API: $($errorDetail.Message)"
                        } else {
                            Write-Error "Failed to release isolation: $_"
                        }
                    }
                }
            }

            'RestrictAppExecution' {
                $device = Get-XdrEndpointDevice -DeviceId $DeviceId
                $commentText = if ($Comment) { $Comment } else { "Restrict app execution - Performed by $env:USERNAME via XDRInternals" }
                $body = @{
                    MachineId          = $DeviceId
                    RequestorComment   = $commentText
                    OsPlatform         = $device.OsPlatform
                    SenseClientVersion = $device.SenseClientVersion
                    ClientVersion      = $device.SenseClientVersion
                    PolicyType         = 'Restrict'
                    Type               = 'RestrictExecutionRequest'
                } | ConvertTo-Json -Depth 10

                if ($PSCmdlet.ShouldProcess("Device $($device.ComputerDnsName) ($DeviceId)", "Restrict app execution")) {
                    try {
                        $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/create"
                        Write-Verbose "Restricting app execution on device $DeviceId"
                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                        $result.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceActionResult')
                        return $result
                    } catch {
                        $errorDetail = Get-XdrParsedErrorDetail -ErrorRecord $_
                        if ($errorDetail.error.code -eq 'ActiveRequestAlreadyExists' -or $errorDetail.Message -match 'already restricted|pending') {
                            Write-Error "App execution restriction is already active or pending. Remove restriction first with -RemoveAppExecutionRestriction. API: $($errorDetail.Message)"
                        } else {
                            Write-Error "Failed to restrict app execution: $_"
                        }
                    }
                }
            }

            'RemoveAppExecutionRestriction' {
                $device = Get-XdrEndpointDevice -DeviceId $DeviceId
                $commentText = if ($Comment) { $Comment } else { "Remove app restriction - Performed by $env:USERNAME via XDRInternals" }
                $body = @{
                    MachineId          = $DeviceId
                    RequestorComment   = $commentText
                    OsPlatform         = $device.OsPlatform
                    SenseClientVersion = $device.SenseClientVersion
                    ClientVersion      = $device.SenseClientVersion
                    PolicyType         = 'Unrestrict'
                    Type               = 'RestrictExecutionRequest'
                } | ConvertTo-Json -Depth 10

                if ($PSCmdlet.ShouldProcess("Device $($device.ComputerDnsName) ($DeviceId)", "Remove app execution restriction")) {
                    try {
                        $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/create"
                        Write-Verbose "Removing app restriction on device $DeviceId"
                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                        $result.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceActionResult')
                        return $result
                    } catch {
                        $errorDetail = Get-XdrParsedErrorDetail -ErrorRecord $_
                        if ($errorDetail.error.code -eq 'ActiveRequestAlreadyExists' -or $errorDetail.Message -match 'not restricted|no restriction') {
                            Write-Error "App execution is not currently restricted. API: $($errorDetail.Message)"
                        } else {
                            Write-Error "Failed to remove app restriction: $_"
                        }
                    }
                }
            }

            'CollectInvestigationPackage' {
                $device = Get-XdrEndpointDevice -DeviceId $DeviceId
                $commentText = if ($Comment) { $Comment } else { "Collect investigation package - Performed by $env:USERNAME via XDRInternals" }
                $body = @{
                    MachineId          = $DeviceId
                    RequestorComment   = $commentText
                    OsPlatform         = $device.OsPlatform
                    SenseClientVersion = $device.SenseClientVersion
                    Type               = 'ForensicsRequest'
                } | ConvertTo-Json -Depth 10

                if ($PSCmdlet.ShouldProcess("Device $($device.ComputerDnsName) ($DeviceId)", "Collect investigation package")) {
                    try {
                        $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/create"
                        Write-Verbose "Collecting investigation package from device $DeviceId"
                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                        $result.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceActionResult')
                        return $result
                    } catch {
                        $errorDetail = Get-XdrParsedErrorDetail -ErrorRecord $_
                        if ($errorDetail.error.code -eq 'ActiveRequestAlreadyExists') {
                            Write-Error "An investigation package collection is already in progress on this device. Wait for it to complete first. API: $($errorDetail.error.message)"
                        } else {
                            Write-Error "Failed to collect investigation package: $_"
                        }
                    }
                }
            }

            'CollectSupportLogs' {
                $device = Get-XdrEndpointDevice -DeviceId $DeviceId
                $commentText = if ($Comment) { $Comment } else { "Collect support logs - Performed by $env:USERNAME via XDRInternals" }
                $body = @{
                    MachineId          = $DeviceId
                    RequestorComment   = $commentText
                    OsPlatform         = $device.OsPlatform
                    SenseClientVersion = $device.SenseClientVersion
                    Type               = 'LogsCollectionRequest'
                } | ConvertTo-Json -Depth 10

                if ($PSCmdlet.ShouldProcess("Device $($device.ComputerDnsName) ($DeviceId)", "Collect support logs")) {
                    try {
                        $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/create"
                        Write-Verbose "Collecting support logs from device $DeviceId"
                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                        $result.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceActionResult')
                        return $result
                    } catch {
                        $errorDetail = Get-XdrParsedErrorDetail -ErrorRecord $_
                        if ($errorDetail.error.code -eq 'ActiveRequestAlreadyExists') {
                            Write-Error "A support log collection is already in progress on this device. Wait for it to complete first. API: $($errorDetail.error.message)"
                        } else {
                            Write-Error "Failed to collect support logs: $_"
                        }
                    }
                }
            }

            'StartTroubleshoot' {
                $device = Get-XdrEndpointDevice -DeviceId $DeviceId
                $commentText = if ($Comment) { $Comment } else { "Start troubleshoot mode - Performed by $env:USERNAME via XDRInternals" }
                $now = (Get-Date).ToUniversalTime()
                $expiration = $now.AddHours($TroubleshootDurationHours)
                $body = @{
                    MachineId                         = $DeviceId
                    RequestorComment                  = $commentText
                    Type                              = 'TroubleshootRequest'
                    TroubleshootState                 = 1
                    TroubleshootExpirationDateTimeUtc = $expiration.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                    TroubleshootStartDateTimeUtc      = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                    ParamsJsonFormatVersion           = 1
                    RequestSource                     = 2
                    OsPlatform                        = $device.OsPlatform
                    SenseClientVersion                = $device.SenseClientVersion
                } | ConvertTo-Json -Depth 10

                if ($PSCmdlet.ShouldProcess("Device $($device.ComputerDnsName) ($DeviceId)", "Start troubleshoot mode ($TroubleshootDurationHours hours)")) {
                    try {
                        $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/create"
                        Write-Verbose "Starting troubleshoot mode on device $DeviceId for $TroubleshootDurationHours hours"
                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                        $result.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceActionResult')
                        return $result
                    } catch {
                        $errorDetail = Get-XdrParsedErrorDetail -ErrorRecord $_
                        if ($errorDetail.error.code -eq 'ActiveRequestAlreadyExists' -or $errorDetail.Message -match 'already|active|enabled') {
                            Write-Error "Troubleshoot mode is already active. Stop it first with -StopTroubleshoot. API: $(if ($null -ne $errorDetail.error.message) { $errorDetail.error.message } else { $errorDetail.Message })"
                        } else {
                            Write-Error "Failed to start troubleshoot mode: $_"
                        }
                    }
                }
            }

            'StopTroubleshoot' {
                $device = Get-XdrEndpointDevice -DeviceId $DeviceId
                $commentText = if ($Comment) { $Comment } else { "Stop troubleshoot mode - Performed by $env:USERNAME via XDRInternals" }
                $body = @{
                    MachineId                         = $DeviceId
                    RequestorComment                  = $commentText
                    Type                              = 'TroubleshootRequest'
                    TroubleshootState                 = 0
                    TroubleshootExpirationDateTimeUtc = (Get-Date).ToUniversalTime().AddMinutes(5).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                    ParamsJsonFormatVersion           = 1
                    RequestSource                     = 2
                    OsPlatform                        = $device.OsPlatform
                    SenseClientVersion                = $device.SenseClientVersion
                } | ConvertTo-Json -Depth 10

                if ($PSCmdlet.ShouldProcess("Device $($device.ComputerDnsName) ($DeviceId)", "Stop troubleshoot mode")) {
                    try {
                        $Uri = "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/requests/create"
                        Write-Verbose "Stopping troubleshoot mode on device $DeviceId"
                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
                        $result.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceActionResult')
                        return $result
                    } catch {
                        $errorDetail = Get-XdrParsedErrorDetail -ErrorRecord $_
                        if ($errorDetail.error.code -eq 'ActiveRequestAlreadyExists' -or $errorDetail.Message -match 'not active|not enabled') {
                            Write-Error "Troubleshoot mode is not currently active on this device. API: $(if ($null -ne $errorDetail.error.message) { $errorDetail.error.message } else { $errorDetail.Message })"
                        } else {
                            Write-Error "Failed to stop troubleshoot mode: $_"
                        }
                    }
                }
            }

            'SetTags' {
                Set-XdrEndpointDeviceTag -DeviceId $DeviceId -Tags $SetTags
            }

            'SetAssetValue' {
                Set-XdrEndpointDeviceAssetValue -DeviceId $DeviceId -AssetValue $SetAssetValue
            }

            'SetCriticalityLevel' {
                Set-XdrEndpointDeviceCriticalityLevel -DeviceId $DeviceId -CriticalityLevel $SetCriticalityLevel
            }

            'SetExclusionState' {
                $params = @{
                    DeviceId       = $DeviceId
                    ExclusionState = $SetExclusionState
                }
                if ($Justification) { $params['Justification'] = $Justification }
                if ($Notes) { $params['Notes'] = $Notes }
                Set-XdrEndpointDeviceExclusionState @params
            }

            'ForceSync' {
                $params = @{ DeviceId = $DeviceId }
                if ($Comment) { $params['Comment'] = $Comment }
                Invoke-XdrEndpointDevicePolicySync @params
            }

            'StartInvestigation' {
                Invoke-XdrEndpointDeviceAutomatedInvestigation -DeviceId $DeviceId
            }

            'LiveResponse' {
                Connect-XdrEndpointDeviceLiveResponse -DeviceId $DeviceId
            }
        }
    }

    end {
    }
}
