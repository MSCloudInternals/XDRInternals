function Invoke-XdrEndpointDeviceLiveResponseCommand {
    <#
    .SYNOPSIS
        Sends a command to an active Live Response session in Microsoft Defender XDR.

    .DESCRIPTION
        Submits a command to an active Live Response session and polls for the result.
        Parses the raw command line to extract the command definition ID and parameters,
        then sends the command via the Live Response API and waits for completion.

        Supports the full Live Response command syntax including:
        - Positional parameters mapped by order from the command definition
        - Named parameters using -paramName value syntax (e.g. -output json, -name notepad.exe)
        - Boolean flags using -flagName syntax (e.g. -full_path, -upload, -overwrite, -keep)
        - Alias resolution (ls -> dir, process -> processes, download -> getfile, etc.)

        This cmdlet can be used programmatically or is called automatically by
        Connect-XdrEndpointDeviceLiveResponse during interactive sessions.

    .PARAMETER SessionId
        The Live Response session ID (starts with CLR prefix).

    .PARAMETER Command
        The raw command line to execute (e.g., "dir /Applications", "processes", "getfile /etc/hosts").
        Supports all Live Response command aliases (ls, process, download, etc.).
        Values containing spaces must be quoted: getfile "/Applications/Utilities/Activity Monitor.app/Contents/Info.plist"

    .PARAMETER CurrentDirectory
        The current working directory on the remote device. Defaults to "C:\" for Windows sessions.
        For macOS and Linux sessions, use '/' or the session's reported current directory.

    .PARAMETER BackgroundMode
        Run the command in background mode if supported.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for command completion. Defaults to 300 seconds (5 minutes).
        Automatically extended to 600s for analyze commands.

    .PARAMETER PollIntervalSeconds
        How often to check for command completion. Defaults to 2 seconds.

    .PARAMETER CommandDefinitions
        Array of command definition objects from the Live Response API's get_command_definitions endpoint.
        Used to resolve aliases and correctly classify -name tokens as flags or named parameters.
        When not provided, falls back to heuristic parsing with 'path' as the default param_id.

    .PARAMETER DeviceName
        Optional device name to stamp onto the returned command object.

    .PARAMETER DeviceId
        Optional device ID to stamp onto the returned command object.

    .PARAMETER ExpandTableOutput
        When set, emits PowerShell-native row objects for table outputs and stamps each row
        with Timestamp, DeviceName, DeviceId, command, and status metadata.

    .PARAMETER IncludeCommandResult
        When used with -ExpandTableOutput, also emits the original command result object
        before the flattened table rows.

    .PARAMETER RawCommandResult
        Returns the original command result object without default structured table expansion.
        Useful for callers such as the interactive Live Response shell that need the raw
        outputs, context, and error collections from the API response.

    .EXAMPLE
        Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb" -Command "processes"
        Lists running processes on the remote device.

    .EXAMPLE
        Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb" -Command "dir /Applications" -CurrentDirectory "/"
        Lists the contents of /Applications on a macOS device.

    .EXAMPLE
        Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb" -Command "dir -full_path"
        Lists all files with full paths. The -full_path flag is correctly sent in the flags[] array.

    .EXAMPLE
        Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb" -Command "process -name launchd"
        Filters processes by name using the 'process' alias and a named -name parameter on macOS.

    .EXAMPLE
        Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb" -Command "getfile /etc/hosts" -TimeoutSeconds 120
        Downloads a file from a macOS device with a 2-minute timeout.

    .EXAMPLE
        Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb" -Command "ls"
        Lists files using the 'ls' alias for 'dir'. Alias is preserved in raw_command_line.

    .EXAMPLE
        $sessions | Invoke-XdrEndpointDeviceLiveResponseCommand -Command "processes" -ExpandTableOutput
        Returns one PowerShell object per process row, stamped with device and execution metadata.

    .EXAMPLE
        $sessions | Invoke-XdrEndpointDeviceLiveResponseCommand -Command "processes" -ExpandTableOutput -IncludeCommandResult
        Returns the original command result object followed by flattened process rows.

    .EXAMPLE
        Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb" -Command "drivers" -RawCommandResult
        Returns the original command result object without expanding structured table rows.

    .NOTES
        macOS validation baseline: February 24, 2026.

        Use POSIX-style paths for macOS sessions (for example: /, /Applications, /etc/hosts, /tmp).

        Some Live Response commands are platform-restricted or tenant-policy restricted and can return
        errors such as "Not allowed to run this command". These responses should be recorded as
        capability limitations instead of parser failures.

    .OUTPUTS
        PSCustomObject
        Returns the command result object including output, status, context, and errors.
        With -ExpandTableOutput, returns flattened table row objects when table outputs are present.
    #>
    [OutputType([PSCustomObject])]
    [OutputType([PSCustomObject[]])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Pipeline-bound parameters are buffered for batched execution.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are consumed inside a deferred worker scriptblock for batch execution.')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$SessionId,

        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$CurrentDirectory = 'C:\',

        [Parameter()]
        [switch]$BackgroundMode,

        [Parameter()]
        [int]$TimeoutSeconds = 300,

        [Parameter()]
        [int]$PollIntervalSeconds = 2,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [array]$CommandDefinitions

        , [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$DeviceName

        , [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$DeviceId

        , [Parameter()]
        [switch]$ExpandTableOutput

        , [Parameter()]
        [switch]$IncludeCommandResult

        , [Parameter()]
        [switch]$RawCommandResult
    )

    begin {
        Update-XdrConnectionSettings

        function Get-XdrLiveResponseStatusText {
            param(
                [Parameter(Mandatory = $false)]
                [object]$Status
            )

            switch ($Status) {
                0 { 'Pending' }
                1 { 'Completed' }
                2 { 'Failed' }
                3 { 'Cancelled' }
                4 { 'Expired' }
                5 { 'Rejected' }
                6 { 'Interrupted' }
                7 { 'Created' }
                130 { 'Downloading' }
                $null { '' }
                default { "Status $Status" }
            }
        }

        function Get-XdrLiveResponseCommandDefinitionList {
            param(
                [Parameter(Mandatory = $false)]
                [object]$CommandDefinitions
            )

            if ($null -eq $CommandDefinitions) {
                return @()
            }

            if ($CommandDefinitions -is [System.Array] -and $CommandDefinitions.Count -eq 1) {
                $firstEntry = $CommandDefinitions[0]
                if ($firstEntry -is [System.Array]) {
                    return @($firstEntry)
                }
            }

            @($CommandDefinitions)
        }

        function Add-XdrLiveResponseCommandContext {
            param(
                [Parameter(Mandatory = $true)]
                [object]$CommandResult,

                [Parameter(Mandatory = $true)]
                [object]$Request
            )

            $timestamp = $null
            foreach ($candidateTimestamp in @($CommandResult.completed_on, $CommandResult.created_on, $CommandResult.created_time, $CommandResult.started_on)) {
                if ([string]::IsNullOrWhiteSpace("$candidateTimestamp")) {
                    continue
                }

                try {
                    $timestamp = [datetime]$candidateTimestamp
                } catch {
                    $timestamp = $candidateTimestamp
                }
                break
            }

            Add-Member -InputObject $CommandResult -NotePropertyName 'Timestamp' -NotePropertyValue $timestamp -Force
            Add-Member -InputObject $CommandResult -NotePropertyName 'DeviceName' -NotePropertyValue $Request.DeviceName -Force
            Add-Member -InputObject $CommandResult -NotePropertyName 'DeviceId' -NotePropertyValue $Request.DeviceId -Force
            $statusValue = if ($CommandResult.PSObject.Properties['status']) { $CommandResult.status } elseif ($CommandResult.PSObject.Properties['Status']) { $CommandResult.Status } else { $null }
            $sessionIdentifier = if ($CommandResult.PSObject.Properties['session_id']) { $CommandResult.session_id } elseif ($CommandResult.PSObject.Properties['SessionId']) { $CommandResult.SessionId } else { $Request.SessionId }
            $commandText = if ($CommandResult.PSObject.Properties['raw_command_line']) { $CommandResult.raw_command_line } else { $Request.Command }
            $durationValue = if ($CommandResult.PSObject.Properties['duration_seconds']) { $CommandResult.duration_seconds } elseif ($CommandResult.PSObject.Properties['DurationSeconds']) { $CommandResult.DurationSeconds } else { $null }

            Add-Member -InputObject $CommandResult -NotePropertyName 'ShortDeviceId' -NotePropertyValue $(if ([string]::IsNullOrWhiteSpace($Request.DeviceId)) { $null } elseif ($Request.DeviceId.Length -le 12) { $Request.DeviceId } else { '{0}...' -f $Request.DeviceId.Substring(0, 12) }) -Force
            Add-Member -InputObject $CommandResult -NotePropertyName 'StatusText' -NotePropertyValue (Get-XdrLiveResponseStatusText -Status $statusValue) -Force
            Add-Member -InputObject $CommandResult -NotePropertyName 'SessionId' -NotePropertyValue $sessionIdentifier -Force
            Add-Member -InputObject $CommandResult -NotePropertyName 'Command' -NotePropertyValue $commandText -Force
            Add-Member -InputObject $CommandResult -NotePropertyName 'DurationSeconds' -NotePropertyValue $durationValue -Force

            if ($CommandResult.PSObject.TypeNames[0] -ne 'XdrEndpointDeviceLiveResponseCommand') {
                $CommandResult.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
            }

            $CommandResult
        }

        function Get-XdrLiveResponseCommandId {
            param(
                [Parameter(Mandatory = $true)]
                [object]$CommandResult
            )

            if ($CommandResult.PSObject.Properties['command_definition_id'] -and -not [string]::IsNullOrWhiteSpace("$($CommandResult.command_definition_id)")) {
                return "$($CommandResult.command_definition_id)".ToLower()
            }

            $commandText = if ($CommandResult.PSObject.Properties['raw_command_line']) { "$($CommandResult.raw_command_line)" } elseif ($CommandResult.PSObject.Properties['Command']) { "$($CommandResult.Command)" } else { '' }
            if ([string]::IsNullOrWhiteSpace($commandText)) {
                return ''
            }

            @($commandText.Trim().Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries) | Select-Object -First 1)[0].ToLower()
        }

        function Test-XdrLiveResponseStructuredDefaultOutput {
            param(
                [Parameter(Mandatory = $true)]
                [string]$CommandId
            )

            $CommandId -in @(
                'processes',
                'services',
                'drivers',
                'connections',
                'scheduledtasks',
                'startupfolders',
                'dir',
                'persistence'
            )
        }

        function Get-XdrLiveResponseRowBase {
            param(
                [Parameter(Mandatory = $true)]
                [object]$CommandResult,

                [Parameter(Mandatory = $true)]
                [int]$OutputIndex
            )

            [ordered]@{
                Timestamp       = $CommandResult.Timestamp
                DeviceName      = $CommandResult.DeviceName
                DeviceId        = $CommandResult.DeviceId
                ShortDeviceId   = $CommandResult.ShortDeviceId
                Command         = $CommandResult.Command
                CommandId       = (Get-XdrLiveResponseCommandId -CommandResult $CommandResult)
                Status          = $CommandResult.status
                StatusText      = $CommandResult.StatusText
                DurationSeconds = $CommandResult.DurationSeconds
                SessionId       = $CommandResult.SessionId
                OutputIndex     = $OutputIndex
            }
        }

        function ConvertTo-XdrLiveResponseRowObject {
            param(
                [Parameter(Mandatory = $true)]
                [hashtable]$BaseProperties,

                [Parameter(Mandatory = $true)]
                [hashtable]$RowProperties,

                [Parameter(Mandatory = $true)]
                [string]$PrimaryTypeName
            )

            $rowData = [ordered]@{}
            foreach ($key in $BaseProperties.Keys) {
                $rowData[$key] = $BaseProperties[$key]
            }

            foreach ($key in $RowProperties.Keys) {
                $propertyName = if ($rowData.Contains($key)) { "Table_$key" } else { $key }
                $rowData[$propertyName] = $RowProperties[$key]
            }

            $rowObject = [PSCustomObject]$rowData
            $rowObject.PSObject.TypeNames.Insert(0, $PrimaryTypeName)
            if ($rowObject.PSObject.TypeNames[1] -ne 'XdrEndpointDeviceLiveResponseTableRow') {
                $rowObject.PSObject.TypeNames.Insert(1, 'XdrEndpointDeviceLiveResponseTableRow')
            }
            $rowObject
        }

        function ConvertTo-XdrLiveResponsePersistenceRow {
            param(
                [Parameter(Mandatory = $true)]
                [object]$CommandResult,

                [Parameter(Mandatory = $true)]
                [object]$OutputItem,

                [Parameter(Mandatory = $true)]
                [int]$OutputIndex
            )

            $baseProperties = Get-XdrLiveResponseRowBase -CommandResult $CommandResult -OutputIndex $OutputIndex
            $flattenedRows = [System.Collections.Generic.List[object]]::new()
            $autoruns = $OutputItem.data.autoruns
            if ($null -eq $autoruns) {
                return @($flattenedRows)
            }

            foreach ($categoryProperty in $autoruns.PSObject.Properties) {
                $categoryName = $categoryProperty.Name
                foreach ($entry in @($categoryProperty.Value)) {
                    switch ($categoryName) {
                        'startup_folders' {
                            $flattenedRows.Add((ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponsePersistenceRow' -RowProperties ([ordered]@{
                                            Category    = 'StartupFolder'
                                            Name        = $entry.filePath
                                            Path        = $entry.filePath
                                            Target      = $entry.executablePath
                                            EntryType   = $entry.category
                                            IsEnabled   = $null
                                            ValueName   = $null
                                            ValueType   = $null
                                            Value       = $null
                                            CommandLine = $null
                                            Principal   = $null
                                        })))
                        }
                        'registry' {
                            $flattenedRows.Add((ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponsePersistenceRow' -RowProperties ([ordered]@{
                                            Category    = 'Registry'
                                            Name        = $entry.display_name
                                            Path        = $entry.reg_path
                                            Target      = $null
                                            EntryType   = $entry.value_name
                                            IsEnabled   = $null
                                            ValueName   = $entry.value_name
                                            ValueType   = $entry.value_type
                                            Value       = $entry.value
                                            CommandLine = $null
                                            Principal   = $null
                                        })))
                        }
                        'schedule_tasks' {
                            $execAction = @($entry.task.actions.exec | Select-Object -First 1)[0]
                            $principal = $entry.task.principals.principal
                            $flattenedRows.Add((ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponsePersistenceRow' -RowProperties ([ordered]@{
                                            Category    = 'ScheduledTask'
                                            Name        = $entry.id
                                            Path        = $entry.task.registrationInfo.uri
                                            Target      = $execAction.command
                                            EntryType   = 'Task'
                                            IsEnabled   = $entry.is_enabled
                                            ValueName   = $null
                                            ValueType   = $null
                                            Value       = $null
                                            CommandLine = $execAction.arguments
                                            Principal   = $(if ($principal.userId) { $principal.userId } else { $principal.id })
                                        })))
                        }
                    }
                }
            }

            @($flattenedRows)
        }

        function ConvertTo-XdrLiveResponseTableRow {
            param(
                [Parameter(Mandatory = $true)]
                [object]$CommandResult
            )

            $flattenedRows = [System.Collections.Generic.List[object]]::new()
            $outputIndex = 0
            $commandId = Get-XdrLiveResponseCommandId -CommandResult $CommandResult

            foreach ($outputItem in @($CommandResult.outputs)) {
                if ($commandId -eq 'persistence' -and $outputItem.data_type -eq 'object' -and $null -ne $outputItem.data) {
                    foreach ($row in @(ConvertTo-XdrLiveResponsePersistenceRow -CommandResult $CommandResult -OutputItem $outputItem -OutputIndex $outputIndex)) {
                        $flattenedRows.Add($row)
                    }
                    $outputIndex++
                    continue
                }

                if ($outputItem.data_type -ne 'table' -or $null -eq $outputItem.data) {
                    $outputIndex++
                    continue
                }

                foreach ($row in @($outputItem.data)) {
                    $baseProperties = Get-XdrLiveResponseRowBase -CommandResult $CommandResult -OutputIndex $outputIndex
                    switch ($commandId) {
                        'processes' {
                            $rowObject = ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponseProcessRow' -RowProperties ([ordered]@{
                                    Name             = $row.name
                                    Pid              = $row.pid
                                    ParentId         = $row.parent_id
                                    UserName         = $row.user_name
                                    ProcessStatus    = $row.status
                                    CreatedTime      = $row.creation_time
                                    CpuCyclesK       = $row.'cpu_cycles (K)'
                                    MemoryKB         = $row.'memory (K)'
                                    WorkingSetBytes  = $row.memory_usage.working_set
                                    PrivateBytes     = $row.memory_usage.private_bytes
                                    ProcessSessionId = $row.session_id
                                })
                        }
                        'services' {
                            $rowObject = ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponseServiceRow' -RowProperties ([ordered]@{
                                    ServiceName  = $row.service_name
                                    DisplayName  = $row.display_name
                                    CurrentState = $row.current_state
                                    StartType    = $row.start_type
                                    ServiceType  = $row.service_type
                                    StartName    = $row.service_start_name
                                    BinaryPath   = $row.binary_path
                                    Path         = $row.path
                                    Arguments    = $row.args
                                    ProcessId    = $row.process_id
                                    Dependencies = @($row.dependencies) -join ', '
                                })
                        }
                        'drivers' {
                            $rowObject = ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponseDriverRow' -RowProperties ([ordered]@{
                                    DriverName   = $row.driver_name
                                    ServiceName  = $row.service_name
                                    ServiceState = $row.service_state
                                    ServiceType  = $row.service_type
                                    DriverLoaded = $row.driver_loaded
                                    Path         = $row.path
                                    Description  = $row.description
                                })
                        }
                        'connections' {
                            $rowObject = ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponseConnectionRow' -RowProperties ([ordered]@{
                                    ProcessName     = $row.name
                                    Pid             = $row.pid
                                    ConnectionState = $row.status_display
                                    LocalIp         = $row.local_ip
                                    LocalPort       = $row.local_port
                                    LocalEndpoint   = '{0}:{1}' -f $row.local_ip, $row.local_port
                                    RemoteIp        = $row.remote_ip
                                    RemotePort      = $row.remote_port
                                    RemoteEndpoint  = '{0}:{1}' -f $row.remote_ip, $row.remote_port
                                })
                        }
                        'scheduledtasks' {
                            $execAction = @($row.task.actions.exec | Select-Object -First 1)[0]
                            $principal = $row.task.principals.principal
                            $rowObject = ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponseScheduledTaskRow' -RowProperties ([ordered]@{
                                    TaskId     = $row.id
                                    IsEnabled  = $row.is_enabled
                                    Author     = $row.task.registrationInfo.author
                                    Principal  = $(if ($principal.userId) { $principal.userId } else { $principal.id })
                                    ActionType = $(if ($row.task.actions.exec) { 'Exec' } elseif ($row.task.actions.comHandler) { 'ComHandler' } else { $null })
                                    ActionPath = $execAction.command
                                    Arguments  = $execAction.arguments
                                    Context    = $row.task.actions.context
                                })
                        }
                        'startupfolders' {
                            $rowObject = ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponseStartupFolderRow' -RowProperties ([ordered]@{
                                    FilePath       = $row.filePath
                                    ExecutablePath = $row.executablePath
                                    Category       = $row.category
                                })
                        }
                        'dir' {
                            $rowObject = ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponseDirectoryRow' -RowProperties ([ordered]@{
                                    Path         = $row.path
                                    ItemType     = $(if ($row.isDirectory) { 'Directory' } else { 'File' })
                                    Size         = $row.size
                                    Created      = $row.created
                                    Modified     = $row.modified
                                    IsCompressed = $row.isCompressed
                                    Hidden       = $row.hidden
                                    ReadOnly     = $row.readOnly
                                })
                        }
                        default {
                            $rowData = [ordered]@{}
                            if ($row -is [System.Collections.IDictionary]) {
                                foreach ($key in $row.Keys) {
                                    $rowData["$key"] = $row[$key]
                                }
                            } elseif ($null -ne $row -and $row.PSObject.Properties.Count -gt 0) {
                                foreach ($property in $row.PSObject.Properties) {
                                    $rowData[$property.Name] = $property.Value
                                }
                            } else {
                                $rowData['Value'] = $row
                            }

                            $rowObject = ConvertTo-XdrLiveResponseRowObject -BaseProperties $baseProperties -PrimaryTypeName 'XdrEndpointDeviceLiveResponseTableRow' -RowProperties $rowData
                        }
                    }

                    $flattenedRows.Add($rowObject)
                }

                $outputIndex++
            }

            switch ($commandId) {
                'processes' { @($flattenedRows | Sort-Object DeviceName, @{ Expression = { if ($null -eq $_.MemoryKB) { -1 } else { [double]$_.MemoryKB } }; Descending = $true }, Name, Pid) }
                'services' { @($flattenedRows | Sort-Object DeviceName, DisplayName, ServiceName) }
                'drivers' { @($flattenedRows | Sort-Object DeviceName, DriverName, ServiceName) }
                'connections' { @($flattenedRows | Sort-Object DeviceName, ProcessName, LocalPort, RemotePort) }
                'scheduledtasks' { @($flattenedRows | Sort-Object DeviceName, TaskId) }
                'startupfolders' { @($flattenedRows | Sort-Object DeviceName, FilePath) }
                'dir' { @($flattenedRows | Sort-Object DeviceName, @{ Expression = { if ($_.ItemType -eq 'Directory') { 0 } else { 1 } } }, Path) }
                'persistence' { @($flattenedRows | Sort-Object DeviceName, Category, Name) }
                default { @($flattenedRows | Sort-Object DeviceName, OutputIndex) }
            }
        }

        function Write-XdrLiveResponseCommandOutput {
            param(
                [Parameter(Mandatory = $true)]
                [object]$CommandResult,

                [Parameter(Mandatory = $true)]
                [object]$Request
            )

            $commandResultWithContext = Add-XdrLiveResponseCommandContext -CommandResult $CommandResult -Request $Request
            $commandId = Get-XdrLiveResponseCommandId -CommandResult $commandResultWithContext
            $shouldExpand = -not $RawCommandResult.IsPresent -and ($ExpandTableOutput.IsPresent -or (Test-XdrLiveResponseStructuredDefaultOutput -CommandId $commandId))

            if (-not $shouldExpand) {
                $commandResultWithContext
                return
            }

            $expandedRows = @(ConvertTo-XdrLiveResponseTableRow -CommandResult $commandResultWithContext)

            if ($IncludeCommandResult) {
                $commandResultWithContext
            }

            if ($expandedRows.Count -gt 0) {
                foreach ($expandedRow in $expandedRows) {
                    $expandedRow
                }
                return
            }

            if (-not $IncludeCommandResult) {
                $commandResultWithContext
            }
        }

        $pendingRequests = [System.Collections.Generic.List[object]]::new()
        $invokeCommandScript = {
            param($Item, $SharedParameters)

            $sessionId = "$($Item.SessionId)"
            $commandLine = "$($Item.Command)"
            $currentDirectory = if ([string]::IsNullOrWhiteSpace("$($Item.CurrentDirectory)")) { 'C:\' } else { "$($Item.CurrentDirectory)" }
            $commandDefinitions = @(Get-XdrLiveResponseCommandDefinitionList -CommandDefinitions $Item.CommandDefinitions)
            $timeoutSeconds = [int]$Item.TimeoutSeconds
            $pollIntervalSeconds = [int]$Item.PollIntervalSeconds
            $backgroundMode = [bool]$Item.BackgroundMode

            $headers = $SharedParameters.HeadersData
            $webSession = $SharedParameters.WebSession
            if (-not $webSession) {
                $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
                foreach ($cookieInfo in $SharedParameters.CookieData) {
                    $cookie = [System.Net.Cookie]::new($cookieInfo.Name, $cookieInfo.Value, $cookieInfo.Path, $cookieInfo.Domain)
                    $webSession.Cookies.Add($cookie)
                }
            }

            $tokenList = [System.Collections.Generic.List[string]]::new()
            $tokenIsQuoted = [System.Collections.Generic.List[bool]]::new()
            $pos = 0
            $line = $commandLine.Trim()
            while ($pos -lt $line.Length) {
                while ($pos -lt $line.Length -and $line[$pos] -eq ' ') { $pos++ }
                if ($pos -ge $line.Length) { break }

                $tokenBuf = [System.Text.StringBuilder]::new()
                $wasQuoted = $false
                while ($pos -lt $line.Length -and $line[$pos] -ne ' ') {
                    $ch = $line[$pos]
                    if ($ch -eq '"' -or $ch -eq "'") {
                        $wasQuoted = $true
                        $quoteChar = $ch
                        $pos++
                        while ($pos -lt $line.Length -and $line[$pos] -ne $quoteChar) {
                            $null = $tokenBuf.Append($line[$pos])
                            $pos++
                        }
                        if ($pos -lt $line.Length) { $pos++ }
                    } else {
                        $null = $tokenBuf.Append($ch)
                        $pos++
                    }
                }

                if ($tokenBuf.Length -gt 0) {
                    $tokenList.Add($tokenBuf.ToString())
                    $tokenIsQuoted.Add($wasQuoted)
                }
            }

            if ($tokenList.Count -eq 0) {
                throw 'Empty command'
            }

            $rawFirstToken = $tokenList[0]
            $commandId = $rawFirstToken.ToLower()
            $cmdDef = $null

            if ($commandDefinitions.Count -gt 0) {
                $cmdDef = $commandDefinitions | Where-Object { $_.command_definition_id -eq $commandId } | Select-Object -First 1
                if (-not $cmdDef) {
                    foreach ($def in $commandDefinitions) {
                        if ($def.aliases) {
                            $aliasLower = @($def.aliases | ForEach-Object { "$_".ToLower() })
                            if ($commandId -in $aliasLower) {
                                $cid = $def.command_definition_id
                                $commandId = if ($cid -is [System.Collections.IEnumerable] -and $cid -isnot [string]) {
                                    "$($cid | Select-Object -First 1)"
                                } else {
                                    "$cid"
                                }
                                $cmdDef = $def
                                break
                            }
                        }
                    }
                }
            }

            $knownFlagIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $knownParamIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            if ($cmdDef) {
                if ($cmdDef.flags) {
                    foreach ($flag in $cmdDef.flags) {
                        $flagId = if ($flag -is [string]) { $flag } elseif ($null -ne $flag.flag_id) { $flag.flag_id } elseif ($null -ne $flag.id) { $flag.id } else { $flag.name }
                        if ($flagId) { $null = $knownFlagIds.Add($flagId) }
                    }
                }

                if ($cmdDef.params) {
                    foreach ($paramDef in $cmdDef.params) {
                        if ($paramDef.param_id) { $null = $knownParamIds.Add($paramDef.param_id) }
                    }
                }
            }

            $params = [System.Collections.Generic.List[hashtable]]::new()
            $flags = [System.Collections.Generic.List[string]]::new()
            $positional = [System.Collections.Generic.List[string]]::new()
            $namedParamSpecs = [System.Collections.Generic.List[hashtable]]::new()

            $i = 1
            while ($i -lt $tokenList.Count) {
                $token = $tokenList[$i]
                if ($token -match '^-(.+)$') {
                    $nameWithoutDash = $Matches[1].ToLower()
                    $nextIdx = $i + 1
                    $hasNext = $nextIdx -lt $tokenList.Count
                    $nextToken = if ($hasNext) { $tokenList[$nextIdx] } else { $null }
                    $nextIsFlag = $nextToken -and $nextToken -match '^-' -and -not $tokenIsQuoted[$nextIdx]

                    $isKnownFlag = $knownFlagIds.Contains($nameWithoutDash)
                    $isKnownParam = $knownParamIds.Contains($nameWithoutDash)

                    if ($isKnownFlag) {
                        $flags.Add($nameWithoutDash)
                        $i++
                    } elseif ($isKnownParam -and $hasNext -and -not $nextIsFlag) {
                        $params.Add(@{ param_id = $nameWithoutDash; value = $nextToken })
                        $namedParamSpecs.Add(@{ param_id = $nameWithoutDash; value = $nextToken })
                        $i += 2
                    } elseif (-not $isKnownFlag -and -not $isKnownParam -and $hasNext -and -not $nextIsFlag) {
                        $params.Add(@{ param_id = $nameWithoutDash; value = $nextToken })
                        $namedParamSpecs.Add(@{ param_id = $nameWithoutDash; value = $nextToken })
                        $i += 2
                    } else {
                        $flags.Add($nameWithoutDash)
                        $i++
                    }
                } else {
                    $positional.Add($token)
                    $i++
                }
            }

            if ($positional.Count -gt 0) {
                if ($cmdDef -and $cmdDef.params) {
                    $namedParamIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($namedParam in $namedParamSpecs) {
                        $null = $namedParamIds.Add($namedParam.param_id)
                    }

                    $remainingParamDefs = @($cmdDef.params | Where-Object {
                            $null -ne $_ -and $_.param_id -and -not $_.isHidden -and -not $namedParamIds.Contains($_.param_id)
                        })

                    for ($j = 0; $j -lt [Math]::Min($positional.Count, $remainingParamDefs.Count); $j++) {
                        $params.Add(@{ param_id = $remainingParamDefs[$j].param_id; value = $positional[$j] })
                    }
                } elseif ($positional.Count -eq 1) {
                    $params.Add(@{ param_id = 'path'; value = $positional[0] })
                }
            }

            $rawCommandLine = $commandLine.Trim()
            $needsRebuild = $false
            foreach ($paramSpec in $params) {
                if ($paramSpec.value -match '\s') {
                    $doubleQuotedValue = '"' + $paramSpec.value + '"'
                    $singleQuotedValue = "'$($paramSpec.value)'"
                    if (-not ($rawCommandLine -match [regex]::Escape($doubleQuotedValue)) -and
                        -not ($rawCommandLine -match [regex]::Escape($singleQuotedValue))) {
                        $needsRebuild = $true
                        break
                    }
                }
            }

            if ($needsRebuild) {
                $parts = [System.Collections.Generic.List[string]]::new()
                $parts.Add($rawFirstToken)
                foreach ($positionalValue in $positional) {
                    $quotedPositionalValue = if ($positionalValue -match '\s') { '"' + $positionalValue + '"' } else { $positionalValue }
                    $parts.Add($quotedPositionalValue)
                }
                foreach ($namedParam in $namedParamSpecs) {
                    $namedPart = if ($namedParam.value -match '\s') {
                        '-{0} "{1}"' -f $namedParam.param_id, $namedParam.value
                    } else {
                        '-{0} {1}' -f $namedParam.param_id, $namedParam.value
                    }
                    $parts.Add($namedPart)
                }
                foreach ($flag in $flags) {
                    $parts.Add("-$flag")
                }
                $rawCommandLine = $parts -join ' '
            }

            $effectiveTimeout = switch ($commandId) {
                'analyze' { [Math]::Max($timeoutSeconds, 600) }
                'findfile' { [Math]::Max($timeoutSeconds, 300) }
                default { $timeoutSeconds }
            }

            $body = @{
                session_id            = $sessionId
                command_definition_id = $commandId
                params                = @($params)
                flags                 = @($flags)
                raw_command_line      = $rawCommandLine
                current_directory     = $currentDirectory
                background_mode       = $backgroundMode
            } | ConvertTo-Json -Depth 10

            $createUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/create_command?session_id=$sessionId&useV3Api=true"
            $createResult = Invoke-RestMethod -Uri $createUri -Method Post -ContentType 'application/json' -Body $body -WebSession $webSession -Headers $headers

            $commandGuid = $createResult.command_id
            if (-not $commandGuid) {
                return $createResult
            }

            $pollUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/commands/${commandGuid}?session_id=$sessionId&useV2Api=false&useV3Api=true"
            $elapsed = 0
            $commandResult = $null

            while ($elapsed -lt $effectiveTimeout) {
                Start-Sleep -Seconds $pollIntervalSeconds
                $elapsed += $pollIntervalSeconds

                $commandResult = Invoke-RestMethod -Uri $pollUri -Method Get -ContentType 'application/json' -WebSession $webSession -Headers $headers
                if ($commandResult.completed_on) {
                    $commandResult.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
                    return $commandResult
                }
            }

            if ($commandResult) {
                $commandResult.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
                return $commandResult
            }
        }
    }

    process {
        $pendingRequests.Add([PSCustomObject]@{
                SessionId           = $SessionId
                Command             = $Command
                CurrentDirectory    = $CurrentDirectory
                DeviceName          = $DeviceName
                DeviceId            = $DeviceId
                BackgroundMode      = [bool]$BackgroundMode
                TimeoutSeconds      = $TimeoutSeconds
                PollIntervalSeconds = $PollIntervalSeconds
                CommandDefinitions  = $CommandDefinitions
            })
    }

    end {
        if ($pendingRequests.Count -eq 0) {
            return
        }

        if ($pendingRequests.Count -eq 1) {
            try {
                $singleResult = & $invokeCommandScript -Item $pendingRequests[0] -SharedParameters @{
                    WebSession  = $script:session
                    HeadersData = $script:headers
                }
                if ($singleResult) {
                    Write-XdrLiveResponseCommandOutput -CommandResult $singleResult -Request $pendingRequests[0]
                }
            } catch {
                Write-Error "Failed to execute Live Response command: $_"
            }
            return
        }

        $requestContext = Get-XdrRequestContextSnapshot
        $batchResults = Invoke-XdrRateLimitedBatch -Items $pendingRequests.ToArray() -OperationName 'Invoke-XdrEndpointDeviceLiveResponseCommand' -ItemScript $invokeCommandScript -SharedParameters @{
            BaseUrl     = $requestContext.BaseUrl
            CookieData  = $requestContext.CookieData
            HeadersData = $requestContext.HeadersData
        }

        foreach ($batchResult in @($batchResults | Sort-Object @{ Expression = { if ([string]::IsNullOrWhiteSpace($_.Item.DeviceName)) { '~' } else { $_.Item.DeviceName } } }, @{ Expression = { $_.Item.SessionId } })) {
            if ($batchResult.Success) {
                if ($batchResult.Result) {
                    Write-XdrLiveResponseCommandOutput -CommandResult $batchResult.Result -Request $batchResult.Item
                }
            } else {
                Write-Error "Failed to execute Live Response command for session '$($batchResult.Item.SessionId)': $($batchResult.ErrorText)"
            }
        }
    }
}
