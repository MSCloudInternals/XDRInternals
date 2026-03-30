function Connect-XdrEndpointDeviceLiveResponse {
    <#
    .SYNOPSIS
        Opens a Live Response session to an endpoint device in Microsoft Defender XDR.

    .DESCRIPTION
        Creates a Live Response session to the specified device. By default, the cmdlet
        provides an interactive command-line interface where you can type Live Response
        commands and see results.

        When -NonInteractive is specified, the cmdlet establishes the session, loads
        command definitions, and returns a session object without entering the prompt loop.

        Type 'disconnect' or 'exit' to close the session and return to PowerShell.
        Type 'help' to see available Live Response commands.

        Available Live Response commands include:
        analyze, cd, cls, connect, connections, dir, drivers, fg, fileinfo, findfile,
        getfile, help, jobs, library, log, persistence, prefetch, processes, putfile,
        registry, remediate, run, scheduledtasks, services, startupfolders, status,
        trace, undo

        Command aliases (e.g. ls, process, download) are supported and resolved automatically.
        Use 'help <command>' for detailed syntax and flags for a specific command.

    .PARAMETER DeviceId
        The device ID (SenseMachineId) of the target device.

    .PARAMETER DeviceName
        Optional device name used for progress display and to avoid an extra lookup when
        device metadata is already available from pipeline input.

    .PARAMETER LastSeen
        Optional last seen timestamp from pipeline input. When provided together with other
        device metadata, the cmdlet can reuse it during non-interactive session creation.

    .PARAMETER OsPlatform
        Optional operating system platform from pipeline input. Used to determine the initial
        working directory without requiring an additional device metadata lookup.

    .PARAMETER NonInteractive
        Connects to Live Response and returns a session object without starting the
        interactive prompt loop.

    .PARAMETER NoStatusTable
        Suppresses the live status table shown during multi-device non-interactive session
        creation. Returned session objects are unchanged.

    .EXAMPLE
        Connect-XdrEndpointDeviceLiveResponse -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2"
        Opens an interactive Live Response session to the specified device.

    .EXAMPLE
        $lr = Connect-XdrEndpointDeviceLiveResponse -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2" -NonInteractive
        Connects to the device and returns a session object for script-driven command execution.

    .EXAMPLE
        $devices | Connect-XdrEndpointDeviceLiveResponse -NonInteractive -NoStatusTable
        Connects to multiple devices without rendering the live status table.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAction -DeviceId "980dddb7036eae7e38d30dee7f11b51e573a6fc2" -LiveResponse
        Opens a Live Response session via the unified action cmdlet.

    .NOTES
        macOS validation baseline: February 24, 2026.

        Initial directory is OS-aware:
        - Windows devices start in C:\
        - macOS/Linux/Unix devices start in /

        NonInteractive mode returns a typed XdrEndpointDeviceLiveResponseSession object
        for automation workflows and test harnesses.

    .OUTPUTS
        PSCustomObject
        When -NonInteractive is used, returns an XdrEndpointDeviceLiveResponseSession object.
        In interactive mode, no output is returned.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameters required by PSReadLine key handler scriptblock signature')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40, 40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$DeviceId,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Alias('ComputerDnsName')]
        [string]$DeviceName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [object]$LastSeen,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]$OsPlatform,

        [Parameter()]
        [switch]$NonInteractive,

        [Parameter()]
        [switch]$NoStatusTable
    )

    begin {
        Update-XdrConnectionSettings

        $knownCommands = @(
            'analyze', 'cd', 'cls', 'connect', 'connections', 'dir', 'drivers',
            'fg', 'fileinfo', 'findfile', 'getfile', 'help', 'jobs', 'library', 'log',
            'persistence', 'prefetch', 'processes', 'putfile', 'registry',
            'remediate', 'run', 'scheduledtasks', 'services', 'startupfolders',
            'status', 'trace', 'undo'
        )

        $pendingDeviceIds = [System.Collections.Generic.List[object]]::new()
    }

    process {
        if ($NonInteractive) {
            $pendingDeviceIds.Add([PSCustomObject]@{
                    DeviceId   = $DeviceId
                    DeviceName = $DeviceName
                    LastSeen   = $LastSeen
                    OsPlatform = $OsPlatform
                })
            return
        }

        # Step 1: Get device details
        Write-Host "Connecting to device..." -ForegroundColor Cyan
        try {
            $device = Get-XdrEndpointDevice -DeviceId $DeviceId
        } catch {
            Write-Error "Failed to retrieve device details: $_"
            return
        }
        $deviceName = $device.ComputerDnsName
        $lastSeen = $device.LastSeen
        Write-Host "  Device: $deviceName ($DeviceId)" -ForegroundColor Gray
        Write-Host "  Last Seen: $lastSeen" -ForegroundColor Gray

        # Step 2: Create Live Response session
        Write-Host "Creating Live Response session..." -ForegroundColor Cyan
        $createBody = @{
            machine_id        = $DeviceId
            machine_last_seen = $lastSeen
        } | ConvertTo-Json -Depth 10

        try {
            $createUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/create_session?useV3Api=true&tenantIds=undefined"
            $sessionResponse = Invoke-RestMethod -Uri $createUri -Method Post -ContentType "application/json" -Body $createBody -WebSession $script:session -Headers $script:headers
        } catch {
            Write-Error "Failed to create Live Response session: $_"
            return
        }

        $sessionId = $sessionResponse.session_id
        if (-not $sessionId) {
            Write-Error "No session_id returned from create_session API"
            return
        }
        Write-Host "  Session ID: $sessionId" -ForegroundColor Gray

        # Step 3: Wait for session to connect by polling the auto-created command
        # The portal determines "connected" when the initial auto-created command completes,
        # NOT by checking session_status (which remains unchanged throughout the session lifecycle).
        # Flow: create_session → poll session once → fetch commands list → discover auto-created
        # command → poll that command until it completes → session is ready for user input.
        Write-Host "Waiting for session to connect..." -ForegroundColor Cyan
        $maxWait = 180
        $pollInterval = 1.5
        $elapsed = 0
        $connected = $false
        $failedStatuses = @('Failed', 'Expired', 'Closed', 4, 5, 6)

        # Initial session poll to verify session was created
        Start-Sleep -Seconds 1
        $elapsed += 1
        try {
            $sessionUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/sessions/${sessionId}?useV3Api=true"
            $sessionStatus = Invoke-RestMethod -Uri $sessionUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            $status = $sessionStatus.session_status
            if ($null -eq $status) { $status = $sessionStatus.status }
            Write-Verbose "Initial session status: $status"

            if ($status -in $failedStatuses) {
                Write-Error "Session failed to create. Status: $status"
                return
            }
        } catch {
            Write-Verbose "Initial session poll error: $_"
        }

        # Discover the auto-created command from the session's command list
        # The server creates an initial "connect" command when the session starts.
        # Polling this command until it completes is the signal that the session is connected.
        $autoCommandId = $null
        $commandsListUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/sessions/${sessionId}/commands/?session_id=${sessionId}&useV2Api=false&useV3Api=true"
        $sessionPollUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/sessions/${sessionId}?useV2Api=false&useV3Api=true"

        # Command status codes: 0=Pending/Created, 1=Completed, 2+=Failed/Cancelled
        # A command is "done" when status != 0 OR completed_on is non-null
        while ($elapsed -lt $maxWait -and -not $connected) {
            # Try to discover the auto-created command if we haven't yet
            if (-not $autoCommandId) {
                try {
                    $commandsList = @(Invoke-RestMethod -Uri $commandsListUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers)
                    if ($commandsList.Count -gt 0) {
                        $autoCmd = $commandsList[0]
                        $autoCommandId = $autoCmd.command_id
                        if (-not $autoCommandId) { $autoCommandId = $autoCmd.id }
                        Write-Verbose "Discovered auto-created command: $autoCommandId"

                        # Check if the command already completed in the list response.
                        # Status 1 = success; status 2+ = failed (e.g. existing session conflict).
                        # For failures fall through to the polling section which extracts error details.
                        if ($autoCmd.completed_on -or ($null -ne $autoCmd.status -and $autoCmd.status -ne 0)) {
                            if ($autoCmd.status -eq 1) {
                                $connected = $true
                                Write-Verbose "Auto-created command already completed successfully"
                                break
                            } else {
                                Write-Verbose "Auto-created command already failed (status: $($autoCmd.status)); fetching full result for details"
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Could not fetch command list (retrying): $_"
                }
            }

            Start-Sleep -Seconds $pollInterval
            $elapsed += $pollInterval

            # Poll the auto-created command if discovered
            if ($autoCommandId) {
                try {
                    $cmdPollUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/commands/${autoCommandId}?session_id=${sessionId}&useV2Api=false&useV3Api=true"
                    $cmdResult = Invoke-RestMethod -Uri $cmdPollUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $cmdStatus = $cmdResult.status
                    Write-Verbose "Auto-command status: $cmdStatus (${elapsed}s)"

                    # Status 0 = still pending.
                    # Status 1 = Completed/Success — session is ready.
                    # Status 2+ = Failed/Cancelled — auto-connect was rejected (e.g. existing session on device).
                    if ($cmdResult.completed_on -or ($null -ne $cmdStatus -and $cmdStatus -ne 0)) {
                        if ($cmdStatus -eq 1) {
                            $connected = $true
                            Write-Verbose "Auto-created command completed successfully"
                            break
                        }

                        # Connection failed — collect error text from all possible fields
                        $errText = ''
                        if ($cmdResult.errors) {
                            $errText = @($cmdResult.errors | ForEach-Object {
                                    if ($_ -is [string]) { $_ } elseif ($null -ne $_.message) { $_.message } else { $_ | ConvertTo-Json -Compress }
                                }) -join ' '
                        }
                        if (-not $errText -and $cmdResult.error_message) { $errText = "$($cmdResult.error_message)" }
                        if (-not $errText) { $errText = ($cmdResult | ConvertTo-Json -Depth 5 -Compress) }

                        # Check for "existing session" portal-link pattern
                        if ($errText -match '<portal-link>(\{[^<]+\})</portal-link>') {
                            $existingSessionId = $null
                            try {
                                $linkData = $Matches[1] | ConvertFrom-Json
                                $existingSessionId = $linkData.id
                            } catch {
                                Write-Verbose "Failed to parse existing session portal link details: $_"
                            }
                            $deviceUser = if ($errText -match 'created by\s+(?:another user:\s*)?(\S+@\S+|\S+)') { $Matches[1] } else { 'another user' }

                            Write-Host ''
                            Write-Host "Cannot connect: a Live Response session is already active on '$deviceName'." -ForegroundColor Red
                            if ($existingSessionId) {
                                Write-Host "  Active session : $existingSessionId" -ForegroundColor Yellow
                                Write-Host "  Created by     : $deviceUser" -ForegroundColor Yellow
                                Write-Host ''
                                Write-Host "To close the existing session and try again, run:" -ForegroundColor Gray
                                Write-Host "  Disconnect-XdrEndpointDeviceLiveResponse -SessionId '$existingSessionId'" -ForegroundColor Cyan
                            }
                        } else {
                            Write-Error "Session connect failed (status: $cmdStatus).$(if ($errText) { " $errText" })"
                        }

                        try {
                            Disconnect-XdrEndpointDeviceLiveResponse -SessionId $sessionId -ErrorAction SilentlyContinue
                        } catch {
                            Write-Verbose "Failed to disconnect session $sessionId after connection failure: $_"
                        }
                        return
                    }
                } catch {
                    Write-Verbose "Command polling error (retrying): $_"
                }
            }

            # Also poll session to detect failures
            try {
                $sessionCheck = Invoke-RestMethod -Uri $sessionPollUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                $sessStatus = $sessionCheck.session_status
                if ($null -eq $sessStatus) { $sessStatus = $sessionCheck.status }
                if ($sessStatus -in $failedStatuses) {
                    Write-Error "Session failed while waiting for connection. Status: $sessStatus"
                    return
                }
            } catch {
                Write-Verbose "Session polling error (retrying): $_"
            }
        }

        if (-not $connected) {
            Write-Error "Session connection timed out after $maxWait seconds"
            try { Disconnect-XdrEndpointDeviceLiveResponse -SessionId $sessionId } catch { Write-Verbose "Cleanup disconnect failed: $_" }
            return
        }

        # Step 4: Fetch command definitions
        $commandDefinitions = @()
        try {
            $defUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/get_command_definitions?session_id=$sessionId&useV2Api=false&useV3Api=true"
            $commandDefinitions = Invoke-RestMethod -Uri $defUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            if ($commandDefinitions) {
                $availableCommands = @($commandDefinitions | ForEach-Object { $_.command_definition_id }) | Sort-Object -Unique
                Write-Verbose "Loaded $($availableCommands.Count) command definitions from API"
            } else {
                $availableCommands = $knownCommands
            }
        } catch {
            Write-Verbose "Could not fetch command definitions, using built-in list: $_"
            $availableCommands = $knownCommands
        }

        # Determine initial directory from OS platform.
        # macOS and Linux devices start at '/', while Windows starts at C:\.
        $osPlatform = "$($device.OsPlatform)".ToLower()
        $initialDirectory = if ($osPlatform -match 'mac|linux|unix') { '/' } else { 'C:\' }

        # Store session state
        $script:LiveResponseSession = @{
            SessionId          = $sessionId
            MachineId          = $DeviceId
            DeviceName         = $deviceName
            OsPlatform         = $device.OsPlatform
            CurrentDirectory   = $initialDirectory
            CommandDefinitions = $commandDefinitions
            AvailableCommands  = $availableCommands
        }


        if ($NonInteractive) {
            $sessionObj = [PSCustomObject]@{
                SessionId          = $sessionId
                DeviceId           = $DeviceId
                DeviceName         = $deviceName
                OsPlatform         = $device.OsPlatform
                CurrentDirectory   = $initialDirectory
                CommandDefinitions = $commandDefinitions
                AvailableCommands  = $availableCommands
                ConnectedOnUtc     = (Get-Date).ToUniversalTime().ToString('o')
            }
            $sessionObj.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseSession')
            return $sessionObj
        }

        # Step 5: Set up tab completion via PSReadLine for the interactive session.
        # We replace the Tab key handler for the duration of the session and restore it on exit.
        $lrPreviousTabHandler = $null
        if (Get-Command -Name 'Set-PSReadLineKeyHandler' -ErrorAction SilentlyContinue) {
            $lrPreviousTabHandler = Get-PSReadLineKeyHandler -Key Tab -ErrorAction SilentlyContinue
            Set-PSReadLineKeyHandler -Key Tab -ScriptBlock {
                param($key, $arg)
                $line = $null
                $cursor = $null
                [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
                $wordToComplete = if ($line -match '(\S+)$') { $Matches[1] } else { '' }
                $completions = @($script:LiveResponseSession.AvailableCommands |
                        Where-Object { $_ -like "$wordToComplete*" } | Sort-Object)
                if ($completions.Count -eq 0) {
                    [Microsoft.PowerShell.PSConsoleReadLine]::Insert([char]9)
                } elseif ($completions.Count -eq 1) {
                    [Microsoft.PowerShell.PSConsoleReadLine]::Replace(
                        $cursor - $wordToComplete.Length, $wordToComplete.Length, $completions[0])
                } else {
                    Write-Host "`n$($completions -join '  ')" -ForegroundColor DarkGray
                    [Microsoft.PowerShell.PSConsoleReadLine]::InvokePrompt()
                }
            }
        }

        # Display welcome banner
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host " Live Response - $deviceName" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host " Type 'help' for available commands" -ForegroundColor Gray
        Write-Host " Type 'disconnect' or 'exit' to end session" -ForegroundColor Gray
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""

        # Step 6: Interactive command loop (try/finally ensures Tab handler is restored on any exit)
        $currentDir = $initialDirectory
        $running = $true

        try {
            while ($running) {
                # Display prompt
                $prompt = "[LR: $deviceName] $currentDir> "

                try {
                    $input_line = Read-Host -Prompt $prompt
                } catch {
                    # Ctrl+C or input error
                    $running = $false
                    break
                }

                # Skip empty input
                if ([string]::IsNullOrWhiteSpace($input_line)) {
                    continue
                }

                $trimmed = $input_line.Trim()

                # Handle disconnect/exit
                if ($trimmed -in @('disconnect', 'exit', 'quit')) {
                    Write-Host "Disconnecting..." -ForegroundColor Yellow
                    try {
                        Disconnect-XdrEndpointDeviceLiveResponse -SessionId $sessionId
                    } catch {
                        Write-Warning "Error closing session: $_"
                    }
                    $running = $false
                    break
                }

                # Handle help / help <command>
                if ($trimmed -eq 'help' -or $trimmed -like 'help *') {
                    $helpSubCmd = $null
                    if ($trimmed -like 'help *') {
                        $helpSubCmd = ($trimmed -split '\s+', 2)[1].Trim().ToLower()
                    }

                    if ($helpSubCmd -and $commandDefinitions) {
                        # Detailed help for a specific command
                        $helpDef = $commandDefinitions | Where-Object { $_.command_definition_id -eq $helpSubCmd } | Select-Object -First 1
                        if ($helpDef) {
                            Write-Host ""
                            Write-Host $helpDef.command_definition_id -ForegroundColor White
                            if ($helpDef.description) {
                                Write-Host "  $($helpDef.description)" -ForegroundColor Gray
                            }
                            Write-Host ""

                            # Syntax line
                            $syntaxParts = @($helpDef.command_definition_id)
                            if ($helpDef.params) {
                                foreach ($p in $helpDef.params) {
                                    $syntaxParts += if ($p.optional) { "[$($p.param_id)]" } else { $p.param_id }
                                }
                            }
                            if ($helpDef.flags) {
                                foreach ($f in $helpDef.flags) {
                                    $fid = if ($f -is [string]) { $f } elseif ($null -ne $f.flag_id) { $f.flag_id } elseif ($null -ne $f.id) { $f.id } else { $f.name }
                                    if ($fid) { $syntaxParts += "[-$fid]" }
                                }
                            }
                            Write-Host ($syntaxParts -join ' ') -ForegroundColor Cyan
                            Write-Host ""

                            # Parameters
                            if ($helpDef.params -and @($helpDef.params).Count -gt 0) {
                                Write-Host "Parameters:" -ForegroundColor Cyan
                                foreach ($p in $helpDef.params) {
                                    $reqText = if ($p.optional) { '' } else { ' (required)' }
                                    Write-Host "  $($p.param_id)$reqText" -ForegroundColor White -NoNewline
                                    if ($p.description) { Write-Host "  $($p.description)" -ForegroundColor Gray } else { Write-Host '' }
                                }
                                Write-Host ""
                            }

                            # Flags
                            if ($helpDef.flags -and @($helpDef.flags).Count -gt 0) {
                                Write-Host "Flags:" -ForegroundColor Cyan
                                foreach ($f in $helpDef.flags) {
                                    $fid = if ($f -is [string]) { $f } elseif ($null -ne $f.flag_id) { $f.flag_id } elseif ($null -ne $f.id) { $f.id } else { $f.name }
                                    $fdesc = if ($f -is [string]) { '' } else { $f.description }
                                    if ($fid) {
                                        Write-Host "  -$fid" -ForegroundColor White -NoNewline
                                        if ($fdesc) { Write-Host "  $fdesc" -ForegroundColor Gray } else { Write-Host '' }
                                    }
                                }
                                Write-Host ""
                            }

                            # Aliases
                            if ($helpDef.aliases -and @($helpDef.aliases).Count -gt 0) {
                                Write-Host "Aliases:" -ForegroundColor Cyan
                                Write-Host "  $($helpDef.aliases -join ', ')" -ForegroundColor Gray
                                Write-Host ""
                            }
                        } else {
                            Write-Host "Unknown command: $helpSubCmd" -ForegroundColor Yellow
                            Write-Host "Type 'help' to see all available commands." -ForegroundColor Gray
                        }
                    } else {
                        # General help: list all commands
                        Write-Host ""
                        Write-Host "Available Live Response Commands:" -ForegroundColor Cyan
                        Write-Host "=================================" -ForegroundColor Cyan
                        if ($commandDefinitions -and $commandDefinitions.Count -gt 0) {
                            foreach ($cmd in ($commandDefinitions | Sort-Object -Property command_definition_id)) {
                                $cmdName = $cmd.command_definition_id
                                $cmdDesc = $cmd.description
                                if ($cmdDesc) {
                                    Write-Host "  $cmdName" -ForegroundColor White -NoNewline
                                    Write-Host " - $cmdDesc" -ForegroundColor Gray
                                } else {
                                    Write-Host "  $cmdName" -ForegroundColor White
                                }
                            }
                        } else {
                            $availableCommands | ForEach-Object {
                                Write-Host "  $_" -ForegroundColor White
                            }
                        }
                        Write-Host ""
                        Write-Host "Session commands:" -ForegroundColor Cyan
                        Write-Host "  disconnect       - Close session and return to PowerShell" -ForegroundColor Gray
                        Write-Host "  help             - Show this help message" -ForegroundColor Gray
                        Write-Host "  help <command>   - Show detailed help for a specific command" -ForegroundColor Gray
                        Write-Host ""
                    }
                    continue
                }

                # Handle cls locally
                if ($trimmed -eq 'cls') {
                    [System.Console]::Clear()
                    continue
                }

                # Send the command
                try {
                    $cmdResult = Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId $sessionId -Command $trimmed -CurrentDirectory $currentDir -CommandDefinitions $commandDefinitions -RawCommandResult

                    # Resolve the first token of the command for command-specific output handling.
                    # Needed before the output loop so analyze verdict can be color-coded.
                    $firstCmdToken = ($trimmed -split '\s+', 2)[0].ToLower()

                    # Display output from the command result.
                    # The API returns outputs[] where each element has data_type, data, keys, table_config.
                    if ($cmdResult -and $cmdResult.outputs) {
                        foreach ($outputItem in $cmdResult.outputs) {
                            $dataType = $outputItem.data_type
                            $data = $outputItem.data

                            if ($null -eq $data) { continue }

                            switch ($dataType) {
                                'table' {
                                    # Keys can be plain strings OR {id, name} objects depending on the command.
                                    # Handle both forms so column selection always works.
                                    if ($outputItem.keys) {
                                        $columns = @($outputItem.keys | ForEach-Object {
                                                if ($_ -is [string]) { $_ } elseif ($null -ne $_.id) { $_.id } else { $_.name }
                                            }) | Where-Object { $_ }
                                        if ($columns.Count -gt 0) {
                                            $data | Select-Object -Property $columns | Format-Table -AutoSize | Out-Host
                                        } else {
                                            $data | Format-Table -AutoSize | Out-Host
                                        }
                                    } else {
                                        $data | Format-Table -AutoSize | Out-Host
                                    }
                                }
                                'object' {
                                    # Object data: Format-List is more readable interactively than raw JSON
                                    $data | Format-List | Out-Host
                                }
                                default {
                                    # String or other data types.  Handle arrays of strings cleanly.
                                    if ($data -is [array]) {
                                        $data | ForEach-Object { Write-Host $_ }
                                    } elseif ($firstCmdToken -eq 'analyze') {
                                        # Color-code the analyze verdict for quick visual identification
                                        $verdictLower = "$data".ToLower()
                                        $verdictColor = if ($verdictLower -match 'malicious') { 'Red' } `
                                            elseif ($verdictLower -match 'suspicious') { 'Yellow' } `
                                            elseif ($verdictLower -match 'clean') { 'Green' } `
                                            else { 'White' }
                                        Write-Host "Verdict: $data" -ForegroundColor $verdictColor
                                    } else {
                                        Write-Host $data
                                    }
                                }
                            }
                        }
                    }

                    # Display PowerShell transcript — populated when a script is run via the 'run' command.
                    if ($cmdResult -and $cmdResult.powershell_transcript) {
                        Write-Host '--- Script Output ---' -ForegroundColor Cyan
                        Write-Host $cmdResult.powershell_transcript
                    }

                    # Check for errors. Error objects have {hresult, message, command_error_type}; plain
                    # strings are also possible. Extract the human-readable message in both cases.
                    if ($cmdResult.errors -and $cmdResult.errors.Count -gt 0) {
                        foreach ($err in $cmdResult.errors) {
                            $errMsg = if ($err -is [string]) { $err } `
                                elseif ($null -ne $err.message) { $err.message } `
                                else { $err | ConvertTo-Json -Compress }
                            Write-Host "Error: $errMsg" -ForegroundColor Red
                        }
                    }

                    # Handle getfile download: after command completes, context.download_token
                    # contains a short-lived token to retrieve the file from the device.
                    # Endpoint: GET /download_file?token={token}&session_id={sid}
                    if ($cmdResult -and $cmdResult.context -and $cmdResult.context.download_token) {
                        $downloadToken = $cmdResult.context.download_token
                        # Extract the remote path from the command to suggest a default local filename
                        $cmdParts = $trimmed -split '\s+', 2
                        $pathArg = if ($cmdParts.Count -ge 2) {
                            # Strip leading/trailing quotes and any trailing flags (e.g. -upload)
                            ($cmdParts[1] -split '\s+-')[0].Trim().Trim('"', "'")
                        } else { '' }
                        $defaultName = if ($pathArg) { [System.IO.Path]::GetFileName($pathArg) } else { 'downloaded_file' }
                        if ([string]::IsNullOrWhiteSpace($defaultName)) { $defaultName = 'downloaded_file' }
                        $defaultLocal = Join-Path ([System.IO.Path]::GetTempPath()) $defaultName

                        Write-Host ''
                        Write-Host "File ready for download from device." -ForegroundColor Green
                        Write-Host "Default path: $defaultLocal" -ForegroundColor Gray
                        $savePath = Read-Host "Save as [Enter for default]"
                        if ([string]::IsNullOrWhiteSpace($savePath)) { $savePath = $defaultLocal }

                        try {
                            $dlUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/download_file?token=$([System.Uri]::EscapeDataString($downloadToken))&session_id=$sessionId&useV2Api=false&useV3Api=true"
                            Write-Host "Downloading..." -ForegroundColor Cyan
                            $dlResponse = Invoke-WebRequest -Uri $dlUri -Method Get -WebSession $script:session -Headers $script:headers
                            [System.IO.File]::WriteAllBytes($savePath, $dlResponse.RawContentStream.ToArray())
                            Write-Host "Saved to: $savePath" -ForegroundColor Green
                        } catch {
                            Write-Host "Download failed: $_" -ForegroundColor Red
                        }
                    }

                    # Update current directory if cd command
                    if ($firstCmdToken -eq 'cd' -and $cmdResult.context -and $cmdResult.context.current_directory) {
                        $currentDir = $cmdResult.context.current_directory
                    }

                    # Show non-success status (status 1 = completed/success)
                    $cmdStatus = $cmdResult.status
                    if ($null -ne $cmdStatus -and $cmdStatus -ne 1) {
                        Write-Host "Command status: $cmdStatus" -ForegroundColor Yellow
                    }

                    # Show execution time for visibility
                    if ($null -ne $cmdResult.duration_seconds) {
                        Write-Host "  [$('{0:N2}' -f $cmdResult.duration_seconds)s]" -ForegroundColor DarkGray
                    }
                } catch {
                    Write-Host "Error executing command: $_" -ForegroundColor Red
                }

                Write-Host ""
            }

        } finally {
            # Restore previous Tab key handler and clean up session state
            if ($null -ne $lrPreviousTabHandler) {
                if ($lrPreviousTabHandler.ScriptBlock) {
                    Set-PSReadLineKeyHandler -Key Tab -ScriptBlock $lrPreviousTabHandler.ScriptBlock
                } elseif ($lrPreviousTabHandler.Function) {
                    Set-PSReadLineKeyHandler -Key Tab -Function $lrPreviousTabHandler.Function
                }
            }
            $script:LiveResponseSession = $null
        }
    }

    end {
        if (-not $NonInteractive -or $pendingDeviceIds.Count -eq 0) {
            return
        }

        $requestContext = Get-XdrRequestContextSnapshot
        $batchItems = @($pendingDeviceIds)

        $connectionStatusMap = [ordered]@{}
        $displayOrder = 0
        foreach ($batchItem in $batchItems) {
            $connectionStatusMap[$batchItem.DeviceId] = [PSCustomObject]@{
                DeviceId       = $batchItem.DeviceId
                DisplayOrder   = $displayOrder
                DeviceName     = if ([string]::IsNullOrWhiteSpace($batchItem.DeviceName)) { $batchItem.DeviceId } else { $batchItem.DeviceName }
                Status         = 'Queued'
                SessionId      = ''
                ConnectedOnUtc = ''
            }
            $displayOrder++
        }

        $renderState = @{
            Initialized = $false
            UseCursor   = $false
            UseAnsi     = $false
            Top         = 0
            LineCount   = 0
            MaxWidth    = 0
            Fallback    = $false
        }

        function Write-XdrLiveResponseConnectionStatusTable {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Title
            )

            $rows = @($connectionStatusMap.Values |
                    Sort-Object DisplayOrder |
                    Select-Object DeviceName, Status, SessionId, ConnectedOnUtc)

            $lines = [System.Collections.Generic.List[string]]::new()
            $lines.Add($Title)
            $lines.Add('')

            $tableText = ($rows | Format-Table DeviceName, Status, SessionId, ConnectedOnUtc -AutoSize | Out-String -Width 320).TrimEnd("`r", "`n")
            foreach ($line in @($tableText -split "`r?`n")) {
                $lines.Add($line)
            }

            if (-not $renderState.Initialized) {
                $supportsAnsiRendering = $false
                $hasTerminalHints = -not [string]::IsNullOrWhiteSpace($env:TERM_PROGRAM) -or
                -not [string]::IsNullOrWhiteSpace($env:WT_SESSION) -or
                -not [string]::IsNullOrWhiteSpace($env:TERM)
                try {
                    $supportsAnsiRendering = $PSStyle.OutputRendering -eq 'Host' -and -not [Console]::IsOutputRedirected
                } catch {
                    $supportsAnsiRendering = $false
                }

                $renderState.UseAnsi = $supportsAnsiRendering -and $hasTerminalHints
                try {
                    if (-not $renderState.UseAnsi) {
                        $renderState.Top = [Console]::CursorTop
                        $renderState.UseCursor = $true
                    }
                } catch {
                    $renderState.UseCursor = $false
                    $renderState.Fallback = $true
                }

                foreach ($line in $lines) {
                    Write-Host $line
                }

                $renderState.LineCount = $lines.Count
                $renderState.MaxWidth = [Math]::Max(1, (($lines | Measure-Object -Property Length -Maximum).Maximum))
                $renderState.Initialized = $true
                return
            }

            if ($renderState.UseAnsi) {
                try {
                    $escape = [char]27
                    $moveUp = if ($renderState.LineCount -gt 0) { "$escape[$($renderState.LineCount)F" } else { '' }
                    Write-Host -NoNewline $moveUp
                    $lineWidth = [Math]::Max($renderState.MaxWidth, (($lines | Measure-Object -Property Length -Maximum).Maximum))
                    for ($index = 0; $index -lt [Math]::Max($renderState.LineCount, $lines.Count); $index++) {
                        $line = if ($index -lt $lines.Count) { $lines[$index] } else { '' }
                        Write-Host ($line.PadRight($lineWidth))
                    }

                    $renderState.LineCount = [Math]::Max($renderState.LineCount, $lines.Count)
                    $renderState.MaxWidth = $lineWidth
                    return
                } catch {
                    $renderState.UseAnsi = $false
                    $renderState.Fallback = $true
                }
            }

            if ($renderState.Fallback -or -not $renderState.UseCursor) {
                Write-Host ''
                foreach ($line in $lines) {
                    Write-Host $line
                }
                $renderState.LineCount = $lines.Count
                $renderState.MaxWidth = [Math]::Max($renderState.MaxWidth, (($lines | Measure-Object -Property Length -Maximum).Maximum))
                return
            }

            try {
                $lineWidth = [Math]::Max($renderState.MaxWidth, (($lines | Measure-Object -Property Length -Maximum).Maximum))
                [Console]::SetCursorPosition(0, $renderState.Top)
                for ($index = 0; $index -lt [Math]::Max($renderState.LineCount, $lines.Count); $index++) {
                    $line = if ($index -lt $lines.Count) { $lines[$index] } else { '' }
                    Write-Host ($line.PadRight($lineWidth))
                }
                $renderState.LineCount = $lines.Count
                $renderState.MaxWidth = $lineWidth
                [Console]::SetCursorPosition(0, $renderState.Top + $renderState.LineCount)
            } catch {
                $renderState.Fallback = $true
                Write-Host ''
                foreach ($line in $lines) {
                    Write-Host $line
                }
                $renderState.LineCount = $lines.Count
                $renderState.MaxWidth = [Math]::Max($renderState.MaxWidth, (($lines | Measure-Object -Property Length -Maximum).Maximum))
            }
        }

        $statusDisplayEnabled = $batchItems.Count -gt 1 -and -not $NoStatusTable
        $progressState = [PSCustomObject]@{
            CompletedCount = 0
        }
        if ($statusDisplayEnabled) {
            Write-XdrLiveResponseConnectionStatusTable -Title ("Connecting Live Response sessions: 0/{0} completed" -f $batchItems.Count)
        }

        $workerScript = {
            param($Item, $SharedParameters)

            $deviceId = "$($Item.DeviceId)"
            $deviceName = if ([string]::IsNullOrWhiteSpace("$($Item.DeviceName)")) { $null } else { "$($Item.DeviceName)" }
            $lastSeen = $Item.LastSeen
            $osPlatform = if ([string]::IsNullOrWhiteSpace("$($Item.OsPlatform)")) { $null } else { "$($Item.OsPlatform)" }
            $baseUrl = $SharedParameters.BaseUrl
            $headers = $SharedParameters.HeadersData
            $knownCommands = @($SharedParameters.KnownCommands)

            $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            foreach ($cookieInfo in $SharedParameters.CookieData) {
                $cookie = [System.Net.Cookie]::new($cookieInfo.Name, $cookieInfo.Value, $cookieInfo.Path, $cookieInfo.Domain)
                $webSession.Cookies.Add($cookie)
            }

            $device = $null
            if ([string]::IsNullOrWhiteSpace($deviceName) -or [string]::IsNullOrWhiteSpace("$lastSeen") -or [string]::IsNullOrWhiteSpace($osPlatform)) {
                $deviceUri = "$baseUrl/apiproxy/mtp/getMachine/machines?machineId=$deviceId&idType=SenseMachineId&readFromCache=false&lookingBackIndays=180"
                $device = Invoke-RestMethod -Uri $deviceUri -Method Get -ContentType 'application/json' -WebSession $webSession -Headers $headers
                if (-not $device) {
                    throw "Device not found: $deviceId"
                }
            }

            if ($device) {
                if ([string]::IsNullOrWhiteSpace($deviceName)) {
                    $deviceName = $device.ComputerDnsName
                }
                if ([string]::IsNullOrWhiteSpace("$lastSeen")) {
                    $lastSeen = $device.LastSeen
                }
                if ([string]::IsNullOrWhiteSpace($osPlatform)) {
                    $osPlatform = $device.OsPlatform
                }
            }

            $createBody = @{
                machine_id        = $deviceId
                machine_last_seen = $lastSeen
            } | ConvertTo-Json -Depth 10

            $createUri = "$baseUrl/apiproxy/mtp/liveResponseApi/create_session?useV3Api=true&tenantIds=undefined"
            $sessionResponse = Invoke-RestMethod -Uri $createUri -Method Post -ContentType 'application/json' -Body $createBody -WebSession $webSession -Headers $headers

            $sessionId = $sessionResponse.session_id
            if (-not $sessionId) {
                throw 'No session_id returned from create_session API'
            }

            $maxWait = 180
            $pollInterval = 1.5
            $elapsed = 0
            $connected = $false
            $failedStatuses = @('Failed', 'Expired', 'Closed', 4, 5, 6)
            $commandDefinitions = @()
            $availableCommands = $knownCommands
            $definitionsFetched = $false

            Start-Sleep -Seconds 1
            $elapsed += 1
            try {
                $sessionUri = "$baseUrl/apiproxy/mtp/liveResponseApi/sessions/${sessionId}?useV3Api=true"
                $sessionStatus = Invoke-RestMethod -Uri $sessionUri -Method Get -ContentType 'application/json' -WebSession $webSession -Headers $headers
                $status = $sessionStatus.session_status
                if ($null -eq $status) { $status = $sessionStatus.status }
                if ($status -in $failedStatuses) {
                    throw "Session failed to create. Status: $status"
                }
            } catch {
                if ($_.Exception.Message -like 'Session failed to create*') {
                    throw
                }
                Write-Verbose "Initial worker session poll error for device ${deviceId}: $_"
            }

            $autoCommandId = $null
            $commandsListUri = "$baseUrl/apiproxy/mtp/liveResponseApi/sessions/${sessionId}/commands/?session_id=${sessionId}&useV2Api=false&useV3Api=true"
            $sessionPollUri = "$baseUrl/apiproxy/mtp/liveResponseApi/sessions/${sessionId}?useV2Api=false&useV3Api=true"

            while ($elapsed -lt $maxWait -and -not $connected) {
                if (-not $autoCommandId) {
                    try {
                        $commandsList = @(Invoke-RestMethod -Uri $commandsListUri -Method Get -ContentType 'application/json' -WebSession $webSession -Headers $headers)
                        if ($commandsList.Count -gt 0) {
                            $autoCmd = $commandsList[0]
                            $autoCommandId = $autoCmd.command_id
                            if (-not $autoCommandId) { $autoCommandId = $autoCmd.id }

                            if ($autoCmd.completed_on -or ($null -ne $autoCmd.status -and $autoCmd.status -ne 0)) {
                                if ($autoCmd.status -eq 1) {
                                    $connected = $true
                                    break
                                }
                            }
                        }
                    } catch {
                        Write-Verbose "Worker command discovery retry for device ${deviceId}: $_"
                    }
                }

                Start-Sleep -Seconds $pollInterval
                $elapsed += $pollInterval

                if ($autoCommandId) {
                    try {
                        $cmdPollUri = "$baseUrl/apiproxy/mtp/liveResponseApi/commands/${autoCommandId}?session_id=${sessionId}&useV2Api=false&useV3Api=true"
                        $cmdResult = Invoke-RestMethod -Uri $cmdPollUri -Method Get -ContentType 'application/json' -WebSession $webSession -Headers $headers
                        $cmdStatus = $cmdResult.status

                        if ($cmdResult.completed_on -or ($null -ne $cmdStatus -and $cmdStatus -ne 0)) {
                            if ($cmdStatus -eq 1) {
                                $connected = $true
                                break
                            }

                            $errText = ''
                            if ($cmdResult.errors) {
                                $errText = @($cmdResult.errors | ForEach-Object {
                                        if ($_ -is [string]) { $_ } elseif ($null -ne $_.message) { $_.message } else { $_ | ConvertTo-Json -Compress }
                                    }) -join ' '
                            }
                            if (-not $errText -and $cmdResult.error_message) { $errText = "$($cmdResult.error_message)" }
                            if (-not $errText) { $errText = ($cmdResult | ConvertTo-Json -Depth 5 -Compress) }

                            if ($errText -match '<portal-link>(\{[^<]+\})</portal-link>') {
                                $existingSessionId = $null
                                try {
                                    $linkData = $Matches[1] | ConvertFrom-Json
                                    $existingSessionId = $linkData.id
                                } catch {
                                    Write-Verbose "Failed to parse existing session portal link details for device ${deviceId}: $_"
                                }
                                $deviceUser = if ($errText -match 'created by\s+(?:another user:\s*)?(\S+@\S+|\S+)') { $Matches[1] } else { 'another user' }
                                if ($existingSessionId) {
                                    throw "Cannot connect: a Live Response session is already active on '$deviceName'. Active session: $existingSessionId. Created by: $deviceUser"
                                }
                                throw "Cannot connect: a Live Response session is already active on '$deviceName'. Created by: $deviceUser"
                            }

                            throw "Session connect failed (status: $cmdStatus). $errText"
                        }
                    } catch {
                        if ($_.Exception.Message -like 'Cannot connect:*' -or $_.Exception.Message -like 'Session connect failed*') {
                            if ($sessionId) {
                                try {
                                    $closeBody = @{ session_id = $sessionId } | ConvertTo-Json -Depth 5
                                    $closeUri = "$baseUrl/apiproxy/mtp/liveResponseApi/close_session?useV2Api=false&useV3Api=true"
                                    Invoke-RestMethod -Uri $closeUri -Method Post -ContentType 'application/json' -Body $closeBody -WebSession $webSession -Headers $headers | Out-Null
                                } catch {
                                    Write-Verbose "Failed to close unsuccessful worker session ${sessionId} for device ${deviceId}: $_"
                                }
                            }
                            throw
                        }
                    }
                }

                try {
                    $sessionCheck = Invoke-RestMethod -Uri $sessionPollUri -Method Get -ContentType 'application/json' -WebSession $webSession -Headers $headers
                    $sessStatus = $sessionCheck.session_status
                    if ($null -eq $sessStatus) { $sessStatus = $sessionCheck.status }
                    if ($sessStatus -in $failedStatuses) {
                        throw "Session failed while waiting for connection. Status: $sessStatus"
                    }
                } catch {
                    if ($_.Exception.Message -like 'Session failed while waiting*') {
                        throw
                    }
                    Write-Verbose "Worker session status retry for device ${deviceId}: $_"
                }

                if (-not $definitionsFetched) {
                    try {
                        $defUri = "$baseUrl/apiproxy/mtp/liveResponseApi/get_command_definitions?session_id=$sessionId&useV2Api=false&useV3Api=true"
                        $commandDefinitions = Invoke-RestMethod -Uri $defUri -Method Get -ContentType 'application/json' -WebSession $webSession -Headers $headers
                        if ($commandDefinitions) {
                            $availableCommands = @($commandDefinitions | ForEach-Object { $_.command_definition_id } | Sort-Object -Unique)
                        }
                        $definitionsFetched = $true
                        $connected = $true
                        break
                    } catch {
                        Write-Verbose "Worker command definitions retry for device ${deviceId}: $_"
                    }
                }
            }

            if (-not $connected) {
                try {
                    $closeBody = @{ session_id = $sessionId } | ConvertTo-Json -Depth 5
                    $closeUri = "$baseUrl/apiproxy/mtp/liveResponseApi/close_session?useV2Api=false&useV3Api=true"
                    Invoke-RestMethod -Uri $closeUri -Method Post -ContentType 'application/json' -Body $closeBody -WebSession $webSession -Headers $headers | Out-Null
                } catch {
                    Write-Verbose "Failed to close timed-out worker session ${sessionId} for device ${deviceId}: $_"
                }
                throw "Session connection timed out after $maxWait seconds"
            }

            if (-not $definitionsFetched) {
                try {
                    $defUri = "$baseUrl/apiproxy/mtp/liveResponseApi/get_command_definitions?session_id=$sessionId&useV2Api=false&useV3Api=true"
                    $commandDefinitions = Invoke-RestMethod -Uri $defUri -Method Get -ContentType 'application/json' -WebSession $webSession -Headers $headers
                    if ($commandDefinitions) {
                        $availableCommands = @($commandDefinitions | ForEach-Object { $_.command_definition_id } | Sort-Object -Unique)
                    } else {
                        $availableCommands = $knownCommands
                    }
                } catch {
                    $availableCommands = $knownCommands
                }
            }

            $osPlatformText = "$osPlatform"
            $initialDirectory = if ($osPlatformText.ToLower() -match 'mac|linux|unix') { '/' } else { 'C:\' }

            $sessionObj = [PSCustomObject]@{
                SessionId          = $sessionId
                DeviceId           = $deviceId
                DeviceName         = $deviceName
                OsPlatform         = $osPlatformText
                CurrentDirectory   = $initialDirectory
                CommandDefinitions = $commandDefinitions
                AvailableCommands  = $availableCommands
                ConnectedOnUtc     = (Get-Date).ToUniversalTime().ToString('o')
            }
            $sessionObj.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseSession')
            $sessionObj
        }

        $batchResults = Invoke-XdrRateLimitedBatch -Items $batchItems -OperationName 'Connect-XdrEndpointDeviceLiveResponse -NonInteractive' -ItemScript $workerScript -SharedParameters @{
            BaseUrl       = $requestContext.BaseUrl
            CookieData    = $requestContext.CookieData
            HeadersData   = $requestContext.HeadersData
            KnownCommands = $knownCommands
        } -BatchStartedScript {
            param($BatchNumber, $TotalBatches, $Items)

            if (-not $statusDisplayEnabled) {
                return
            }

            foreach ($startedItem in @($Items)) {
                $entry = $connectionStatusMap[$startedItem.DeviceId]
                if ($null -eq $entry) {
                    continue
                }

                if ([string]::IsNullOrWhiteSpace($entry.DeviceName) -or $entry.DeviceName -eq $startedItem.DeviceId) {
                    $entry.DeviceName = if ([string]::IsNullOrWhiteSpace($startedItem.DeviceName)) { $startedItem.DeviceId } else { $startedItem.DeviceName }
                }
                $entry.Status = 'Connecting'
            }

            Write-XdrLiveResponseConnectionStatusTable -Title ("Connecting Live Response sessions: {0}/{1} completed" -f $progressState.CompletedCount, $batchItems.Count)
        } -ItemCompletedScript {
            param($BatchNumber, $TotalBatches, $Result)

            if (-not $statusDisplayEnabled) {
                return
            }

            $entry = $connectionStatusMap[$Result.Item.DeviceId]
            if ($null -eq $entry) {
                return
            }

            $progressState.CompletedCount++
            if ($Result.Success -and $Result.Result) {
                $entry.DeviceName = if ([string]::IsNullOrWhiteSpace($Result.Result.DeviceName)) { $entry.DeviceName } else { $Result.Result.DeviceName }
                $entry.Status = 'Connected'
                $entry.SessionId = $Result.Result.SessionId
                $entry.ConnectedOnUtc = $Result.Result.ConnectedOnUtc
            } else {
                $entry.Status = 'Failed'
                $entry.SessionId = ''
                $entry.ConnectedOnUtc = ''
            }

            Write-XdrLiveResponseConnectionStatusTable -Title ("Connecting Live Response sessions: {0}/{1} completed" -f $progressState.CompletedCount, $batchItems.Count)
        }

        if ($statusDisplayEnabled) {
            Write-Host ''
        }

        foreach ($batchResult in $batchResults) {
            if ($batchResult.Success) {
                $batchResult.Result
            } else {
                Write-Error "Failed to create Live Response session for device '$($batchResult.Item.DeviceId)': $($batchResult.ErrorText)"
            }
        }
    }
}
