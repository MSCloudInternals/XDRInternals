function Connect-XdrEndpointDeviceLiveResponse {
    <#
    .SYNOPSIS
        Opens an interactive Live Response session to an endpoint device in Microsoft Defender XDR.

    .DESCRIPTION
        Creates a Live Response session to the specified device and provides an interactive
        command-line interface. The session connects to the device, fetches available commands
        for tab completion, and enters an interactive loop where you can type Live Response
        commands and see results.

        Type 'disconnect' or 'exit' to close the session and return to PowerShell.
        Type 'help' to see available Live Response commands.

        Available Live Response commands include:
        analyze, cd, cls, connect, connections, dir, drivers, fileinfo, findfile,
        getfile, help, jobs, library, log, persistence, prefetch, processes, putfile,
        registry, remediate, run, scheduledtasks, services, startup, trace, undo

    .PARAMETER DeviceId
        The device ID (SenseMachineId) of the target device.

    .EXAMPLE
        Connect-XdrEndpointDeviceLiveResponse -DeviceId "55a5db7b474470725e0131dec38c07b2f54bf2ad"
        Opens an interactive Live Response session to the specified device.

    .EXAMPLE
        Invoke-XdrEndpointDeviceAction -DeviceId "abc123" -LiveResponse
        Opens a Live Response session via the unified action cmdlet.

    .OUTPUTS
        None
        This cmdlet runs interactively and does not return output.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameters required by Register-ArgumentCompleter scriptblock signature')]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40,40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$DeviceId
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Known Live Response commands for tab completion fallback
        $knownCommands = @(
            'analyze', 'cd', 'cls', 'connect', 'connections', 'dir', 'drivers',
            'fileinfo', 'findfile', 'getfile', 'help', 'jobs', 'library', 'log',
            'persistence', 'prefetch', 'processes', 'putfile', 'registry',
            'remediate', 'run', 'scheduledtasks', 'services', 'startup', 'trace', 'undo'
        )

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

                        # Check if the command already completed in the list response
                        if ($autoCmd.completed_on -or ($null -ne $autoCmd.status -and $autoCmd.status -ne 0)) {
                            $connected = $true
                            Write-Verbose "Auto-created command already completed (status: $($autoCmd.status))"
                            break
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

                    # Status 0 = still pending; any other status (1=Completed, etc.) means done
                    if ($cmdResult.completed_on -or ($null -ne $cmdStatus -and $cmdStatus -ne 0)) {
                        $connected = $true
                        Write-Verbose "Auto-created command completed with status: $cmdStatus"
                        break
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

        # Store session state
        $script:LiveResponseSession = @{
            SessionId          = $sessionId
            MachineId          = $DeviceId
            DeviceName         = $deviceName
            CurrentDirectory   = 'C:\'
            CommandDefinitions = $commandDefinitions
            AvailableCommands  = $availableCommands
        }

        # Step 5: Register tab completion for the interactive session
        Register-ArgumentCompleter -CommandName 'Read-Host' -ScriptBlock {
            param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
            $script:LiveResponseSession.AvailableCommands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
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

        # Step 6: Interactive command loop
        $currentDir = 'C:\'
        $running = $true

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

            # Handle help
            if ($trimmed -eq 'help') {
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
                Write-Host "  disconnect  - Close session and return to PowerShell" -ForegroundColor Gray
                Write-Host "  help        - Show this help message" -ForegroundColor Gray
                Write-Host ""
                continue
            }

            # Handle cls locally
            if ($trimmed -eq 'cls') {
                [System.Console]::Clear()
                continue
            }

            # Send the command
            try {
                $cmdResult = Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId $sessionId -Command $trimmed -CurrentDirectory $currentDir -CommandDefinitions $commandDefinitions

                # Display output from the command result
                # The API returns outputs[] array where each element has data_type and data
                if ($cmdResult -and $cmdResult.outputs) {
                    foreach ($outputItem in $cmdResult.outputs) {
                        $dataType = $outputItem.data_type
                        $data = $outputItem.data

                        if ($null -eq $data) { continue }

                        switch ($dataType) {
                            'table' {
                                # Table data: array of objects, use keys for column selection if available
                                if ($outputItem.keys) {
                                    $columns = @($outputItem.keys | ForEach-Object { $_.id })
                                    $data | Select-Object -Property $columns | Format-Table -AutoSize | Out-Host
                                } else {
                                    $data | Format-Table -AutoSize | Out-Host
                                }
                            }
                            'object' {
                                # Object data: render as formatted JSON
                                $data | ConvertTo-Json -Depth 10 | Out-Host
                            }
                            default {
                                # String or other data types
                                Write-Host $data
                            }
                        }
                    }
                }

                # Check for errors
                if ($cmdResult.errors -and $cmdResult.errors.Count -gt 0) {
                    foreach ($err in $cmdResult.errors) {
                        Write-Host "Error: $err" -ForegroundColor Red
                    }
                }

                # Update current directory if cd command
                $firstToken = ($trimmed -split '\s+', 2)[0].ToLower()
                if ($firstToken -eq 'cd' -and $cmdResult.context -and $cmdResult.context.current_directory) {
                    $currentDir = $cmdResult.context.current_directory
                }

                # Show non-success status (status 1 = completed/success)
                $cmdStatus = $cmdResult.status
                if ($null -ne $cmdStatus -and $cmdStatus -ne 1) {
                    Write-Host "Command status: $cmdStatus" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error executing command: $_" -ForegroundColor Red
            }

            Write-Host ""
        }

        # Cleanup
        $script:LiveResponseSession = $null
    }

    end {
    }
}
