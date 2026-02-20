function Invoke-XdrEndpointDeviceLiveResponseCommand {
    <#
    .SYNOPSIS
        Sends a command to an active Live Response session in Microsoft Defender XDR.

    .DESCRIPTION
        Submits a command to an active Live Response session and polls for the result.
        Parses the raw command line to extract the command definition ID and parameters,
        then sends the command via the Live Response API and waits for completion.

        This cmdlet can be used programmatically or is called automatically by
        Connect-XdrEndpointDeviceLiveResponse during interactive sessions.

    .PARAMETER SessionId
        The Live Response session ID (starts with CLR prefix).

    .PARAMETER Command
        The raw command line to execute (e.g., "dir C:\Windows", "processes", "getfile C:\temp\log.txt").

    .PARAMETER CurrentDirectory
        The current working directory on the remote device. Defaults to "C:\".

    .PARAMETER BackgroundMode
        Run the command in background mode if supported.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for command completion. Defaults to 300 seconds (5 minutes).

    .PARAMETER PollIntervalSeconds
        How often to check for command completion. Defaults to 2 seconds.

    .PARAMETER CommandDefinitions
        Array of command definition objects from the Live Response API's get_command_definitions endpoint.
        Used to map positional parameters to the correct param_id for each command.
        When not provided, falls back to using 'path' as the default param_id.

    .EXAMPLE
        Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb" -Command "processes"
        Lists running processes on the remote device.

    .EXAMPLE
        Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb" -Command "dir C:\Windows" -CurrentDirectory "C:\"
        Lists the contents of C:\Windows.

    .EXAMPLE
        Invoke-XdrEndpointDeviceLiveResponseCommand -SessionId "CLR0c33ce1c-1665-4e00-9059-8fa39da9e2cb" -Command "getfile C:\temp\log.txt" -TimeoutSeconds 120
        Downloads a file with a 2-minute timeout.

    .OUTPUTS
        PSCustomObject
        Returns the command result object including output and status.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SessionId,

        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter()]
        [string]$CurrentDirectory = 'C:\',

        [Parameter()]
        [switch]$BackgroundMode,

        [Parameter()]
        [int]$TimeoutSeconds = 300,

        [Parameter()]
        [int]$PollIntervalSeconds = 2,

        [Parameter()]
        [array]$CommandDefinitions
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Parse command line: first token is command_definition_id, rest are params
        $tokens = $Command.Trim() -split '\s+', 2
        $commandId = $tokens[0].ToLower()
        $paramString = if ($tokens.Length -gt 1) { $tokens[1] } else { $null }

        # Build params array using command definitions for correct param_id mapping
        $params = @()
        if ($paramString) {
            # Look up the command definition to find the correct param_id
            $cmdDef = $null
            if ($CommandDefinitions) {
                $cmdDef = $CommandDefinitions | Where-Object { $_.command_definition_id -eq $commandId }
            }

            if ($cmdDef -and $cmdDef.params) {
                # Get value params (exclude 'output' format selector)
                $valueParams = @($cmdDef.params | Where-Object { $_.param_id -ne 'output' })

                if ($valueParams.Count -eq 1) {
                    # Single value param: entire paramString is the value (strip surrounding quotes if present)
                    $value = $paramString -replace '^"(.*)"$', '$1' -replace "^'(.*)'$", '$1'
                    $params += @{
                        param_id = $valueParams[0].param_id
                        value    = $value
                    }
                } elseif ($valueParams.Count -gt 1) {
                    # Multiple value params: split with limit so the last param gets the remainder
                    # Use shell-like tokenization to respect quoted strings
                    $paramTokens = [System.Collections.Generic.List[string]]::new()
                    $remaining = $paramString
                    for ($i = 0; $i -lt ($valueParams.Count - 1); $i++) {
                        $remaining = $remaining.TrimStart()
                        if ($remaining -match '^"([^"]*)"(.*)$') {
                            $paramTokens.Add($Matches[1])
                            $remaining = $Matches[2]
                        } elseif ($remaining -match "^'([^']*)'(.*)$") {
                            $paramTokens.Add($Matches[1])
                            $remaining = $Matches[2]
                        } elseif ($remaining -match '^(\S+)(.*)$') {
                            $paramTokens.Add($Matches[1])
                            $remaining = $Matches[2]
                        } else {
                            break
                        }
                    }
                    # Last value param gets whatever remains
                    $lastValue = $remaining.Trim() -replace '^"(.*)"$', '$1' -replace "^'(.*)'$", '$1'
                    if ($lastValue) { $paramTokens.Add($lastValue) }

                    for ($i = 0; $i -lt [Math]::Min($valueParams.Count, $paramTokens.Count); $i++) {
                        $params += @{
                            param_id = $valueParams[$i].param_id
                            value    = $paramTokens[$i]
                        }
                    }
                }
            } else {
                # Fallback: use 'path' as default param_id (works for dir, fileinfo, getfile)
                $params += @{
                    param_id = 'path'
                    value    = $paramString -replace '^"(.*)"$', '$1' -replace "^'(.*)'$", '$1'
                }
            }
        }

        # Build raw_command_line with quoting for param values that contain spaces
        # The API server parses raw_command_line and validates consistency with params.
        # Values containing spaces must be quoted in raw_command_line to be treated as single tokens.
        $rawCommandLine = $Command
        if ($params.Count -gt 0) {
            $quotedParts = @($commandId)
            foreach ($p in $params) {
                if ($p.value -match '\s') {
                    $quotedParts += "`"$($p.value)`""
                } else {
                    $quotedParts += $p.value
                }
            }
            $rawCommandLine = $quotedParts -join ' '
        }

        # Build the create command body
        $body = @{
            session_id            = $SessionId
            command_definition_id = $commandId
            params                = $params
            flags                 = @()
            raw_command_line      = $rawCommandLine
            current_directory     = $CurrentDirectory
            background_mode       = [bool]$BackgroundMode
        } | ConvertTo-Json -Depth 10

        try {
            # Create the command
            $createUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/create_command?session_id=$SessionId&useV3Api=true"
            Write-Verbose "Sending Live Response command: $Command"
            $createResult = Invoke-RestMethod -Uri $createUri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

            $commandGuid = $createResult.command_id
            if (-not $commandGuid) {
                Write-Error "Failed to create Live Response command - no command_id returned"
                return $createResult
            }

            Write-Verbose "Command created with ID: $commandGuid"

            # Poll for command completion
            $pollUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/commands/${commandGuid}?session_id=$SessionId&useV2Api=false&useV3Api=true"
            $elapsed = 0

            while ($elapsed -lt $TimeoutSeconds) {
                Start-Sleep -Seconds $PollIntervalSeconds
                $elapsed += $PollIntervalSeconds

                $commandResult = Invoke-RestMethod -Uri $pollUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $status = $commandResult.status
                Write-Verbose "Command status: $status (${elapsed}s elapsed)"

                # Completion is signaled by completed_on being set.
                # Status codes include transient values (7=created, 130=downloading, etc.)
                # so we cannot rely on status alone to determine completion.
                if ($commandResult.completed_on) {
                    $commandResult.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
                    return $commandResult
                }
            }

            Write-Warning "Command timed out after $TimeoutSeconds seconds. Command ID: $commandGuid"
            $commandResult.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
            return $commandResult
        } catch {
            Write-Error "Failed to execute Live Response command: $_"
        }
    }

    end {
    }
}
