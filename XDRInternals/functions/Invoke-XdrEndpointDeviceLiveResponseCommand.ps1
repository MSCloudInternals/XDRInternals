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

    .NOTES
        macOS validation baseline: February 24, 2026.

        Use POSIX-style paths for macOS sessions (for example: /, /Applications, /etc/hosts, /tmp).

        Some Live Response commands are platform-restricted or tenant-policy restricted and can return
        errors such as "Not allowed to run this command". These responses should be recorded as
        capability limitations instead of parser failures.

    .OUTPUTS
        PSCustomObject
        Returns the command result object including output, status, context, and errors.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameters used inside process block; false positive from PSScriptAnalyzer scoping')]
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
        #region Step 1: Tokenize the command line, respecting quoted strings
        # Example: dir "C:\Program Files" -output json -> ["dir", "C:\Program Files", "-output", "json"]
        # $tokenIsQuoted tracks whether each token was originally surrounded by quotes.
        # A quoted token is never treated as a flag even if its content starts with '-'.
        # This is critical for: run script.ps1 -parameters "-processName Registry"
        $tokenList = [System.Collections.Generic.List[string]]::new()
        $tokenIsQuoted = [System.Collections.Generic.List[bool]]::new()
        $pos = 0
        $line = $Command.Trim()
        while ($pos -lt $line.Length) {
            # Skip whitespace between tokens
            while ($pos -lt $line.Length -and $line[$pos] -eq ' ') { $pos++ }
            if ($pos -ge $line.Length) { break }

            $tokenBuf = [System.Text.StringBuilder]::new()
            $wasQuoted = $false
            while ($pos -lt $line.Length -and $line[$pos] -ne ' ') {
                $ch = $line[$pos]
                if ($ch -eq '"' -or $ch -eq "'") {
                    # Quoted segment: consume until matching closing quote, stripping the quotes
                    $wasQuoted = $true
                    $qc = $ch; $pos++
                    while ($pos -lt $line.Length -and $line[$pos] -ne $qc) {
                        $null = $tokenBuf.Append($line[$pos]); $pos++
                    }
                    if ($pos -lt $line.Length) { $pos++ }  # skip closing quote
                } else {
                    $null = $tokenBuf.Append($ch); $pos++
                }
            }
            if ($tokenBuf.Length -gt 0) {
                $tokenList.Add($tokenBuf.ToString())
                $tokenIsQuoted.Add($wasQuoted)
            }
        }

        if ($tokenList.Count -eq 0) {
            Write-Error 'Empty command'
            return
        }

        $rawFirstToken = $tokenList[0]      # Original token (may be alias) — preserved in raw_command_line
        $rawTokenLower = $rawFirstToken.ToLower()
        #endregion

        #region Step 2: Resolve alias -> canonical command_definition_id
        # The portal preserves the original alias in raw_command_line but uses the
        # canonical command_definition_id (e.g. raw: "ls", command_definition_id: "dir").
        $commandId = $rawTokenLower
        $cmdDef = $null

        if ($CommandDefinitions) {
            # First try direct match by command_definition_id
            $cmdDef = $CommandDefinitions | Where-Object { $_.command_definition_id -eq $commandId } | Select-Object -First 1

            if (-not $cmdDef) {
                # Try alias lookup across all definitions
                foreach ($def in $CommandDefinitions) {
                    if ($def.aliases) {
                        $aliasLower = @($def.aliases | ForEach-Object { "$_".ToLower() })
                        if ($commandId -in $aliasLower) {
                            # Ensure command_definition_id is always a scalar string.
                            # Guard against partial/malformed definitions where the field
                            # might be an array (member enumeration artefact).
                            $cid = $def.command_definition_id
                            $commandId = if ($cid -is [System.Collections.IEnumerable] -and $cid -isnot [string]) {
                                "$($cid | Select-Object -First 1)"
                            } else { "$cid" }
                            $cmdDef = $def
                            break
                        }
                    }
                }
            }
        }
        #endregion

        #region Step 3: Build lookup sets for known flags and params from the command definition
        $knownFlagIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $knownParamIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        if ($cmdDef) {
            if ($cmdDef.flags) {
                foreach ($f in $cmdDef.flags) {
                    $fid = if ($f -is [string]) { $f } elseif ($null -ne $f.flag_id) { $f.flag_id } elseif ($null -ne $f.id) { $f.id } else { $f.name }
                    if ($fid) { $null = $knownFlagIds.Add($fid) }
                }
            }
            if ($cmdDef.params) {
                foreach ($p in $cmdDef.params) {
                    if ($p.param_id) { $null = $knownParamIds.Add($p.param_id) }
                }
            }
        }
        #endregion

        #region Step 4: Parse remaining tokens into params, flags, and positionals
        # Rules (determined by command definition when available):
        #   -flagname           -> boolean flag if flagname is a known flag_id
        #   -paramname value    -> named param if paramname is a known param_id and a value follows
        #   -name value         -> named param (heuristic: next token doesn't start with -)
        #   -name               -> flag (heuristic: no value follows, or next token starts with -)
        #   value               -> positional
        $params = [System.Collections.Generic.List[hashtable]]::new()
        $flags = [System.Collections.Generic.List[string]]::new()
        $positional = [System.Collections.Generic.List[string]]::new()
        # Tracks -param value pairs for raw_command_line reconstruction
        $namedParamSpecs = [System.Collections.Generic.List[hashtable]]::new()

        $i = 1  # Start after the command name token
        while ($i -lt $tokenList.Count) {
            $token = $tokenList[$i]

            if ($token -match '^-(.+)$') {
                $nameWithoutDash = $Matches[1].ToLower()
                $nextIdx = $i + 1
                $hasNext = $nextIdx -lt $tokenList.Count
                $nextToken = if ($hasNext) { $tokenList[$nextIdx] } else { $null }
                # A quoted token is never a flag even if its unquoted content starts with '-'
                # (e.g. run script.ps1 -parameters "-processName Registry" should treat the
                # quoted value as the param value, not as a flag)
                $nextIsFlag = $nextToken -and $nextToken -match '^-' -and -not $tokenIsQuoted[$nextIdx]

                $isKnownFlag = $knownFlagIds.Contains($nameWithoutDash)
                $isKnownParam = $knownParamIds.Contains($nameWithoutDash)

                if ($isKnownFlag) {
                    # Definitively a boolean flag from command definition
                    $flags.Add($nameWithoutDash)
                    $i++
                } elseif ($isKnownParam -and $hasNext -and -not $nextIsFlag) {
                    # Definitively a named parameter with a value from command definition
                    $params.Add(@{ param_id = $nameWithoutDash; value = $nextToken })
                    $namedParamSpecs.Add(@{ param_id = $nameWithoutDash; value = $nextToken })
                    $i += 2
                } elseif (-not $isKnownFlag -and -not $isKnownParam -and $hasNext -and -not $nextIsFlag) {
                    # Unknown -name with a following non-flag value: treat as named param
                    # (e.g. -output json when cmdDef is unavailable)
                    $params.Add(@{ param_id = $nameWithoutDash; value = $nextToken })
                    $namedParamSpecs.Add(@{ param_id = $nameWithoutDash; value = $nextToken })
                    $i += 2
                } else {
                    # No following value, next token is also a flag, or standalone: treat as flag
                    $flags.Add($nameWithoutDash)
                    $i++
                }
            } else {
                $positional.Add($token)
                $i++
            }
        }
        #endregion

        #region Handle: library (REST API — not a Live Response session command)
        # 'library' has no command_definition_id; route to the module's library cmdlets instead.
        #   library              -> Get-XdrEndpointDeviceLiveResponseLibrary (list)
        #   library add <path>   -> New-XdrEndpointDeviceLiveResponseLibraryFile
        #   library delete <name>-> Remove-XdrEndpointDeviceLiveResponseLibraryFile
        if ($commandId -eq 'library') {
            $subCmd = if ($positional.Count -gt 0) { $positional[0].ToLower() } else { '' }
            $now = (Get-Date -Format 'o')
            $syntheticId = [System.Guid]::NewGuid().ToString()

            if ($subCmd -eq 'add') {
                $libFilePath = if ($positional.Count -gt 1) { $positional[1] } else { $null }
                if (-not $libFilePath) {
                    $errObj = [PSCustomObject]@{ message = "library add requires a file path: library add <path> [-Description <text>] [-HasParameters] [-ParametersDescription <text>] [-OverrideIfExists]" }
                    $r = [PSCustomObject]@{ command_id = $syntheticId; status = 2; completed_on = $now; errors = @($errObj); outputs = @() }
                    $r.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
                    return $r
                }
                $splatNew = @{ FilePath = $libFilePath }
                $descParam = $params | Where-Object { $_.param_id -eq 'description' } | Select-Object -First 1
                if ($descParam) { $splatNew['Description'] = $descParam.value }
                $pdParam = $params | Where-Object { $_.param_id -in 'parametersdescription', 'parameters_description' } | Select-Object -First 1
                if ($pdParam) { $splatNew['ParametersDescription'] = $pdParam.value }
                if ($flags -contains 'hasparameters')    { $splatNew['HasParameters']   = $true }
                if ($flags -contains 'overrideifexists') { $splatNew['OverrideIfExists'] = $true }
                try {
                    $uploadResult = New-XdrEndpointDeviceLiveResponseLibraryFile @splatNew
                    $r = [PSCustomObject]@{
                        command_id   = $syntheticId; status = 1; completed_on = $now; errors = @()
                        outputs      = @([PSCustomObject]@{ data_type = 'object'; data = $uploadResult })
                    }
                } catch {
                    $r = [PSCustomObject]@{ command_id = $syntheticId; status = 2; completed_on = $now
                        errors = @([PSCustomObject]@{ message = "$_" }); outputs = @() }
                }
                $r.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
                return $r

            } elseif ($subCmd -eq 'delete') {
                $libFileName = if ($positional.Count -gt 1) { $positional[1] } else { $null }
                if (-not $libFileName) {
                    $errObj = [PSCustomObject]@{ message = "library delete requires a file name: library delete <filename>" }
                    $r = [PSCustomObject]@{ command_id = $syntheticId; status = 2; completed_on = $now; errors = @($errObj); outputs = @() }
                    $r.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
                    return $r
                }
                try {
                    Remove-XdrEndpointDeviceLiveResponseLibraryFile -FileName $libFileName -Confirm:$false
                    $r = [PSCustomObject]@{
                        command_id   = $syntheticId; status = 1; completed_on = $now; errors = @()
                        outputs      = @([PSCustomObject]@{ data_type = 'string'; data = "Deleted '$libFileName' from Live Response library" })
                    }
                } catch {
                    $r = [PSCustomObject]@{ command_id = $syntheticId; status = 2; completed_on = $now
                        errors = @([PSCustomObject]@{ message = "$_" }); outputs = @() }
                }
                $r.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
                return $r

            } else {
                # No subcommand: list library files
                try {
                    $libFiles = Get-XdrEndpointDeviceLiveResponseLibrary
                    $r = [PSCustomObject]@{
                        command_id   = $syntheticId; status = 1; completed_on = $now; errors = @()
                        outputs      = @([PSCustomObject]@{ data_type = 'table'; data = if ($libFiles) { @($libFiles) } else { @() } })
                    }
                } catch {
                    $r = [PSCustomObject]@{ command_id = $syntheticId; status = 2; completed_on = $now
                        errors = @([PSCustomObject]@{ message = "$_" }); outputs = @() }
                }
                $r.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
                return $r
            }
        }
        #endregion

        #region Step 5: Map positional values to unfilled param_ids from the command definition
        if ($positional.Count -gt 0) {
            if ($cmdDef -and $cmdDef.params) {
                # Find params not already filled by -named value syntax
                $namedParamIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($np in $namedParamSpecs) { $null = $namedParamIds.Add($np.param_id) }

                # Guard: skip params with null param_id (malformed/partial definition) to
                # avoid ArgumentNullException from HashSet.Contains(null).
                # Also skip isHidden params (internal fields like pid on fileinfo) — the portal
                # skips these when mapping positional arguments, so we must do the same.
                $remainingParamDefs = @($cmdDef.params | Where-Object { $null -ne $_ -and $_.param_id -and -not $_.isHidden -and -not $namedParamIds.Contains($_.param_id) })
                for ($j = 0; $j -lt [Math]::Min($positional.Count, $remainingParamDefs.Count); $j++) {
                    $params.Add(@{ param_id = $remainingParamDefs[$j].param_id; value = $positional[$j] })
                }
            } elseif ($positional.Count -eq 1) {
                # Fallback: single positional -> 'path' (covers dir, fileinfo, getfile)
                $params.Add(@{ param_id = 'path'; value = $positional[0] })
            }
            # Multi-positional with no cmdDef: rely on server-side parsing of raw_command_line
        }
        #endregion

        #region Step 6: Build raw_command_line
        # Use the original user input as-is; rebuild only when a param value contains
        # unquoted spaces, which would cause "Inconsistency between raw command and
        # input parameters" on the server.
        $rawCommandLine = $Command.Trim()

        $needsRebuild = $false
        foreach ($p in $params) {
            if ($p.value -match '\s') {
                if (-not ($rawCommandLine -match [regex]::Escape("""$($p.value)""")) -and
                    -not ($rawCommandLine -match [regex]::Escape("'$($p.value)'"))) {
                    $needsRebuild = $true
                    break
                }
            }
        }

        if ($needsRebuild) {
            # Rebuild preserving the original alias, then positionals, named params, flags
            $parts = [System.Collections.Generic.List[string]]::new()
            $parts.Add($rawFirstToken)
            foreach ($pv in $positional) {
                $quotedPv = if ($pv -match '\s') { """$pv""" } else { $pv }
                $parts.Add($quotedPv)
            }
            foreach ($np in $namedParamSpecs) {
                $namedPart = if ($np.value -match '\s') { "-$($np.param_id) ""$($np.value)""" } else { "-$($np.param_id) $($np.value)" }
                $parts.Add($namedPart)
            }
            foreach ($f in $flags) { $parts.Add("-$f") }
            $rawCommandLine = $parts -join ' '
        }
        #endregion

        #region Step 7: Per-command timeout overrides
        # analyze can take several minutes for cloud lookups; findfile scans the whole disk
        $effectiveTimeout = switch ($commandId) {
            'analyze'  { [Math]::Max($TimeoutSeconds, 600) }
            'findfile' { [Math]::Max($TimeoutSeconds, 300) }
            default    { $TimeoutSeconds }
        }
        #endregion

        # Build the create command body
        $body = @{
            session_id            = $SessionId
            command_definition_id = $commandId
            params                = @($params)
            flags                 = @($flags)
            raw_command_line      = $rawCommandLine
            current_directory     = $CurrentDirectory
            background_mode       = [bool]$BackgroundMode
        } | ConvertTo-Json -Depth 10

        try {
            # Create the command
            $createUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/create_command?session_id=$SessionId&useV3Api=true"
            Write-Verbose "Sending Live Response command: $rawCommandLine (command_definition_id: $commandId, flags: [$($flags -join ', ')], params: $($params.Count))"
            $createResult = Invoke-RestMethod -Uri $createUri -Method Post -ContentType 'application/json' -Body $body -WebSession $script:session -Headers $script:headers

            $commandGuid = $createResult.command_id
            if (-not $commandGuid) {
                Write-Error 'Failed to create Live Response command - no command_id returned'
                return $createResult
            }

            Write-Verbose "Command created with ID: $commandGuid"

            # Poll for command completion
            $pollUri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/commands/${commandGuid}?session_id=$SessionId&useV2Api=false&useV3Api=true"
            $elapsed = 0
            $commandResult = $null

            while ($elapsed -lt $effectiveTimeout) {
                Start-Sleep -Seconds $PollIntervalSeconds
                $elapsed += $PollIntervalSeconds

                $commandResult = Invoke-RestMethod -Uri $pollUri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers

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

            Write-Warning "Command timed out after $effectiveTimeout seconds. Command ID: $commandGuid"
            if ($commandResult) {
                $commandResult.PSObject.TypeNames.Insert(0, 'XdrEndpointDeviceLiveResponseCommand')
                return $commandResult
            }
        } catch {
            Write-Error "Failed to execute Live Response command: $_"
        }
    }

    end {
    }
}
