BeforeAll {
    $script:OriginalTimelineDefinition = (Get-Command Get-XdrIdentityUserTimeline).ScriptBlock.ToString()
    # Replace only the remote worker and timing/branch seams. The actual planning,
    # coordinators, reconciliation, merge and publication execute in both branches.
    $script:SyntheticWorker = @'
            $chunkProcessingScript = {
                param($chunk, $userIds, $baseParams, $tempPath, $cookieInfo, $headerInfo, $baseUrl)
                $scenario = '__SCENARIO__'
                $index = [int]$chunk.Index
                if ($scenario -eq 'caught retry') {
                    try { Write-Error 'Synthetic retryable attempt' -ErrorAction Stop } catch { }
                }
                if ($scenario -eq 'uncaught error' -and $index -eq 1) { Write-Error 'Synthetic uncaught worker error' -ErrorAction Continue }
                if ($scenario -eq 'empty') { return }
                if ($index -eq 1) {
                    if ($scenario -eq 'missing') { return }
                    if ($scenario -eq 'failed') { throw 'Synthetic terminal worker failure' }
                    if ($scenario -in @('timeout', 'stall')) { Start-Sleep -Seconds 8; return }
                    if ($scenario -eq 'explicit failure') { return @{ ChunkIndex = 1; Success = $false; Error = 'Synthetic failure' } }
                }
                $events = @([pscustomobject]@{ EventId = "event-$index"; Timestamp = $chunk.FromDate.AddMinutes(30).ToString('o') })
                if ($scenario -eq 'successful empty') { $events = @() }
                $path = Join-Path $tempPath ('chunk_{0:D4}_{1:yyyyMMdd}_{2:yyyyMMdd}.json' -f $index, $chunk.FromDate, $chunk.ToDate)
                $data = @{ ChunkIndex = $index; FromDate = $chunk.FromDate.ToString('o'); ToDate = $chunk.ToDate.ToString('o'); EventCount = $events.Count; Events = $events }
                if ($scenario -eq 'wrong metadata' -and $index -eq 1) { $data.ChunkIndex = 99 }
                if ($scenario -ne 'missing file' -or $index -ne 1) {
                    $data | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path
                }
                if ($scenario -eq 'rogue file' -and $index -eq 0) {
                    @{ ChunkIndex = 99; Events = @(@{ EventId = 'rogue'; Timestamp = $chunk.FromDate.AddMinutes(15).ToString('o') }) } |
                        ConvertTo-Json -Depth 10 | Set-Content (Join-Path $tempPath 'chunk_0099_rogue.json')
                }
                $result = @{ ChunkIndex = $index; FilePath = $path; EventCount = $events.Count; FromDate = $chunk.FromDate; ToDate = $chunk.ToDate; Success = $true; ElapsedSeconds = 0.1; FileSizeKB = 1 }
                $result
                if ($scenario -eq 'duplicate' -and $index -eq 1) { $result }
            }
'@
}

Describe 'Identity timeline planned chunk completeness' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrIdentityHeaders { @{} } -ModuleName XDRInternals
        Mock Get-XdrIdentityUser { [pscustomobject]@{ displayName = 'Synthetic'; ids = [pscustomobject]@{ upn = 'synthetic@example.invalid' } } } -ModuleName XDRInternals
        Mock Invoke-RestMethod { throw 'Unexpected transport' } -ModuleName XDRInternals
        Mock Invoke-WebRequest { throw 'Unexpected transport' } -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
        }
    }
    AfterEach {
        InModuleScope XDRInternals -Parameters @{ Definition = $script:OriginalTimelineDefinition } {
            param($Definition)
            Set-Item Function:script:Get-XdrIdentityUserTimeline ([scriptblock]::Create($Definition))
        }
    }

    It '<Branch> handles <Scenario> with AllowPartial=<Partial>' -ForEach @(
        foreach ($branch in @('ThreadJob', 'Runspace')) {
            foreach ($scenario in @('missing', 'empty', 'duplicate', 'failed', 'timeout', 'stall', 'explicit failure', 'missing file', 'wrong metadata', 'rogue file', 'complete', 'successful empty', 'caught retry', 'uncaught error', 'coordinator error')) {
                if ($branch -eq 'Runspace' -and $scenario -eq 'coordinator error') { continue }
                foreach ($partial in @($false, $true)) {
                    @{ Branch = $branch; Scenario = $scenario; Partial = $partial }
                }
            }
        }
    ) {
        $worker = $script:SyntheticWorker.Replace('__SCENARIO__', $Scenario)
        $ast = [scriptblock]::Create($script:OriginalTimelineDefinition).Ast
        $assignments = @($ast.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $node.Left.VariablePath.UserPath -eq 'chunkProcessingScript'
        }, $true))
        $assignments | Should -HaveCount 1
        $definition = $script:OriginalTimelineDefinition.Replace($assignments[0].Extent.Text, $worker.Trim())
        if ($Branch -eq 'Runspace') {
            $definition = $definition.Replace('if ($PSVersionTable.PSVersion.Major -ge 7)', 'if ($false)')
        }
        if ($Scenario -eq 'coordinator error') {
            $definition = $definition.Replace('                } -ArgumentList $dateChunks', "                    Write-Error 'Synthetic coordinator error' -ErrorAction Continue`n                } -ArgumentList `$dateChunks")
        }
        # Accelerate genuine coordinator timeout paths without changing decisions.
        if ($Scenario -eq 'timeout') { $definition = $definition.Replace('$operationStartTime.Elapsed.TotalSeconds -gt $TimeoutSeconds', '$operationStartTime.Elapsed.TotalSeconds -gt 2') }
        if ($Scenario -eq 'stall') { $definition = $definition.Replace('$StallTimeoutSeconds = 120', '$StallTimeoutSeconds = 1') }
        InModuleScope XDRInternals -Parameters @{ Definition = $definition } {
            param($Definition)
            Set-Item Function:script:Get-XdrIdentityUserTimeline ([scriptblock]::Create($Definition))
        }
        $export = Join-Path $TestDrive 'output.json'
        Set-Content $export 'original destination bytes'
        $parameters = @{ Upn = 'synthetic@example.invalid'; FromDate = [datetime]'2026-01-01T00:00:00Z'; ToDate = [datetime]'2026-01-01T02:00:00Z'; ChunkSizeHours = 1; ThrottleLimit = 2; OutputPath = $TestDrive; ExportPath = $export; AllowPartial = $Partial; ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
        $observed = [System.Collections.Generic.List[object]]::new(); $failure = $null; $warnings = @()
        try { & (Get-Module XDRInternals) { [CmdletBinding()] param($p) Get-XdrIdentityUserTimeline @p } $parameters -WarningVariable +warnings 6>$null | ForEach-Object { $observed.Add($_) } } catch { $failure = $_ }
        $result = @($observed.ToArray())
        if (-not $Partial -and $Scenario -notin @('complete', 'rogue file', 'successful empty', 'caught retry')) {
            $failure | Should -Not -BeNullOrEmpty
            $result | Should -HaveCount 0
            (Get-Content $export -Raw).Trim() | Should -Be 'original destination bytes'
        } else {
            $failure | Should -BeNullOrEmpty -Because ([string]$failure.ScriptStackTrace)
            $expected = if ($Scenario -in @('empty', 'successful empty')) { 0 } elseif ($Scenario -in @('complete', 'rogue file', 'caught retry', 'coordinator error')) { 2 } else { 1 }
            $result | Should -HaveCount $expected
            @($result.EventId) | Should -Not -Contain 'rogue'
            if ($expected -eq 1) { $result[0].EventId | Should -Be 'event-0' }
            if ($Partial -and $Scenario -notin @('complete', 'rogue file', 'successful empty', 'caught retry')) { $warnings.Count | Should -BeGreaterThan 0 }
        }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 0 -Exactly
    }
}
