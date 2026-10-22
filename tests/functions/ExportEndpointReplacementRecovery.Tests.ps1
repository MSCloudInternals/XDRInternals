Describe 'Interrupted endpoint timeline replacement recovery' {
    BeforeAll {
        function New-ReplacementRecoveryFixture {
            param([string]$Root, [string]$State = 'Failed', [bool]$ReplacementMetadata = $true)
            $Root = Join-Path $Root ([guid]::NewGuid().ToString('N'))
            $null = New-Item $Root -ItemType Directory
            $output = Join-Path $Root 'replacement.ndjson'
            $parts = "$output.parts"
            $null = New-Item $parts -ItemType Directory
            $from = [datetime]'2026-01-01T00:00:00Z'
            $to = $from.AddHours(1)
            $chunk = InModuleScope XDRInternals -Parameters @{ From = $from; To = $to } {
                New-XdrEndpointTimelineExportChunk -FromDate $From -ToDate $To
            }
            $part = Join-Path $parts $chunk.FileName
            $old = "{`"id`":`"A`"}`n"
            $new = "{`"id`":`"B`"}`n"
            [IO.File]::WriteAllText($output, $old)
            [IO.File]::WriteAllText($part, $new)
            $hash = (Get-FileHash $part).Hash.ToLowerInvariant()
            $manifest = [ordered]@{
                SchemaVersion = 1; State = $State; DeviceId = ('a' * 40)
                FromDateUtc = $from.ToString('o'); ToDateUtc = $to.ToString('o')
                IncludeSentinelEvents = $false; ChunkHours = 4; PageSize = 1000
                Ordering = 'NewestTimeWindowFirst;ApiEventOrderPreserved'
                CreatedUtc = $from.ToString('o'); UpdatedUtc = $from.ToString('o'); Summary = $null
                Chunks = @([ordered]@{
                    Index = 0; FromDateUtc = $from.ToString('o'); ToDateUtc = $to.ToString('o')
                    DurationTicks = ($to - $from).Ticks; FileName = $chunk.FileName; Status = 'Completed'
                    EventCount = 1; PageCount = 1; RetryCount = 0; AttemptCount = 0
                    FileBytes = (Get-Item $part).Length; FileSha256 = $hash
                    MissingTimestampCount = 0; BoundaryTimestampCount = 0; ElapsedSeconds = 0; Error = $null
                })
            }
            if ($ReplacementMetadata) {
                $manifest.Replacement = @{ FileBytes = (Get-Item $output).Length; FileSha256 = (Get-FileHash $output).Hash.ToLowerInvariant() }
            }
            if ($State -eq 'Finalizing') {
                $merged = InModuleScope XDRInternals -Parameters @{ Part = $part; Hash = $hash; Destination = "$output.partial" } {
                    Merge-XdrEndpointTimelineNdjsonPart -Part @([pscustomobject]@{ FilePath = $Part; FileSha256 = $Hash; EventCount = 1 }) -DestinationPath $Destination
                }
                $manifest.Summary = @{
                    EventCount = 1; PageCount = 1; RetryCount = 0; ChunkRestartCount = 0
                    FileBytes = $merged.FileBytes; FileSha256 = $merged.FileSha256
                    MissingTimestampCount = 0; BoundaryTimestampCount = 0; ResumedChunkCount = 1
                    PartsRetained = $true; MergeSeconds = 0; ElapsedSeconds = 0; CompletedUtc = $null
                }
            }
            [IO.File]::WriteAllText("$output.manifest.json", ($manifest | ConvertTo-Json -Depth 16))
            @{ Output = $output; Part = $part; Old = $old; New = $new; Manifest = $manifest
                Arguments = @{ DeviceId = ('a' * 40); FromDate = $from; ToDate = $to; Path = $output } }
        }
    }

    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
            $script:ReplacementRealMerge = (Get-Command Merge-XdrEndpointTimelineNdjsonPart).ScriptBlock
        }
        Mock New-XdrEndpointTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                $output = $sharedParameters.PartsPath -replace '\.parts$', ''
                if ([IO.File]::ReadAllText($output) -ne "{`"id`":`"A`"}`n") { throw 'Old destination changed during collection' }
                [IO.File]::AppendAllText("$output.worker-calls", 'called;')
                $part = Join-Path $sharedParameters.PartsPath $chunk.FileName
                [IO.File]::WriteAllText($part, "{`"id`":`"B`"}`n")
                [pscustomobject]@{
                    Success = $true; ChunkIndex = $chunk.Index; EventCount = 1; PageCount = 1
                    FileBytes = (Get-Item $part).Length; FileSha256 = (Get-FileHash $part).Hash.ToLowerInvariant()
                    MissingTimestampCount = 0; BoundaryTimestampCount = 0; ElapsedSeconds = 0; RetryCount = 0
                }
            }
        } -ModuleName XDRInternals
    }

    It 'resumes authorized replacement parts from <State> while preserving the prior destination until publication' -ForEach @(
        @{ State = 'InProgress' }; @{ State = 'Failed' }; @{ State = 'Finalizing' }
    ) {
        $fixture = New-ReplacementRecoveryFixture -Root $TestDrive -State $State
        $arguments = $fixture.Arguments
        $summary = Export-XdrEndpointDeviceTimeline @arguments
        $summary.ResumedChunks | Should -Be 1
        Test-Path "$($fixture.Output).worker-calls" | Should -BeFalse
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.New
        (Get-Content "$($fixture.Output).manifest.json" -Raw | ConvertFrom-Json).State | Should -Be 'Complete'
    }

    It 'resumes an early Finalizing replacement before publication metadata was written' {
        $fixture = New-ReplacementRecoveryFixture -Root $TestDrive -State Finalizing
        $fixture.Manifest.Summary = $null
        [IO.File]::WriteAllText("$($fixture.Output).manifest.json", ($fixture.Manifest | ConvertTo-Json -Depth 16))
        $arguments = $fixture.Arguments
        $summary = Export-XdrEndpointDeviceTimeline @arguments
        $summary.ResumedChunks | Should -Be 1
        Test-Path "$($fixture.Output).worker-calls" | Should -BeFalse
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.New
    }

    It 'recovers an already published replacement without collection' {
        $fixture = New-ReplacementRecoveryFixture -Root $TestDrive -State Finalizing
        [IO.File]::WriteAllText($fixture.Output, $fixture.New)
        $arguments = $fixture.Arguments
        $summary = Export-XdrEndpointDeviceTimeline @arguments
        $summary.FileSha256 | Should -Be (Get-FileHash $fixture.Output).Hash.ToLowerInvariant()
        Should -Invoke New-XdrEndpointTimelineExportWorker -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'rejects an unrelated destination even when it has the recorded size' {
        $fixture = New-ReplacementRecoveryFixture -Root $TestDrive
        $changed = "{`"id`":`"C`"}`n"
        [IO.File]::WriteAllText($fixture.Output, $changed)
        $arguments = $fixture.Arguments
        { Export-XdrEndpointDeviceTimeline @arguments } | Should -Throw '*Use -Force*'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $changed
        [IO.File]::ReadAllText($fixture.Part) | Should -BeExactly $fixture.New
        Should -Invoke New-XdrEndpointTimelineExportWorker -ModuleName XDRInternals -Times 0 -Exactly
    }

    It 'does not infer replacement permission from a legacy <State> manifest' -ForEach @(
        @{ State = 'Failed' }; @{ State = 'Finalizing' }
    ) {
        $fixture = New-ReplacementRecoveryFixture -Root $TestDrive -State $State -ReplacementMetadata $false
        $arguments = $fixture.Arguments
        { Export-XdrEndpointDeviceTimeline @arguments } | Should -Throw '*Use -Force*'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.Old
        Test-Path $fixture.Part | Should -BeTrue
    }

    It 'rejects an incompatible request despite replacement metadata' {
        $fixture = New-ReplacementRecoveryFixture -Root $TestDrive
        $arguments = $fixture.Arguments
        $arguments.DeviceId = 'b' * 40
        { Export-XdrEndpointDeviceTimeline @arguments } | Should -Throw '*does not match this request*'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.Old
    }

    It 'preserves the old destination and reusable parts when merging fails' {
        $fixture = New-ReplacementRecoveryFixture -Root $TestDrive
        Mock Merge-XdrEndpointTimelineNdjsonPart { throw 'Synthetic merge failure' } -ModuleName XDRInternals
        $arguments = $fixture.Arguments
        { Export-XdrEndpointDeviceTimeline @arguments } | Should -Throw '*Synthetic merge failure*'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.Old
        [IO.File]::ReadAllText($fixture.Part) | Should -BeExactly $fixture.New
        Test-Path "$($fixture.Output).worker-calls" | Should -BeFalse
    }

    It 'validates completed parts before reuse and recollects a corrupt part' {
        $fixture = New-ReplacementRecoveryFixture -Root $TestDrive
        [IO.File]::WriteAllText($fixture.Part, 'corrupt')
        $arguments = $fixture.Arguments
        $summary = Export-XdrEndpointDeviceTimeline @arguments
        $summary.ResumedChunks | Should -Be 0
        [IO.File]::ReadAllText("$($fixture.Output).worker-calls") | Should -BeExactly 'called;'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.New
    }

    It 'keeps Force as a fresh start and records prior output identity for the next resume' {
        $fixture = New-ReplacementRecoveryFixture -Root $TestDrive
        $priorHash = (Get-FileHash $fixture.Output).Hash.ToLowerInvariant()
        $arguments = $fixture.Arguments
        $summary = Export-XdrEndpointDeviceTimeline @arguments -Force
        $summary.ResumedChunks | Should -Be 0
        [IO.File]::ReadAllText("$($fixture.Output).worker-calls") | Should -BeExactly 'called;'
        $manifest = Get-Content "$($fixture.Output).manifest.json" -Raw | ConvertFrom-Json
        $manifest.Replacement.FileSha256 | Should -Be $priorHash
        $manifest.Replacement.FileBytes | Should -Be 11
    }

    It 'rechecks the prior destination immediately before publishing a resumed replacement' {
        $fixture = New-ReplacementRecoveryFixture -Root $TestDrive
        Mock Merge-XdrEndpointTimelineNdjsonPart {
            param($Part, $DestinationPath)
            InModuleScope XDRInternals -Parameters @{ Parts = $Part; Destination = $DestinationPath } {
                $merged = & $script:ReplacementRealMerge -Part $Parts -DestinationPath $Destination
                [IO.File]::WriteAllText(($Destination -replace '\.partial$', ''), "{`"id`":`"C`"}`n")
                $merged
            }
        } -ModuleName XDRInternals
        $arguments = $fixture.Arguments
        { Export-XdrEndpointDeviceTimeline @arguments } | Should -Throw '*destination changed during replacement recovery*'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly "{`"id`":`"C`"}`n"
        Test-Path $fixture.Part | Should -BeTrue
        Test-Path "$($fixture.Output).partial" | Should -BeTrue
    }
    It 'resumes populated replacement after killing the exporter during <Phase>' -ForEach @(
        @{ Phase = 'collection' }; @{ Phase = 'finalizing' }
    ) {
        $root = Join-Path $TestDrive $Phase
        $null = New-Item $root -ItemType Directory
        $output = Join-Path $root 'export.ndjson'
        $old = "{`"Id`":`"prior-export`"}`n"
        [IO.File]::WriteAllText($output, $old, [Text.UTF8Encoding]::new($false))
        $priorHash = (Get-FileHash $output).Hash
        $manifestPath = (Get-Module XDRInternals).ModuleBase | Join-Path -ChildPath 'XDRInternals.psd1'
        $childScript = Join-Path $root 'export-child.ps1'
        $childSource = @'
param([string]$ManifestPath, [string]$Root, [string]$Phase, [switch]$Resume)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function global:Invoke-RestMethod { throw 'OFFLINE child transport blocked' }
function global:Invoke-WebRequest { throw 'OFFLINE child transport blocked' }
$m = Import-Module $ManifestPath -Force -PassThru
if ($m.ModuleBase -ne (Split-Path $ManifestPath -Parent)) { throw 'Wrong child module' }
& $m {
    param($Root, $Phase, $Resume)
    function script:Update-XdrConnectionSettings {}
    $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $script:headers = @{}
    function script:New-XdrEndpointTimelineExportWorker {
        return {
            param($chunk, $sharedParameters, $statusMap)
            $root = Split-Path $sharedParameters.PartsPath -Parent
            [IO.File]::AppendAllText((Join-Path $root "calls-$($chunk.Index).txt"), "called`n")
            if ($chunk.Index -eq 1 -and (Test-Path (Join-Path $root 'hold-collection'))) {
                [IO.File]::WriteAllText((Join-Path $root 'worker-blocked'), 'ready')
                while ($true) { Start-Sleep -Milliseconds 50 }
            }
            $part = Join-Path $sharedParameters.PartsPath $chunk.FileName
            $text = "{`"Id`":`"chunk-$($chunk.Index)-first`"}`n{`"Id`":`"chunk-$($chunk.Index)-second`"}`n"
            [IO.File]::WriteAllText($part, $text, [Text.UTF8Encoding]::new($false))
            [pscustomobject]@{
                Success = $true; ChunkIndex = $chunk.Index; EventCount = 2; PageCount = 1
                FileBytes = (Get-Item $part).Length; FileSha256 = (Get-FileHash $part).Hash.ToLowerInvariant()
                MissingTimestampCount = 0; BoundaryTimestampCount = 0; ElapsedSeconds = 0; RetryCount = 0
            }
        }
    }
    if (-not $Resume -and $Phase -eq 'finalizing') {
        $script:InterruptionRealMerge = (Get-Command Merge-XdrEndpointTimelineNdjsonPart).ScriptBlock
        function script:Merge-XdrEndpointTimelineNdjsonPart {
            param($Part, $DestinationPath)
            $result = & $script:InterruptionRealMerge -Part $Part -DestinationPath $DestinationPath
            [IO.File]::WriteAllText((Join-Path (Split-Path $DestinationPath -Parent) 'merge-blocked'), 'ready')
            while ($true) { Start-Sleep -Milliseconds 50 }
            $result
        }
    }
} $Root $Phase ([bool]$Resume)
$args = @{ DeviceId = ('a' * 40); FromDate = [datetime]'2026-01-01T00:00:00Z'; ToDate = [datetime]'2026-01-01T08:00:00Z'; Path = (Join-Path $Root 'export.ndjson') }
if (-not $Resume) { $args.Force = $true }
$summary = Export-XdrEndpointDeviceTimeline @args 6>$null
$summary | ConvertTo-Json | Set-Content (Join-Path $Root 'summary.json')
'@
        [IO.File]::WriteAllText($childScript, $childSource, [Text.UTF8Encoding]::new($true))
        if ($Phase -eq 'collection') { [IO.File]::WriteAllText((Join-Path $root 'hold-collection'), 'hold') }
        $start = [Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh'))
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        foreach ($argument in @('-NonInteractive', '-NoProfile', '-File', $childScript, '-ManifestPath', $manifestPath, '-Root', $root, '-Phase', $Phase)) {
            $start.ArgumentList.Add($argument)
        }
        $child = [Diagnostics.Process]::Start($start)
        try {
            $deadline = [datetime]::UtcNow.AddSeconds(20)
            $ready = $false
            do {
                if ($child.HasExited) { throw "Exporter exited before interruption: $($child.StandardError.ReadToEnd())" }
                try {
                    $checkpoint = Get-Content "$output.manifest.json" -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    $completed = @($checkpoint.Chunks | Where-Object Status -eq 'Completed')
                    $ready = if ($Phase -eq 'collection') {
                        $checkpoint.State -eq 'InProgress' -and $completed.Count -eq 1 -and (Test-Path (Join-Path $root 'worker-blocked'))
                    } else {
                        $checkpoint.State -eq 'Finalizing' -and $completed.Count -eq 2 -and (Test-Path (Join-Path $root 'merge-blocked'))
                    }
                } catch { $ready = $false }
                if (-not $ready) { Start-Sleep -Milliseconds 50 }
            } while (-not $ready -and [datetime]::UtcNow -lt $deadline)
            $ready | Should -BeTrue -Because 'a real exporter checkpoint must precede process termination'
            $completed.Count | Should -BeGreaterThan 0
            $checkpoint.Replacement.FileSha256 | Should -Be $priorHash.ToLowerInvariant()
            foreach ($part in $completed) {
                (Get-FileHash (Join-Path "$output.parts" $part.FileName)).Hash.ToLowerInvariant() | Should -Be $part.FileSha256
                $part.EventCount | Should -Be 2
            }
            (Get-FileHash $output).Hash | Should -Be $priorHash
            $child.Kill($true)
            $child.WaitForExit(5000) | Should -BeTrue
            $child.ExitCode | Should -Not -Be 0
            (Get-FileHash $output).Hash | Should -Be $priorHash
        } finally {
            if (-not $child.HasExited) { $child.Kill($true); $null = $child.WaitForExit(5000) }
            $child.Dispose()
        }
        $hold = Join-Path $root 'hold-collection'
        if (Test-Path $hold) { Remove-Item -LiteralPath $hold }
        $start.ArgumentList.Add('-Resume')
        $resumed = [Diagnostics.Process]::Start($start)
        try {
            $resumed.WaitForExit(20000) | Should -BeTrue
            $resumed.ExitCode | Should -Be 0 -Because $resumed.StandardError.ReadToEnd()
        } finally {
            if (-not $resumed.HasExited) { $resumed.Kill($true); $null = $resumed.WaitForExit(5000) }
            $resumed.Dispose()
        }
        $summary = Get-Content (Join-Path $root 'summary.json') -Raw | ConvertFrom-Json
        $summary.ResumedChunks | Should -Be $completed.Count
        $summary.TotalEvents | Should -Be 4
        $expected = "{`"Id`":`"chunk-0-first`"}`n{`"Id`":`"chunk-0-second`"}`n{`"Id`":`"chunk-1-first`"}`n{`"Id`":`"chunk-1-second`"}`n"
        [IO.File]::ReadAllText($output) | Should -BeExactly $expected
        $summary.FileSha256 | Should -Be (Get-FileHash $output).Hash.ToLowerInvariant()
        @(Get-Content (Join-Path $root 'calls-0.txt')) | Should -HaveCount 1
        @(Get-Content (Join-Path $root 'calls-1.txt')) | Should -HaveCount $(if ($Phase -eq 'collection') { 2 } else { 1 })
        (Get-Content "$output.manifest.json" -Raw | ConvertFrom-Json).State | Should -Be 'Complete'
        Test-Path "$output.parts" | Should -BeFalse
        Test-Path "$output.partial" | Should -BeFalse
    }

}
