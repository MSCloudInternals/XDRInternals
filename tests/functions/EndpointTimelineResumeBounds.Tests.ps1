[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Synthetic worker statusMap parameter retains the production runspace argument contract.')]
param()

Describe 'Endpoint timeline resume request bounds compatibility' {
    BeforeAll {
        function New-BoundsResumeFixture {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates only disposable test fixtures under TestDrive.')]
            [CmdletBinding()]
            [OutputType([hashtable])]
            param([string]$Root, [string]$State, [bool]$Published = $false, [bool]$Fractional = $true, [bool]$Versioned = $false)
            $root = Join-Path $Root ([guid]::NewGuid().ToString('N'))
            $null = New-Item $root -ItemType Directory
            $output = Join-Path $root 'timeline.ndjson'
            $null = New-Item "$output.parts" -ItemType Directory
            $from = [datetime]'2026-01-01T00:00:00.123Z'
            $to = if ($Fractional) { [datetime]'2026-01-01T01:00:00.9876543Z' } else { [datetime]'2026-01-01T01:00:00.987Z' }
            $chunk = InModuleScope XDRInternals -Parameters @{ From=$from; To=$to } { New-XdrEndpointTimelineExportChunk -FromDate $From -ToDate $To }
            $part = Join-Path "$output.parts" $chunk.FileName
            $old = "{`"Id`":`"prior-export`"}`n"
            # Hash-valid populated data can still have omitted a pre-fix boundary event.
            $data = "{`"Id`":`"retained-event`",`"Timestamp`":`"2026-01-01T00:30:00Z`"}`n"
            [IO.File]::WriteAllText($output, $old)
            $replacement = @{ FileBytes=(Get-Item $output).Length; FileSha256=(Get-FileHash $output).Hash }
            [IO.File]::WriteAllText($part, $data)
            [IO.File]::WriteAllText("$output.partial", $data)
            [IO.File]::WriteAllText("$output.manifest.json.partial", 'preserve pending manifest bytes')
            if ($Published) { [IO.File]::WriteAllText($output, $data) }
            $manifest = [ordered]@{
                SchemaVersion=1; State=$State; DeviceId=('a'*40); FromDateUtc=$from.ToString('o'); ToDateUtc=$to.ToString('o')
                IncludeSentinelEvents=$false; ChunkHours=4; PageSize=1000; Replacement=$replacement
                CreatedUtc=$from.ToString('o'); UpdatedUtc=$from.ToString('o'); Summary=$null
                Chunks=@(@{ Index=0; FromDateUtc=$from.ToString('o'); ToDateUtc=$to.ToString('o'); DurationTicks=($to-$from).Ticks
                    FileName=$chunk.FileName; Status='Completed'; EventCount=1; PageCount=1; RetryCount=0; AttemptCount=0
                    FileBytes=(Get-Item $part).Length; FileSha256=(Get-FileHash $part).Hash; MissingTimestampCount=0; BoundaryTimestampCount=0; ElapsedSeconds=0; Error=$null })
            }
            if ($Versioned) { $manifest.RequestBoundsVersion=1 }
            if ($State -eq 'Finalizing') {
                $manifest.Summary=@{ EventCount=1; PageCount=1; RetryCount=0; ChunkRestartCount=0; FileBytes=(Get-Item $part).Length
                    FileSha256=(Get-FileHash $part).Hash; MissingTimestampCount=0; BoundaryTimestampCount=0; ResumedChunkCount=1; PartsRetained=$true; MergeSeconds=0; ElapsedSeconds=0; CompletedUtc=$null }
            }
            [IO.File]::WriteAllText("$output.manifest.json", ($manifest | ConvertTo-Json -Depth 16))
            @{ Root=$root; Output=$output; Data=$data; Part=$part; Manifest=$manifest
                Arguments=@{ DeviceId=('a'*40); FromDate=$from; ToDate=$to; Path=$output } }
        }
    }
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $script:session=[Microsoft.PowerShell.Commands.WebRequestSession]::new(); $script:headers=@{}
        }
        Mock New-XdrEndpointTimelineExportWorker { return { throw 'Hash-valid completed parts must not be recollected in compatibility controls' } } -ModuleName XDRInternals
    }
    It 'rejects legacy fractional <State> state (published=<Published>) before changing artifacts' -ForEach @(
        @{ State='InProgress'; Published=$false }; @{ State='Failed'; Published=$false }
        @{ State='Finalizing'; Published=$false }; @{ State='Finalizing'; Published=$true }
    ) {
        $fixture=New-BoundsResumeFixture -Root $TestDrive -State $State -Published $Published
        $hashes=@{}; foreach ($file in Get-ChildItem $fixture.Root -File -Recurse) { $hashes[$file.FullName]=(Get-FileHash $file.FullName).Hash }
        $arguments=$fixture.Arguments
        { Export-XdrEndpointDeviceTimeline @arguments } | Should -Throw '*request bounds*Use -Force*'
        foreach ($path in $hashes.Keys) { (Get-FileHash $path -ErrorAction Stop).Hash | Should -Be $hashes[$path] }
        @(Get-ChildItem $fixture.Root -File -Recurse) | Should -HaveCount $hashes.Count
        Should -Invoke New-XdrEndpointTimelineExportWorker -Times 0 -Exactly -ModuleName XDRInternals
    }
    It 'resumes <Kind> <State> state (published=<Published>) without recollection' -ForEach @(
        foreach ($kind in @('new fractional', 'legacy exact millisecond')) {
            foreach ($case in @(@{ State='InProgress'; Published=$false },@{ State='Failed'; Published=$false },@{ State='Finalizing'; Published=$false },@{ State='Finalizing'; Published=$true })) {
                @{ Kind=$kind; State=$case.State; Published=$case.Published }
            }
        }
    ) {
        $new=$Kind -eq 'new fractional'
        $fixture=New-BoundsResumeFixture -Root $TestDrive -State $State -Published $Published -Fractional $new -Versioned $new
        $arguments=$fixture.Arguments
        $summary=Export-XdrEndpointDeviceTimeline @arguments
        $summary.ResumedChunks | Should -Be 1
        $summary.TotalEvents | Should -Be 1
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.Data
        (Get-Content "$($fixture.Output).manifest.json" -Raw | ConvertFrom-Json).State | Should -Be Complete
    }
    It 'rejects <_> without changing legacy artifacts' -ForEach @('unknown bounds version','fractional internal chunk bounds') {
        $fixture=New-BoundsResumeFixture -Root $TestDrive -State InProgress -Fractional $false
        if ($_ -eq 'unknown bounds version') { $fixture.Manifest.RequestBoundsVersion=99 } else { $fixture.Manifest.Chunks[0].ToDateUtc='2026-01-01T01:00:00.9876543Z' }
        [IO.File]::WriteAllText("$($fixture.Output).manifest.json", ($fixture.Manifest | ConvertTo-Json -Depth 16))
        $before=@{}; foreach ($file in Get-ChildItem $fixture.Root -File -Recurse) { $before[$file.FullName]=(Get-FileHash $file.FullName).Hash }
        $arguments=$fixture.Arguments
        { Export-XdrEndpointDeviceTimeline @arguments } | Should -Throw '*request bounds*Use -Force*'
        foreach ($path in $before.Keys) { (Get-FileHash $path -ErrorAction Stop).Hash | Should -Be $before[$path] }
    }
    It 'records request bounds version on a fresh fractional Force export' {
        $fixture=New-BoundsResumeFixture -Root $TestDrive -State Failed
        Mock New-XdrEndpointTimelineExportWorker {
            return {
                param($chunk,$sharedParameters,$statusMap)
                $part=Join-Path $sharedParameters.PartsPath $chunk.FileName
                [IO.File]::WriteAllText($part,"{`"Id`":`"fresh-boundary-event`",`"Timestamp`":`"2026-01-01T01:00:00.9875000Z`"}`n")
                [pscustomobject]@{ Success=$true; ChunkIndex=$chunk.Index; EventCount=1; PageCount=1; RetryCount=0; FileBytes=(Get-Item $part).Length; FileSha256=(Get-FileHash $part).Hash; MissingTimestampCount=0; BoundaryTimestampCount=0; ElapsedSeconds=0 }
            }
        } -ModuleName XDRInternals
        $arguments=$fixture.Arguments
        $summary=Export-XdrEndpointDeviceTimeline @arguments -Force
        $summary.ResumedChunks | Should -Be 0
        (Get-Content "$($fixture.Output).manifest.json" -Raw | ConvertFrom-Json).RequestBoundsVersion | Should -Be 1
        (Get-Content $fixture.Output -Raw | ConvertFrom-Json).Id | Should -Be 'fresh-boundary-event'
    }
}
