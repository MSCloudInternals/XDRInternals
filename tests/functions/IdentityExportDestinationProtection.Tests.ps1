Describe 'Identity export destination protection' {
    BeforeAll {
        function New-IdentityDestinationFixture {
            param([string]$Root, [string]$State, [bool]$Replacement = $true, [string]$Destination = 'A')
            $root = Join-Path $Root ([guid]::NewGuid().ToString('N'))
            $null = New-Item $root -ItemType Directory
            $output = Join-Path $root 'identity.ndjson'
            $parts = "$output.parts"
            $null = New-Item $parts -ItemType Directory
            $old = "{`"id`":`"A`"}`n"; $new = "{`"id`":`"B`"}`n"; $changed = "{`"id`":`"C`"}`n"
            $part = Join-Path $parts 'chunk_0000.ndjson'
            [IO.File]::WriteAllText($part, $new)
            if ($Destination -ne 'Missing') { [IO.File]::WriteAllText($output, $(if ($Destination -eq 'A') { $old } else { $changed })) }
            $oldHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($old))).ToLowerInvariant()
            $newHash = (Get-FileHash $part).Hash.ToLowerInvariant()
            $ids = [ordered]@{ aad = '11111111-1111-1111-1111-111111111111'; upn = 'user@contoso.com' } | ConvertTo-Json -Compress
            $fingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($ids))).ToLowerInvariant()
            $from = [datetime]'2026-01-01T00:00:00Z'; $to = $from.AddHours(1)
            $manifest = [ordered]@{
                SchemaVersion = 2; State = $State; IdentityFingerprint = $fingerprint; IdentitySelector = 'Upn'
                FromDateUtc = $from.ToString('o'); ToDateUtc = $to.ToString('o'); ChunkHours = 12; PageSize = 1000
                PaginationStrategy = 'TimestampKeysetV2'; CanonicalizationVersion = 2; Ordering = 'NewestTimeWindowFirst;ApiTimestampDescending'
                ReplaceExisting = $Replacement; CreatedUtc = $from.ToString('o'); UpdatedUtc = $from.ToString('o'); Summary = $null
                Replacement = $(if ($Replacement) { @{ FileBytes = [Text.Encoding]::UTF8.GetByteCount($old); FileSha256 = $oldHash } } else { $null })
                Chunks = @(@{
                    Index = 0; FromDateUtc = $from.ToString('o'); ToDateUtc = $to.ToString('o'); DurationTicks = ($to - $from).Ticks
                    FileName = 'chunk_0000.ndjson'; Status = 'Completed'; EventCount = 1; PageCount = 1; RetryCount = 0
                    RewindCount = 0; AttemptCount = 0; FileBytes = (Get-Item $part).Length; FileSha256 = $newHash
                    MissingTimestampCount = 0; BoundaryTimestampCount = 0; ElapsedSeconds = 0; Error = $null; DuplicateRepresentationCount = 0
                })
            }
            if ($State -eq 'Publishing') {
                [IO.File]::WriteAllText("$output.partial", $new)
                $manifest.Summary = @{
                    EventCount = 1; PageCount = 1; RetryCount = 0; ChunkRestartCount = 0; PaginationRewindCount = 0
                    FileBytes = (Get-Item $part).Length; FileSha256 = $newHash; MissingTimestampCount = 0; BoundaryTimestampCount = 0
                    DuplicateRepresentationCount = 0; MergeSeconds = 0; ElapsedSeconds = 0; PartsRetained = $true
                }
            }
            [IO.File]::WriteAllText("$output.manifest.json", ($manifest | ConvertTo-Json -Depth 20))
            @{ Output = $output; Part = $part; Old = $old; New = $new; Changed = $changed; Manifest = $manifest
                Arguments = @{ Upn = 'user@contoso.com'; FromDate = $from; ToDate = $to; Path = $output } }
        }
    }
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrIdentityHeaders { @{} } -ModuleName XDRInternals
        Mock Get-XdrIdentityUser { [pscustomobject]@{ ids = [pscustomobject]@{ aad = '11111111-1111-1111-1111-111111111111'; upn = 'user@contoso.com' } } } -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new(); $script:headers = @{}
            $script:DestinationRealMerge = (Get-Command Merge-XdrTimelineNdjsonPart).ScriptBlock
        }
        Mock New-XdrIdentityTimelineExportWorker {
            return { throw 'Completed fixture must not be recollected' }
        } -ModuleName XDRInternals
    }
    It 'preserves <Kind> destination on <State> resume without Force' -ForEach @(
        foreach ($state in @('InProgress', 'Failed', 'Publishing')) {
            foreach ($kind in @('newly appeared', 'same-size changed replacement', 'legacy replacement without fingerprint')) {
                @{ State = $state; Kind = $kind }
            }
        }
    ) {
        $fixture = New-IdentityDestinationFixture -Root $TestDrive -State $State -Replacement ($Kind -ne 'newly appeared') -Destination C
        if ($Kind -eq 'legacy replacement without fingerprint') {
            $fixture.Manifest.Replacement = $null
            [IO.File]::WriteAllText("$($fixture.Output).manifest.json", ($fixture.Manifest | ConvertTo-Json -Depth 20))
        }
        $beforeManifest = [IO.File]::ReadAllText("$($fixture.Output).manifest.json")
        $arguments = $fixture.Arguments
        { Export-XdrIdentityUserTimeline @arguments } | Should -Throw '*destination*'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.Changed
        [IO.File]::ReadAllText($fixture.Part) | Should -BeExactly $fixture.New
        [IO.File]::ReadAllText("$($fixture.Output).manifest.json") | Should -BeExactly $beforeManifest
        if ($State -eq 'Publishing') { [IO.File]::ReadAllText("$($fixture.Output).partial") | Should -BeExactly $fixture.New }
    }
    It 'resumes a valid authorized replacement in <State> without recollection' -ForEach @(
        @{ State = 'InProgress' }; @{ State = 'Failed' }; @{ State = 'Publishing' }
    ) {
        $fixture = New-IdentityDestinationFixture -Root $TestDrive -State $State
        $arguments = $fixture.Arguments
        $result = Export-XdrIdentityUserTimeline @arguments
        $result.ResumedChunks | Should -Be 1
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.New
        (Get-Content "$($fixture.Output).manifest.json" -Raw | ConvertFrom-Json).State | Should -Be 'Complete'
    }
    It 'rechecks the destination after merging before normal publication' {
        $fixture = New-IdentityDestinationFixture -Root $TestDrive -State Failed
        Mock Merge-XdrTimelineNdjsonPart {
            param($Part, $DestinationPath)
            InModuleScope XDRInternals -Parameters @{ Part = $Part; DestinationPath = $DestinationPath } {
                $result = & $script:DestinationRealMerge -Part $Part -DestinationPath $DestinationPath
                [IO.File]::WriteAllText(($DestinationPath -replace '\.partial$', ''), "{`"id`":`"C`"}`n")
                $result
            }
        } -ModuleName XDRInternals
        $arguments = $fixture.Arguments
        { Export-XdrIdentityUserTimeline @arguments } | Should -Throw '*destination*'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.Changed
        [IO.File]::ReadAllText($fixture.Part) | Should -BeExactly $fixture.New
        [IO.File]::ReadAllText("$($fixture.Output).partial") | Should -BeExactly $fixture.New
    }
    It 'rechecks the destination after validating a Publishing partial' {
        $fixture = New-IdentityDestinationFixture -Root $TestDrive -State Publishing
        $script:PartialHash = (Get-FileHash "$($fixture.Output).partial").Hash
        Mock Get-FileHash {
            param($LiteralPath, $Algorithm)
            Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm
        } -ModuleName XDRInternals
        Mock Get-FileHash {
            param($LiteralPath)
            [IO.File]::WriteAllText(($LiteralPath -replace '\.partial$', ''), "{`"id`":`"C`"}`n")
            [pscustomobject]@{ Hash = $script:PartialHash }
        } -ModuleName XDRInternals -ParameterFilter { $LiteralPath -like '*.partial' }
        $arguments = $fixture.Arguments
        { Export-XdrIdentityUserTimeline @arguments } | Should -Throw '*destination*'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.Changed
        [IO.File]::ReadAllText($fixture.Part) | Should -BeExactly $fixture.New
        [IO.File]::ReadAllText("$($fixture.Output).partial") | Should -BeExactly $fixture.New
    }
    It 'does not overwrite a destination that appeared during a fresh export' {
        $fixture = New-IdentityDestinationFixture -Root $TestDrive -State Failed -Replacement $false -Destination Missing
        Remove-Item -LiteralPath "$($fixture.Output).manifest.json"
        Mock New-XdrIdentityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                $part = Join-Path $sharedParameters.PartsPath $chunk.FileName
                [IO.File]::WriteAllText($part, "{`"id`":`"B`"}`n")
                [pscustomobject]@{ Success = $true; ChunkIndex = $chunk.Index; EventCount = 1; PageCount = 1; RetryCount = 0; RewindCount = 0; FileBytes = (Get-Item $part).Length; FileSha256 = (Get-FileHash $part).Hash.ToLowerInvariant(); MissingTimestampCount = 0; BoundaryTimestampCount = 0; DuplicateRepresentationCount = 0; ElapsedSeconds = 0 }
            }
        } -ModuleName XDRInternals
        Mock Merge-XdrTimelineNdjsonPart {
            param($Part, $DestinationPath)
            InModuleScope XDRInternals -Parameters @{ Part = $Part; DestinationPath = $DestinationPath } {
                $result = & $script:DestinationRealMerge -Part $Part -DestinationPath $DestinationPath
                [IO.File]::WriteAllText(($DestinationPath -replace '\.partial$', ''), "{`"id`":`"C`"}`n")
                $result
            }
        } -ModuleName XDRInternals
        $arguments = $fixture.Arguments
        { Export-XdrIdentityUserTimeline @arguments } | Should -Throw '*destination*'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.Changed
        Test-Path "$($fixture.Output).parts" | Should -BeTrue
        Test-Path "$($fixture.Output).partial" | Should -BeTrue
    }
    It 'records authorization during Force and resumes completed parts after a failed replacement' {
        $fixture = New-IdentityDestinationFixture -Root $TestDrive -State Failed
        $arguments = $fixture.Arguments
        $arguments.ToDate = $arguments.FromDate.AddDays(1)
        $oldHash = (Get-FileHash $fixture.Output).Hash.ToLowerInvariant()
        Mock New-XdrIdentityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                if ($chunk.Index -eq 1) {
                    return [pscustomobject]@{ Success = $false; ChunkIndex = 1; EventCount = 0; PageCount = 0; RetryCount = 0; RewindCount = 0; DuplicateRepresentationCount = 0; ElapsedSeconds = 0; Error = 'synthetic interruption'; FailureClass = 'PermanentHttp' }
                }
                $part = Join-Path $sharedParameters.PartsPath $chunk.FileName
                [IO.File]::WriteAllText($part, "{`"id`":`"B`"}`n")
                [pscustomobject]@{ Success = $true; ChunkIndex = $chunk.Index; EventCount = 1; PageCount = 1; RetryCount = 0; RewindCount = 0; FileBytes = (Get-Item $part).Length; FileSha256 = (Get-FileHash $part).Hash.ToLowerInvariant(); MissingTimestampCount = 0; BoundaryTimestampCount = 0; DuplicateRepresentationCount = 0; ElapsedSeconds = 0 }
            }
        } -ModuleName XDRInternals
        { Export-XdrIdentityUserTimeline @arguments -Force } | Should -Throw '*preserved for resume*'
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly $fixture.Old
        $manifest = Get-Content "$($fixture.Output).manifest.json" -Raw | ConvertFrom-Json
        $manifest.ReplaceExisting | Should -BeTrue
        $manifest.Replacement.FileSha256 | Should -Be $oldHash
        $manifest.Replacement.FileBytes | Should -Be 11
        @($manifest.Chunks | Where-Object Status -eq 'Completed') | Should -HaveCount 1
        Mock New-XdrIdentityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                if ($chunk.Index -eq 0) { throw 'Completed replacement part was recollected' }
                $part = Join-Path $sharedParameters.PartsPath $chunk.FileName
                [IO.File]::WriteAllText($part, "{`"id`":`"B`"}`n")
                [pscustomobject]@{ Success = $true; ChunkIndex = $chunk.Index; EventCount = 1; PageCount = 1; RetryCount = 0; RewindCount = 0; FileBytes = (Get-Item $part).Length; FileSha256 = (Get-FileHash $part).Hash.ToLowerInvariant(); MissingTimestampCount = 0; BoundaryTimestampCount = 0; DuplicateRepresentationCount = 0; ElapsedSeconds = 0 }
            }
        } -ModuleName XDRInternals
        $summary = Export-XdrIdentityUserTimeline @arguments
        $summary.ResumedChunks | Should -Be 1
        $summary.TotalEvents | Should -Be 2
        [IO.File]::ReadAllText($fixture.Output) | Should -BeExactly ($fixture.New + $fixture.New)
    }

}
