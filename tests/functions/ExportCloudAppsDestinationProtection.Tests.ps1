Describe 'Export-XdrCloudAppsActivityTimeline orchestration' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
        }
        Mock New-XdrCloudAppsActivityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                [void]$statusMap
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                [System.IO.File]::WriteAllText($filePath, "{`"chunk`":$([int]$chunk.Index)}`n", [System.Text.UTF8Encoding]::new($false))
                [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; ExpectedEventCount = 1L
                    CountIsLowerBound = $false; PageCount = 1; RetryCount = 0; RewindCount = 0
                    FileBytes = (Get-Item $filePath).Length; FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant()
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01
                    Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals
    }



    It 'rejects an unrelated destination on publishing resume' -ForEach @(
        @{ ReplaceExisting = $false; Identity = $false },
        @{ ReplaceExisting = $true; Identity = $false },
        @{ ReplaceExisting = $true; Identity = $true }
    ) {
        $from = [datetime]'2026-01-01T00:00:00Z'
        $outputPath = Join-Path $TestDrive "resume-protected-$ReplaceExisting-$Identity.ndjson"
        $null = Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath
        $manifestPath = "$outputPath.manifest.json"
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
        $manifest.State = 'Publishing'
        $manifest.ReplaceExisting = $ReplaceExisting
        if ($Identity) {
            $manifest.Replacement = @{ FileBytes = (Get-Item $outputPath).Length; FileSha256 = (Get-FileHash $outputPath).Hash.ToLowerInvariant() }
        }
        [System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 30))
        [System.IO.File]::Move($outputPath, "$outputPath.partial")
        [System.IO.File]::WriteAllText($outputPath, 'unrelated caller-owned output')
        { Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath } |
            Should -Throw -ExpectedMessage '*not match an authorized replacement*'
        [System.IO.File]::ReadAllText($outputPath) | Should -Be 'unrelated caller-owned output'
        Test-Path -LiteralPath "$outputPath.partial" | Should -BeTrue
    }

    It 'publishes a forced replacement and records its prior identity' {
        $from = [datetime]'2026-01-01T00:00:00Z'
        $outputPath = Join-Path $TestDrive 'authorized.ndjson'
        [System.IO.File]::WriteAllText($outputPath, 'authorized prior output')
        $priorHash = (Get-FileHash $outputPath).Hash.ToLowerInvariant()
        $null = Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath -Force
        $manifest = Get-Content -LiteralPath "$outputPath.manifest.json" -Raw | ConvertFrom-Json -AsHashtable
        $manifest.ReplaceExisting | Should -BeTrue
        $manifest.Replacement.FileSha256 | Should -Be $priorHash
        [System.IO.File]::ReadAllText($outputPath) | Should -Be "{`"chunk`":0}`n"
        $manifest.State = 'Publishing'
        [System.IO.File]::Move($outputPath, "$outputPath.partial")
        [System.IO.File]::WriteAllText($outputPath, 'authorized prior output')
        [System.IO.File]::WriteAllText("$outputPath.manifest.json", ($manifest | ConvertTo-Json -Depth 30))
        $null = Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath
        [System.IO.File]::ReadAllText($outputPath) | Should -Be "{`"chunk`":0}`n"
    }

    It 'preserves a destination changed during collection with Force=<ForceReplacement>' -ForEach @(
        @{ ForceReplacement = $false }, @{ ForceReplacement = $true }
    ) {
        Mock New-XdrCloudAppsActivityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                [System.IO.File]::WriteAllText($filePath, "{`"chunk`":0}`n")
                $finalPath = $sharedParameters.PartsPath.Substring(0, $sharedParameters.PartsPath.Length - '.parts'.Length)
                [System.IO.File]::WriteAllText($finalPath, 'changed during collection')
                [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; ExpectedEventCount = 1L
                    CountIsLowerBound = $false; PageCount = 1; RetryCount = 0; RewindCount = 0
                    FileBytes = (Get-Item $filePath).Length; FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant()
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01
                    Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals
        $from = [datetime]'2026-01-01T00:00:00Z'
        $outputPath = Join-Path $TestDrive "collection-protected-$ForceReplacement.ndjson"
        if ($ForceReplacement) { [System.IO.File]::WriteAllText($outputPath, 'authorized prior output') }
        { Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath -Force:$ForceReplacement } |
            Should -Throw -ExpectedMessage '*not match an authorized replacement*'
        [System.IO.File]::ReadAllText($outputPath) | Should -Be 'changed during collection'
    }
}
