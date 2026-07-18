Describe 'Export-XdrEndpointDeviceTimeline' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
        }
        $script:DeviceId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        $script:FromDate = [datetime]'2026-01-01T00:00:00Z'
        $script:ToDate = [datetime]'2026-01-01T09:00:00Z'
    }

    It 'keeps the public parameter surface intentionally small' {
        $command = Get-Command Export-XdrEndpointDeviceTimeline
        $publicParameters = @($command.Parameters.Keys | Where-Object { $_ -notin [System.Management.Automation.PSCmdlet]::CommonParameters -and $_ -notin [System.Management.Automation.PSCmdlet]::OptionalCommonParameters })

        $publicParameters | Sort-Object | Should -Be @('DeviceId', 'Force', 'FromDate', 'IncludeSentinelEvents', 'Path', 'ToDate')
    }

    It 'plans adjacent newest-first four-hour chunks' {
        InModuleScope XDRInternals -Parameters @{ FromDate = $script:FromDate; ToDate = $script:ToDate } {
            $chunks = @(New-XdrEndpointTimelineExportChunk -FromDate $FromDate -ToDate $ToDate)

            $chunks.Count | Should -Be 3
            $chunks[0].FromDate.ToString('o') | Should -Be '2026-01-01T05:00:00.0000000Z'
            $chunks[0].ToDate.ToString('o') | Should -Be '2026-01-01T09:00:00.0000000Z'
            $chunks[1].FromDate | Should -Be $chunks[2].ToDate
            $chunks[1].ToDate | Should -Be $chunks[0].FromDate
            $chunks[2].FromDate | Should -Be $FromDate.ToUniversalTime()
        }
    }

    It 'concatenates parts exactly and validates their hashes' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $firstPath = Join-Path $TestRoot 'first.ndjson'
            $secondPath = Join-Path $TestRoot 'second.ndjson'
            $destinationPath = Join-Path $TestRoot 'combined.ndjson'
            [System.IO.File]::WriteAllText($firstPath, "{`"id`":2}`n", [System.Text.UTF8Encoding]::new($false))
            [System.IO.File]::WriteAllText($secondPath, "{`"id`":1}`n", [System.Text.UTF8Encoding]::new($false))
            $parts = @(
                [PSCustomObject]@{ FilePath = $firstPath; FileSha256 = (Get-FileHash -LiteralPath $firstPath).Hash.ToLowerInvariant(); EventCount = 1 },
                [PSCustomObject]@{ FilePath = $secondPath; FileSha256 = (Get-FileHash -LiteralPath $secondPath).Hash.ToLowerInvariant(); EventCount = 1 }
            )

            $result = Merge-XdrEndpointTimelineNdjsonPart -Part $parts -DestinationPath $destinationPath

            [System.IO.File]::ReadAllText($destinationPath) | Should -Be "{`"id`":2}`n{`"id`":1}`n"
            $result.EventCount | Should -Be 2
            $result.FileSha256 | Should -Be (Get-FileHash -LiteralPath $destinationPath).Hash.ToLowerInvariant()
        }
    }

    It 'rejects a part whose bytes do not match its recorded hash' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $partPath = Join-Path $TestRoot 'changed.ndjson'
            $destinationPath = Join-Path $TestRoot 'invalid-combined.ndjson'
            [System.IO.File]::WriteAllText($partPath, "{`"id`":1}`n", [System.Text.UTF8Encoding]::new($false))
            $parts = @([PSCustomObject]@{ FilePath = $partPath; FileSha256 = ('0' * 64); EventCount = 1 })

            { Merge-XdrEndpointTimelineNdjsonPart -Part $parts -DestinationPath $destinationPath } | Should -Throw -ExpectedMessage '*failed SHA-256 validation*'
        }
    }

    It 'follows Prev, ignores Next, and writes one NDJSON record per event' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive; DeviceId = $script:DeviceId } {
            $script:WorkerCall = 0
            $script:RequestedUris = [System.Collections.Generic.List[string]]::new()
            $script:WorkerResponses = @(
                [PSCustomObject]@{
                    Items = @([PSCustomObject]@{ ActionTimeIsoString = '2026-01-01T01:30:00Z'; ActionType = 'Newest'; Id = 2 })
                    PartialResponseReasons = @()
                    Prev = '/machines/device/events/?cursor=older'
                    Next = '/machines/device/events/?cursor=must-not-follow'
                },
                [PSCustomObject]@{
                    Items = @([PSCustomObject]@{ ActionTimeIsoString = '2026-01-01T00:30:00Z'; ActionType = 'Older'; Id = 1 })
                    PartialResponseReasons = @()
                    Prev = $null
                    Next = '/machines/device/events/?cursor=must-not-follow'
                }
            )
            Mock Invoke-RestMethod {
                param($Uri)
                $script:RequestedUris.Add([string]$Uri)
                $response = $script:WorkerResponses[$script:WorkerCall]
                $script:WorkerCall++
                return $response
            }

            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = [PSCustomObject]@{
                Index = 0
                FromDate = [datetime]'2026-01-01T00:00:00Z'
                ToDate = [datetime]'2026-01-01T02:00:00Z'
                FileName = 'worker.ndjson'
            }
            $shared = @{
                PartsPath = $TestRoot
                BaseUrl = 'https://security.microsoft.com'
                DeviceId = $DeviceId
                CookieData = @()
                HeadersData = @{}
                PageSize = 1000
                IncludeSentinelEvents = $false
                MaxPagesPerChunk = 10
                MaxRetries = 1
                RequestTimeoutSeconds = 30
            }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status
            $lines = @(Get-Content -LiteralPath $result.FilePath)

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 2
            $result.PageCount | Should -Be 2
            $lines.Count | Should -Be 2
            ($lines[0] | ConvertFrom-Json).Id | Should -Be 2
            ($lines[1] | ConvertFrom-Json).Id | Should -Be 1
            $script:RequestedUris.Count | Should -Be 2
            $script:RequestedUris[1] | Should -BeLike '*cursor=older*'
            ($script:RequestedUris -join "`n") | Should -Not -BeLike '*must-not-follow*'
        }
    }

    It 'uses half-open intervals to prevent duplicate boundary events' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive; DeviceId = $script:DeviceId } {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    Items = @(
                        [PSCustomObject]@{ ActionTimeIsoString = '2026-01-01T00:00:00Z'; Id = 'included-lower' },
                        [PSCustomObject]@{ ActionTimeIsoString = '2026-01-01T01:00:00Z'; Id = 'excluded-upper' }
                    )
                    PartialResponseReasons = @()
                    Prev = $null
                    Next = $null
                }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; FileName = 'boundaries.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; DeviceId = $DeviceId; CookieData = @(); HeadersData = @{}; PageSize = 1000; IncludeSentinelEvents = $false; MaxPagesPerChunk = 10; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status
            $lines = @(Get-Content -LiteralPath $result.FilePath)

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 1
            $result.BoundaryTimestampCount | Should -Be 2
            $lines.Count | Should -Be 1
            ($lines[0] | ConvertFrom-Json).Id | Should -Be 'included-lower'
        }
    }

    It 'fails closed when an event has no parseable timestamp' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive; DeviceId = $script:DeviceId } {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{ Items = @([PSCustomObject]@{ ActionTimeIsoString = 'not-a-date'; Id = 1 }); PartialResponseReasons = @(); Prev = $null; Next = $null }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; FileName = 'missing-time.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; DeviceId = $DeviceId; CookieData = @(); HeadersData = @{}; PageSize = 1000; IncludeSentinelEvents = $false; MaxPagesPerChunk = 10; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.MissingTimestampCount | Should -Be 1
            $result.Error | Should -BeLike '*without a parseable timestamp*'
            Test-Path -LiteralPath (Join-Path $TestRoot 'missing-time.ndjson') | Should -BeFalse
        }
    }

    It 'does not publish output when the API reports partial data' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive; DeviceId = $script:DeviceId } {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{
                    Items = @()
                    PartialResponseReasons = @('backend timeout')
                    Prev = $null
                    Next = $null
                }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; FileName = 'partial.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; DeviceId = $DeviceId; CookieData = @(); HeadersData = @{}; PageSize = 1000; IncludeSentinelEvents = $false; MaxPagesPerChunk = 10; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.Error | Should -BeLike '*partial API response*'
            Test-Path -LiteralPath (Join-Path $TestRoot 'partial.ndjson') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $TestRoot 'partial.ndjson.partial') | Should -BeFalse
        }
    }

    It 'retries a partial API response before accepting the page' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive; DeviceId = $script:DeviceId } {
            $script:PartialRetryCall = 0
            Mock Start-Sleep {}
            Mock Invoke-RestMethod {
                $script:PartialRetryCall++
                if ($script:PartialRetryCall -eq 1) {
                    return [PSCustomObject]@{ Items = @(); PartialResponseReasons = @('6'); Prev = $null; Next = $null }
                }
                return [PSCustomObject]@{
                    Items = @([PSCustomObject]@{ ActionTimeIsoString = '2026-01-01T00:30:00Z'; ActionType = 'Recovered'; Id = 1 })
                    PartialResponseReasons = @()
                    Prev = $null
                    Next = $null
                }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; FileName = 'retried.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; DeviceId = $DeviceId; CookieData = @(); HeadersData = @{}; PageSize = 1000; IncludeSentinelEvents = $false; MaxPagesPerChunk = 10; MaxRetries = 2; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 1
            $result.PageCount | Should -Be 1
            $result.RetryCount | Should -Be 1
            Should -Invoke Invoke-RestMethod -Times 2 -Exactly
            Should -Invoke Start-Sleep -Times 1 -Exactly
        }
    }

    It 'restarts a partial window with a fresh request context' {
        Mock New-XdrEndpointTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                if ([int]$chunk.Attempt -eq 0) {
                    return [PSCustomObject]@{
                        Success = $false; ChunkIndex = [int]$chunk.Index; EventCount = 250L; PageCount = 1
                        FileBytes = 0L; FileSha256 = $null; RetryCount = 1
                        MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01
                        Error = 'simulated poisoned cursor'; FailureClass = 'PartialResponse'
                    }
                }

                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                $line = "{`"attempt`":$([int]$chunk.Attempt)}`n"
                [System.IO.File]::WriteAllText($filePath, $line, [System.Text.UTF8Encoding]::new($false))
                return [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; PageCount = 1
                    FileBytes = (Get-Item -LiteralPath $filePath).Length
                    FileSha256 = (Get-FileHash -LiteralPath $filePath).Hash.ToLowerInvariant(); RetryCount = 0
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01
                    Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'fresh-context.ndjson'

        $result = Export-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:FromDate.AddHours(1) -Path $outputPath
        $manifest = Get-Content -LiteralPath "$outputPath.manifest.json" -Raw | ConvertFrom-Json

        $result.TotalEvents | Should -Be 1
        $result.TotalRetries | Should -Be 1
        $result.TotalChunkRestarts | Should -Be 1
        (Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json).attempt | Should -Be 1
        $manifest.Summary.ChunkRestartCount | Should -Be 1
        Test-Path -LiteralPath "$outputPath.parts" | Should -BeFalse
    }

    It 'publishes a validated export and removes successful temporary parts' {
        Mock New-XdrEndpointTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                $line = [string]::Format('{{"chunk":{0},"time":"{1}"}}{2}', [int]$chunk.Index, ([datetime]$chunk.ToDate).ToUniversalTime().ToString('o'), "`n")
                [System.IO.File]::WriteAllText($filePath, $line, [System.Text.UTF8Encoding]::new($false))
                [PSCustomObject]@{
                    Success = $true
                    ChunkIndex = [int]$chunk.Index
                    EventCount = 1L
                    PageCount = 1
                    FileBytes = (Get-Item -LiteralPath $filePath).Length
                    FileSha256 = (Get-FileHash -LiteralPath $filePath).Hash.ToLowerInvariant()
                    MissingTimestampCount = 0L
                    BoundaryTimestampCount = 0L
                    ElapsedSeconds = 0.01
                    Error = $null
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'timeline.ndjson'
        $sevenDayToDate = $script:FromDate.AddDays(7)

        $result = Export-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $sevenDayToDate -Path $outputPath
        $lines = @(Get-Content -LiteralPath $outputPath)
        $manifest = Get-Content -LiteralPath "$outputPath.manifest.json" -Raw | ConvertFrom-Json

        $result.TotalEvents | Should -Be 42
        $result.TotalPages | Should -Be 42
        $result.TotalChunks | Should -Be 42
        $result.FileSha256 | Should -Be (Get-FileHash -LiteralPath $outputPath).Hash.ToLowerInvariant()
        @($lines | ForEach-Object { ($_ | ConvertFrom-Json).chunk }) | Should -Be @(0..41)
        $manifest.State | Should -Be 'Complete'
        $manifest.Summary.PartsRetained | Should -BeFalse
        Test-Path -LiteralPath "$outputPath.parts" | Should -BeFalse
    }

    It 'resumes validated chunks after a failed run' {
        $script:FailOneChunk = $true
        Mock New-XdrEndpointTimelineExportWorker {
            if ($script:FailOneChunk) {
                return {
                    param($chunk, $sharedParameters, $statusMap)
                    if ([int]$chunk.Index -eq 1) {
                        return [PSCustomObject]@{
                            Success = $false; ChunkIndex = 1; EventCount = 0L; PageCount = 0; FileBytes = 0L; FileSha256 = $null
                            MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = 'simulated interruption'
                        }
                    }
                    $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                    $line = [string]::Format('{{"chunk":{0}}}{1}', [int]$chunk.Index, "`n")
                    [System.IO.File]::WriteAllText($filePath, $line, [System.Text.UTF8Encoding]::new($false))
                    return [PSCustomObject]@{
                        Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; PageCount = 1
                        FileBytes = (Get-Item -LiteralPath $filePath).Length
                        FileSha256 = (Get-FileHash -LiteralPath $filePath).Hash.ToLowerInvariant()
                        MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = $null
                    }
                }
            }

            return {
                param($chunk, $sharedParameters, $statusMap)
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                $line = [string]::Format('{{"chunk":{0}}}{1}', [int]$chunk.Index, "`n")
                [System.IO.File]::WriteAllText($filePath, $line, [System.Text.UTF8Encoding]::new($false))
                return [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; PageCount = 1
                    FileBytes = (Get-Item -LiteralPath $filePath).Length
                    FileSha256 = (Get-FileHash -LiteralPath $filePath).Hash.ToLowerInvariant()
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = $null
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'resumed.ndjson'

        { Export-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -Path $outputPath } | Should -Throw -ExpectedMessage '*preserved for resume*'
        Test-Path -LiteralPath $outputPath | Should -BeFalse
        Test-Path -LiteralPath "$outputPath.parts" | Should -BeTrue

        $script:FailOneChunk = $false
        $result = Export-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -Path $outputPath

        $result.ResumedChunks | Should -Be 2
        $result.TotalEvents | Should -Be 3
        Test-Path -LiteralPath $outputPath | Should -BeTrue
        Test-Path -LiteralPath "$outputPath.parts" | Should -BeFalse
    }
}
