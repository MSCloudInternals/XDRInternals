Describe 'Timeline architecture helpers' {
    It 'keeps public timeline files limited to their primary public cmdlet' {
        $publicTimelineFiles = Get-ChildItem -Path (Join-Path $PSScriptRoot '..\..\XDRInternals\functions') -Filter 'Get-Xdr*Timeline.ps1'

        foreach ($file in $publicTimelineFiles) {
            $functionNames = @(Select-String -Path $file.FullName -Pattern '^function\s+([A-Za-z0-9-]+)' | ForEach-Object { $_.Matches[0].Groups[1].Value })

            $functionNames.Count | Should -Be 1 -Because "$($file.Name) should not contain injected private helpers"
            $functionNames[0] | Should -Be $file.BaseName
        }
    }

    It 'keeps ExportPath explicit while accepting OutputPath for compatibility' {
        $command = Get-Command Get-XdrEndpointDeviceTimeline

        $command.Parameters.ContainsKey('ExportPath') | Should -BeTrue
        $command.Parameters.ContainsKey('OutputPath') | Should -BeTrue
        $command.Parameters.ContainsKey('WorkingDirectory') | Should -BeTrue
        $command.Parameters.ContainsKey('ExportFormat') | Should -BeTrue
        $command.Parameters.ContainsKey('AllowPartial') | Should -BeTrue
        $command.Parameters.ContainsKey('ManifestPath') | Should -BeTrue
        $command.Parameters.ContainsKey('RequestTimeoutSeconds') | Should -BeTrue
        $command.Parameters.ContainsKey('DiagnosticsPath') | Should -BeTrue
        $command.Parameters.ContainsKey('PaginationDelayMinMilliseconds') | Should -BeTrue
        $command.Parameters.ContainsKey('PaginationDelayMaxMilliseconds') | Should -BeTrue
        $command.Parameters['OutputPath'].Aliases | Should -Not -Contain 'ExportPath'
    }

    It 'validates LastNDays range before execution' {
        {
            Get-XdrEndpointDeviceTimeline -DeviceId ('a' * 40) -LastNDays 0
        } | Should -Throw '*LastNDays*'
    }

    It 'plans fixed and balanced timeline chunks' {
        InModuleScope XDRInternals {
            $fixed = @(New-XdrTimelineChunkPlan -FromDate ([datetime]'2026-05-10T00:00:00Z') -ToDate ([datetime]'2026-05-10T05:00:00Z') -ChunkHours 2)
            $balanced = @(New-XdrTimelineChunkPlan -FromDate ([datetime]'2026-05-10T00:00:00Z') -ToDate ([datetime]'2026-05-11T00:00:00Z') -ChunkHours 4 -TargetChunkCount 6)
            $minutes = @(New-XdrTimelineChunkPlan -FromDate ([datetime]'2026-05-10T00:00:00Z') -ToDate ([datetime]'2026-05-10T01:00:00Z') -ChunkMinutes 15)

            $fixed.Count | Should -Be 3
            $fixed[0].Index | Should -Be 0
            $fixed[2].ToDate | Should -Be ([datetime]'2026-05-10T05:00:00Z')
            $balanced.Count | Should -Be 6
            $balanced[0].Strategy | Should -Be 'TargetChunkCount:6'
            $minutes.Count | Should -Be 4
            $minutes[0].ChunkMinutes | Should -Be 15
            $minutes[1].FromDate | Should -Be ([datetime]'2026-05-10T00:15:00Z')
        }
    }

    It 'prefers Next continuation paths and can explicitly use backward mode' {
        InModuleScope XDRInternals {
            $responseWithBoth = [pscustomobject]@{
                Next = '/machines/example/events?page=2'
                Prev = '/machines/example/events?page=1'
            }
            $responseWithPrevOnly = [pscustomobject]@{
                Prev = '/machines/example/events?page=1'
            }

            (Get-XdrEndpointTimelineContinuationPath -Response $responseWithBoth) | Should -Be '/machines/example/events?page=2'
            (Get-XdrEndpointTimelineContinuationPath -Response $responseWithBoth -Direction Backward) | Should -Be '/machines/example/events?page=1'
            (Get-XdrEndpointTimelineContinuationPath -Response $responseWithPrevOnly) | Should -Be '/machines/example/events?page=1'
        }
    }

    It 'builds continuation URIs from Next links first' {
        InModuleScope XDRInternals {
            $relativeResponse = [pscustomobject]@{ Next = '/machines/example/events?page=2' }
            $absoluteResponse = [pscustomobject]@{ Next = 'https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/example/events?page=2' }

            (Get-XdrEndpointTimelineNextUri -BaseUrl 'https://security.microsoft.com' -Response $relativeResponse) |
                Should -Be 'https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/example/events?page=2'
            (Get-XdrEndpointTimelineNextUri -BaseUrl 'https://security.microsoft.com' -Response $absoluteResponse) |
                Should -Be 'https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/example/events?page=2'
        }
    }

    It 'matches event types across ActionType Type and EventType properties' {
        InModuleScope XDRInternals {
            (Test-XdrEndpointTimelineEventTypeMatch -TimelineEvent ([pscustomobject]@{ ActionType = 'ProcessCreated' }) -EventType 'Process*') | Should -BeTrue
            (Test-XdrEndpointTimelineEventTypeMatch -TimelineEvent ([pscustomobject]@{ Type = 'NetworkConnection' }) -EventType 'Network*') | Should -BeTrue
            (Test-XdrEndpointTimelineEventTypeMatch -TimelineEvent ([pscustomobject]@{ EventType = 'FileCreated' }) -EventType 'Process*') | Should -BeFalse
        }
    }

    It 'resolves ExportPath OutputPath and WorkingDirectory compatibility' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            param($TestRoot)

            $fileLike = Resolve-XdrEndpointTimelineOutputTarget -OutputPath (Join-Path $TestRoot 'events.ndjson')
            $directoryLike = Resolve-XdrEndpointTimelineOutputTarget -OutputPath (Join-Path $TestRoot 'chunks')
            $explicit = Resolve-XdrEndpointTimelineOutputTarget -OutputPath (Join-Path $TestRoot 'legacy') -WorkingDirectory (Join-Path $TestRoot 'work') -WarningAction SilentlyContinue

            $fileLike.ExportPath | Should -Be (Join-Path $TestRoot 'events.ndjson')
            $directoryLike.WorkingDirectory | Should -Be (Join-Path $TestRoot 'chunks')
            $explicit.WorkingDirectory | Should -Be (Join-Path $TestRoot 'work')
        }
    }

    It 'reads timeline chunk files and skips unreadable ones when partial data is allowed' {
        $chunkPath = Join-Path $TestDrive 'chunk_bad.json'
        Set-Content -Path $chunkPath -Value '{"Events":[{"EventType":"ProcessCreated"}' -Encoding UTF8

        InModuleScope XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            $result = Read-XdrTimelineChunkFile -File (Get-Item -Path $ChunkPath) -AllowPartial -WarningAction SilentlyContinue

            $result | Should -BeNullOrEmpty
        }
    }

    It 'extracts raw event JSON from chunk envelopes' {
        $chunkPath = Join-Path $TestDrive 'chunk_good.json'
        Set-Content -Path $chunkPath -Value '{"ChunkIndex":0,"Events":[{"EventType":"ProcessCreated"},{"EventType":"NetworkConnection"}],"EventCount":2}' -Encoding UTF8

        InModuleScope XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            $result = Get-XdrTimelineChunkEventsJson -File (Get-Item -Path $ChunkPath)

            $result | Should -Be '{"EventType":"ProcessCreated"},{"EventType":"NetworkConnection"}'
        }
    }

    It 'merges raw event chunks with fast JSON metadata while preserving payloads and ordering' {
        $chunkOne = Join-Path $TestDrive 'chunk_raw_fast_1.json'
        $chunkTwo = Join-Path $TestDrive 'chunk_raw_fast_2.json'
        Set-Content -Path $chunkOne -Value '{"ChunkIndex":1,"Events":[{"ReportId":"old","ActionTimeIsoString":"2026-05-10T00:30:00Z","ActionType":"ProcessCreated","Nested":{"Value":1}},{"ReportId":"skip","ActionTimeIsoString":"2026-05-10T00:45:00Z","ActionType":"NetworkConnection"}],"EventCount":2}' -Encoding UTF8
        Set-Content -Path $chunkTwo -Value '{"ChunkIndex":2,"Events":[{"ReportId":"new","ActionTimeIsoString":"2026-05-10T01:30:00Z","ActionType":"ProcessCreated"},{"ReportId":"old","ActionTimeIsoString":"2026-05-10T00:30:00Z","ActionType":"ProcessCreated","Nested":{"Value":1}}],"EventCount":2}' -Encoding UTF8

        InModuleScope XDRInternals -Parameters @{ ChunkOne = $chunkOne; ChunkTwo = $chunkTwo } {
            param($ChunkOne, $ChunkTwo)

            $files = @((Get-Item $ChunkOne), (Get-Item $ChunkTwo))
            $slow = @(Merge-XdrTimelineChunkRawEvent -File $files -FilterScript {
                    param($TimelineEvent)
                    Test-XdrEndpointTimelineEventTypeMatch -TimelineEvent $TimelineEvent -EventType 'Process*'
                } -GetStableEventKeyScript {
                    param($TimelineEvent)
                    Get-XdrTimelineStableEventKey -TimelineEvent $TimelineEvent
                })
            $fast = @(Merge-XdrTimelineChunkRawEvent -File $files -EventType 'Process*' -UseFastJsonMetadata -FilterScript {
                    param($TimelineEvent)
                    Test-XdrEndpointTimelineEventTypeMatch -TimelineEvent $TimelineEvent -EventType 'Process*'
                } -GetStableEventKeyScript {
                    param($TimelineEvent)
                    Get-XdrTimelineStableEventKey -TimelineEvent $TimelineEvent
                })

            @($fast | ForEach-Object StableKey) | Should -Be @($slow | ForEach-Object StableKey)
            @($fast | ForEach-Object RawJson) | Should -Be @($slow | ForEach-Object RawJson)
            @($fast | ForEach-Object StableKey) | Should -Be @('new', 'old')
            $fast[0].Event | Should -BeNullOrEmpty
        }
    }

    It 'falls back to object stable keys when fast JSON metadata has no preferred id' {
        $chunkPath = Join-Path $TestDrive 'chunk_raw_fast_fallback.json'
        Set-Content -Path $chunkPath -Value '{"ChunkIndex":1,"Events":[{"ActionTimeIsoString":"2026-05-10T00:30:00Z","ActionType":"ProcessCreated","FileName":"cmd.exe","RowNumber":1},{"ActionTimeIsoString":"2026-05-10T00:30:00Z","ActionType":"ProcessCreated","FileName":"cmd.exe","RowNumber":2}],"EventCount":2}' -Encoding UTF8

        InModuleScope XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            $fast = @(Merge-XdrTimelineChunkRawEvent -File @((Get-Item $ChunkPath)) -EventType 'Process*' -UseFastJsonMetadata -FilterScript {
                    param($TimelineEvent)
                    Test-XdrEndpointTimelineEventTypeMatch -TimelineEvent $TimelineEvent -EventType 'Process*'
                } -GetStableEventKeyScript {
                    param($TimelineEvent)
                    Get-XdrTimelineStableEventKey -TimelineEvent $TimelineEvent
                })
            $slow = @(Merge-XdrTimelineChunkRawEvent -File @((Get-Item $ChunkPath)) -FilterScript {
                    param($TimelineEvent)
                    Test-XdrEndpointTimelineEventTypeMatch -TimelineEvent $TimelineEvent -EventType 'Process*'
                } -GetStableEventKeyScript {
                    param($TimelineEvent)
                    Get-XdrTimelineStableEventKey -TimelineEvent $TimelineEvent
                })

            $fast.Count | Should -Be 1
            $fast[0].StableKey | Should -Be $slow[0].StableKey
            $fast[0].RawJson | ConvertFrom-Json | Select-Object -ExpandProperty FileName | Should -Be 'cmd.exe'
        }
    }

    It 'throws unreadable timeline chunk errors when partial data is not allowed' {
        $chunkPath = Join-Path $TestDrive 'chunk_bad_strict.json'
        Set-Content -Path $chunkPath -Value '{"Events":[{"EventType":"ProcessCreated"}' -Encoding UTF8

        InModuleScope XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            { Read-XdrTimelineChunkFile -File (Get-Item -Path $ChunkPath) } |
                Should -Throw '*Conversion from JSON failed*'
        }
    }

    It 'sorts timeline events by timestamp then stable key' {
        InModuleScope XDRInternals {
            $events = @(
                [pscustomobject]@{ Timestamp = '2026-05-10T01:00:00Z'; EventType = 'Older'; Id = '2' }
                [pscustomobject]@{ Timestamp = '2026-05-10T03:00:00Z'; EventType = 'Newer'; Id = '1' }
                [pscustomobject]@{ Timestamp = '2026-05-10T02:00:00Z'; EventType = 'Middle'; Id = '3' }
            )

            $sorted = Get-XdrTimelineSortedEvent -Events $events

            @($sorted | ForEach-Object EventType) | Should -Be @('Newer', 'Middle', 'Older')
            (Get-XdrTimelineStableEventKey -TimelineEvent $events[0]) | Should -Be '2'
        }
    }

    It 'writes and merges chunk files with stable dedupe' {
        $chunkOne = Join-Path $TestDrive 'chunk_0001.json'
        $chunkTwo = Join-Path $TestDrive 'chunk_0002.json'

        InModuleScope XDRInternals -Parameters @{ ChunkOne = $chunkOne; ChunkTwo = $chunkTwo } {
            param($ChunkOne, $ChunkTwo)

            Write-XdrTimelineChunkFile -Path $ChunkOne -ChunkIndex 1 -FromDate ([datetime]'2026-05-10T00:00:00Z') -ToDate ([datetime]'2026-05-10T01:00:00Z') -Events @(
                [pscustomobject]@{ Id = 'same'; Timestamp = '2026-05-10T00:30:00Z'; EventType = 'ProcessCreated' }
            )
            Write-XdrTimelineChunkFile -Path $ChunkTwo -ChunkIndex 2 -FromDate ([datetime]'2026-05-10T01:00:00Z') -ToDate ([datetime]'2026-05-10T02:00:00Z') -Events @(
                [pscustomobject]@{ Id = 'same'; Timestamp = '2026-05-10T00:30:00Z'; EventType = 'ProcessCreated' }
                [pscustomobject]@{ Id = 'new'; Timestamp = '2026-05-10T01:30:00Z'; EventType = 'NetworkConnection' }
            )

            $merged = @(Merge-XdrTimelineChunkFile -File @((Get-Item $ChunkOne), (Get-Item $ChunkTwo)) -Sort)

            $merged.Count | Should -Be 2
            @($merged | ForEach-Object Id) | Should -Be @('new', 'same')
        }
    }

    It 'allows empty event collections during chunk merges' {
        InModuleScope XDRInternals {
            $sorted = Get-XdrTimelineSortedEvent -Events @()

            @($sorted).Count | Should -Be 0
        }
    }

    It 'writes structured diagnostics to disk' {
        $diagnosticsPath = Join-Path $TestDrive 'timeline.diagnostics.json'

        InModuleScope XDRInternals -Parameters @{ DiagnosticsPath = $diagnosticsPath } {
            param($DiagnosticsPath)

            Write-XdrTimelineDiagnosticFile -Path $DiagnosticsPath -Diagnostics ([ordered]@{
                    Status = 'Succeeded'
                    Totals = [ordered]@{
                        TotalEvents = 42
                    }
                })

            $saved = Get-Content -Path $DiagnosticsPath -Raw | ConvertFrom-Json

            $saved.Status | Should -Be 'Succeeded'
            $saved.Totals.TotalEvents | Should -Be 42
        }
    }

    It 'runs chunk workers with bounded concurrency' {
        InModuleScope XDRInternals {
            $chunks = @(New-XdrTimelineChunkPlan -FromDate ([datetime]'2026-05-10T00:00:00Z') -ToDate ([datetime]'2026-05-10T03:00:00Z') -ChunkHours 1)
            $worker = {
                param($Chunk, $SharedParameters)

                Start-Sleep -Milliseconds $SharedParameters.DelayMilliseconds
                [PSCustomObject]@{
                    ChunkIndex = $Chunk.Index
                    Success = $true
                }
            }

            $results = @(Invoke-XdrTimelineChunkQueue -Chunks $chunks -WorkerScript $worker -SharedParameters @{ DelayMilliseconds = 10 } -ThrottleLimit 2 -TimeoutSeconds 30 -Activity 'Pester Timeline Queue')

            $results.Count | Should -Be 3
            @($results | ForEach-Object ChunkIndex) | Should -Be @(0, 1, 2)
        }
    }

    It 'returns a successful endpoint page after the first request attempt' {
        InModuleScope XDRInternals -Parameters @{ TempPath = $TestDrive } {
            param($TempPath)

            Mock Invoke-RestMethod {
                [pscustomobject]@{
                    Items = @(
                        [pscustomobject]@{
                            ReportId            = 'report-1'
                            ActionTimeIsoString = '2026-05-10T00:30:00Z'
                            ActionType          = 'ProcessCreated'
                        }
                    )
                    Next = $null
                }
            } -ModuleName XDRInternals

            $worker = New-XdrEndpointTimelineChunkWorkerScript
            $chunk = [pscustomobject]@{
                Index         = 0
                FromDate      = [datetime]'2026-05-10T00:00:00Z'
                ToDate        = [datetime]'2026-05-10T01:00:00Z'
                OwnerFromDate = [datetime]'2026-05-10T00:00:00Z'
                OwnerToDate   = [datetime]'2026-05-10T01:00:00Z'
            }
            $sharedParameters = @{
                BaseUrl                     = 'https://security.microsoft.com'
                DeviceId                    = 'device-1'
                MachineDnsName              = $null
                SenseClientVersion          = $null
                GenerateIdentityEvents      = $false
                IncludeIdentityEvents       = $false
                SupportMdiOnlyEvents        = $false
                DoNotUseCache               = $true
                ForceUseCache               = $false
                IncludeSentinelEvents       = $false
                MarkedEventsOnly            = $false
                EventsGroups                = @()
                DataTypes                   = @()
                SourceProviders             = @()
                PageSize                    = 999
                MaxRetries                  = 4
                RetryDelaySeconds           = 0
                RequestTimeoutSeconds       = 10
                PaginationDelayMilliseconds = 0
                MaxPagesPerChunk            = 5
                TempPath                    = $TempPath
                CookieData                  = @()
                HeadersData                 = @{}
            }

            $result = & $worker $chunk $sharedParameters

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 1
            $result.PagesRetrieved | Should -Be 1
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1
        }
    }

    It 'stops endpoint workers at the internal dense page threshold' {
        InModuleScope XDRInternals {
            $script:EndpointDensePageCall = 0
            Mock Invoke-RestMethod {
                $script:EndpointDensePageCall++
                [pscustomobject]@{
                    Items = @(
                        [pscustomobject]@{
                            ReportId            = "report-$script:EndpointDensePageCall"
                            ActionTimeIsoString = ('2026-05-10T00:0{0}:00Z' -f $script:EndpointDensePageCall)
                            ActionType          = 'ProcessCreated'
                        }
                    )
                    Next = "/next-$script:EndpointDensePageCall"
                }
            } -ModuleName XDRInternals

            $worker = New-XdrEndpointTimelineChunkWorkerScript
            $chunk = [pscustomobject]@{
                Index         = 0
                FromDate      = [datetime]'2026-05-10T00:00:00Z'
                ToDate        = [datetime]'2026-05-10T01:00:00Z'
                OwnerFromDate = [datetime]'2026-05-10T00:00:00Z'
                OwnerToDate   = [datetime]'2026-05-10T01:00:00Z'
            }
            $sharedParameters = @{
                BaseUrl                     = 'https://security.microsoft.com'
                DeviceId                    = 'device-1'
                MachineDnsName              = $null
                SenseClientVersion          = $null
                GenerateIdentityEvents      = $false
                IncludeIdentityEvents       = $false
                SupportMdiOnlyEvents        = $false
                DoNotUseCache               = $true
                ForceUseCache               = $false
                IncludeSentinelEvents       = $false
                MarkedEventsOnly            = $false
                EventsGroups                = @()
                DataTypes                   = @()
                SourceProviders             = @()
                PageSize                    = 999
                MaxRetries                  = 1
                RetryDelaySeconds           = 0
                RequestTimeoutSeconds       = 10
                PaginationDelayMilliseconds = 0
                MaxPagesPerChunk            = 10
                DensePageThreshold          = 2
                EarlyDensitySamplePages     = 0
                EarlyDensityMaxTimestampSpanSeconds = 0
                TempPath                    = $TestDrive
                CookieData                  = @()
                HeadersData                 = @{}
            }

            $result = & $worker $chunk $sharedParameters

            $result.Success | Should -BeFalse
            $result.PagesRetrieved | Should -Be 2
            $result.EventCount | Should -Be 2
            $result.Error | Should -Match 'DensePageThreshold=2'
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2
        }
    }

    It 'continues paging minimum-size adaptive chunks instead of stopping at dense threshold' {
        InModuleScope XDRInternals {
            $script:EndpointMinimumDenseCall = 0
            Mock Invoke-RestMethod {
                $script:EndpointMinimumDenseCall++
                [pscustomobject]@{
                    Items = @(
                        [pscustomobject]@{
                            ReportId            = "minimum-$script:EndpointMinimumDenseCall"
                            ActionTimeIsoString = ([datetime]'2026-05-10T00:00:00Z').AddSeconds($script:EndpointMinimumDenseCall).ToString('o')
                            ActionType          = 'ProcessCreated'
                        }
                    )
                    Next = if ($script:EndpointMinimumDenseCall -lt 3) { "/next-minimum-$script:EndpointMinimumDenseCall" } else { $null }
                }
            } -ModuleName XDRInternals

            $worker = New-XdrEndpointTimelineChunkWorkerScript
            $chunk = [pscustomobject]@{
                Index         = 0
                FromDate      = [datetime]'2026-05-10T00:00:00Z'
                ToDate        = [datetime]'2026-05-10T00:15:00Z'
                OwnerFromDate = [datetime]'2026-05-10T00:00:00Z'
                OwnerToDate   = [datetime]'2026-05-10T00:15:00Z'
            }
            $sharedParameters = @{
                BaseUrl                              = 'https://security.microsoft.com'
                DeviceId                             = 'device-1'
                MachineDnsName                       = $null
                SenseClientVersion                   = $null
                GenerateIdentityEvents               = $false
                IncludeIdentityEvents                = $false
                SupportMdiOnlyEvents                 = $false
                DoNotUseCache                        = $true
                ForceUseCache                        = $false
                IncludeSentinelEvents                = $false
                MarkedEventsOnly                     = $false
                EventsGroups                         = @()
                DataTypes                            = @()
                SourceProviders                      = @()
                PageSize                             = 999
                MaxRetries                           = 1
                RetryDelaySeconds                    = 0
                RequestTimeoutSeconds                = 10
                PaginationDelayMilliseconds          = 0
                MaxPagesPerChunk                     = 10
                DensePageThreshold                   = 2
                AdaptiveMinimumChunkMinutes          = 15
                EarlyDensitySamplePages              = 0
                EarlyDensityMaxTimestampSpanSeconds  = 0
                TempPath                             = $TestDrive
                CookieData                           = @()
                HeadersData                          = @{}
            }

            $result = & $worker $chunk $sharedParameters

            $result.Success | Should -BeTrue
            $result.PagesRetrieved | Should -Be 3
            $result.EventCount | Should -Be 3
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 3
        }
    }

    It 'stops endpoint workers early when initial full pages are timestamp-dense' {
        InModuleScope XDRInternals {
            $script:EndpointEarlyDensityCall = 0
            Mock Invoke-RestMethod {
                $script:EndpointEarlyDensityCall++
                $baseSecond = ($script:EndpointEarlyDensityCall - 1) * 5
                [pscustomobject]@{
                    Items = @(
                        [pscustomobject]@{
                            ReportId            = "early-$script:EndpointEarlyDensityCall-a"
                            ActionTimeIsoString = ([datetime]'2026-05-10T00:00:00Z').AddSeconds($baseSecond).ToString('o')
                            ActionType          = 'ProcessCreated'
                        },
                        [pscustomobject]@{
                            ReportId            = "early-$script:EndpointEarlyDensityCall-b"
                            ActionTimeIsoString = ([datetime]'2026-05-10T00:00:00Z').AddSeconds($baseSecond + 1).ToString('o')
                            ActionType          = 'ProcessCreated'
                        }
                    )
                    Next = "/next-early-$script:EndpointEarlyDensityCall"
                }
            } -ModuleName XDRInternals

            $worker = New-XdrEndpointTimelineChunkWorkerScript
            $chunk = [pscustomobject]@{
                Index         = 0
                FromDate      = [datetime]'2026-05-10T00:00:00Z'
                ToDate        = [datetime]'2026-05-10T01:00:00Z'
                OwnerFromDate = [datetime]'2026-05-10T00:00:00Z'
                OwnerToDate   = [datetime]'2026-05-10T01:00:00Z'
            }
            $sharedParameters = @{
                BaseUrl                              = 'https://security.microsoft.com'
                DeviceId                             = 'device-1'
                MachineDnsName                       = $null
                SenseClientVersion                   = $null
                GenerateIdentityEvents               = $false
                IncludeIdentityEvents                = $false
                SupportMdiOnlyEvents                 = $false
                DoNotUseCache                        = $true
                ForceUseCache                        = $false
                IncludeSentinelEvents                = $false
                MarkedEventsOnly                     = $false
                EventsGroups                         = @()
                DataTypes                            = @()
                SourceProviders                      = @()
                PageSize                             = 2
                MaxRetries                           = 1
                RetryDelaySeconds                    = 0
                RequestTimeoutSeconds                = 10
                PaginationDelayMilliseconds          = 0
                MaxPagesPerChunk                     = 100
                DensePageThreshold                   = 32
                EarlyDensitySamplePages              = 3
                EarlyDensityMaxTimestampSpanSeconds  = 60
                TempPath                             = $TestDrive
                CookieData                           = @()
                HeadersData                          = @{}
            }

            $result = & $worker $chunk $sharedParameters

            $result.Success | Should -BeFalse
            $result.FailureClass | Should -Be 'Fatal'
            $result.PagesRetrieved | Should -Be 3
            $result.EventCount | Should -Be 6
            $result.Error | Should -Match 'EarlyDensityThreshold'
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 3
        }
    }

    It 'stops endpoint workers early when a later full-page window is timestamp-dense' {
        InModuleScope XDRInternals {
            $script:EndpointSlidingDensityCall = 0
            Mock Invoke-RestMethod {
                $script:EndpointSlidingDensityCall++
                $timestamps = switch ($script:EndpointSlidingDensityCall) {
                    1 { @('2026-05-10T00:00:00Z', '2026-05-10T00:30:00Z') }
                    2 { @('2026-05-10T00:40:00Z', '2026-05-10T00:40:01Z') }
                    3 { @('2026-05-10T00:40:02Z', '2026-05-10T00:40:03Z') }
                    default { @('2026-05-10T00:40:04Z', '2026-05-10T00:40:05Z') }
                }
                [pscustomobject]@{
                    Items = @(
                        [pscustomobject]@{
                            ReportId            = "sliding-$script:EndpointSlidingDensityCall-a"
                            ActionTimeIsoString = $timestamps[0]
                            ActionType          = 'ProcessCreated'
                        },
                        [pscustomobject]@{
                            ReportId            = "sliding-$script:EndpointSlidingDensityCall-b"
                            ActionTimeIsoString = $timestamps[1]
                            ActionType          = 'ProcessCreated'
                        }
                    )
                    Next = "/next-sliding-$script:EndpointSlidingDensityCall"
                }
            } -ModuleName XDRInternals

            $worker = New-XdrEndpointTimelineChunkWorkerScript
            $chunk = [pscustomobject]@{
                Index         = 0
                FromDate      = [datetime]'2026-05-10T00:00:00Z'
                ToDate        = [datetime]'2026-05-10T01:00:00Z'
                OwnerFromDate = [datetime]'2026-05-10T00:00:00Z'
                OwnerToDate   = [datetime]'2026-05-10T01:00:00Z'
            }
            $sharedParameters = @{
                BaseUrl                              = 'https://security.microsoft.com'
                DeviceId                             = 'device-1'
                MachineDnsName                       = $null
                SenseClientVersion                   = $null
                GenerateIdentityEvents               = $false
                IncludeIdentityEvents                = $false
                SupportMdiOnlyEvents                 = $false
                DoNotUseCache                        = $true
                ForceUseCache                        = $false
                IncludeSentinelEvents                = $false
                MarkedEventsOnly                     = $false
                EventsGroups                         = @()
                DataTypes                            = @()
                SourceProviders                      = @()
                PageSize                             = 2
                MaxRetries                           = 1
                RetryDelaySeconds                    = 0
                RequestTimeoutSeconds                = 10
                PaginationDelayMilliseconds          = 0
                MaxPagesPerChunk                     = 100
                DensePageThreshold                   = 32
                EarlyDensitySamplePages              = 3
                EarlyDensityMaxTimestampSpanSeconds  = 10
                TempPath                             = $TestDrive
                CookieData                           = @()
                HeadersData                          = @{}
            }

            $result = & $worker $chunk $sharedParameters

            $result.Success | Should -BeFalse
            $result.FailureClass | Should -Be 'Fatal'
            $result.PagesRetrieved | Should -Be 4
            $result.EventCount | Should -Be 8
            $result.Error | Should -Match 'EarlyDensityThreshold'
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 4
        }
    }

    It 'returns failed chunk results when queue timeout is reached' {
        InModuleScope XDRInternals {
            $chunks = @(New-XdrTimelineChunkPlan -FromDate ([datetime]'2026-05-10T00:00:00Z') -ToDate ([datetime]'2026-05-10T02:00:00Z') -ChunkHours 1)
            $worker = {
                param($Chunk, $SharedParameters)

                Start-Sleep -Seconds $SharedParameters.DelaySeconds
                [PSCustomObject]@{
                    ChunkIndex = $Chunk.Index
                    Success = $true
                }
            }

            $results = @(Invoke-XdrTimelineChunkQueue -Chunks $chunks -WorkerScript $worker -SharedParameters @{ DelaySeconds = 3 } -ThrottleLimit 1 -TimeoutSeconds 1 -Activity 'Pester Timeline Timeout')

            $results.Count | Should -Be 2
            @($results | Where-Object { -not $_.Success }).Count | Should -Be 2
            @($results | Select-Object -ExpandProperty FailureClass -Unique) | Should -Be @('Timeout')
            $results[0].Error | Should -Match 'timed out'
        }
    }

    It 'treats queue timeout failures in the manifest as resumable pending chunks' {
        InModuleScope XDRInternals {
            $chunks = @(
                [pscustomobject]@{
                    Index         = 0
                    FromDate      = [datetime]'2026-05-10T00:00:00Z'
                    ToDate        = [datetime]'2026-05-10T01:00:00Z'
                    OwnerFromDate = [datetime]'2026-05-10T00:00:00Z'
                    OwnerToDate   = [datetime]'2026-05-10T01:00:00Z'
                    ChunkHours    = 1
                    ChunkMinutes  = 60
                    Strategy      = 'Test'
                }
                [pscustomobject]@{
                    Index         = 1
                    FromDate      = [datetime]'2026-05-10T01:00:00Z'
                    ToDate        = [datetime]'2026-05-10T02:00:00Z'
                    OwnerFromDate = [datetime]'2026-05-10T01:00:00Z'
                    OwnerToDate   = [datetime]'2026-05-10T02:00:00Z'
                    ChunkHours    = 1
                    ChunkMinutes  = 60
                    Strategy      = 'Test'
                }
            )
            $manifest = New-XdrEndpointTimelineManifestState -Compatibility @{ Command = 'test' } -Chunks $chunks
            $worker = {
                param($Chunk, $SharedParameters)

                Start-Sleep -Seconds $SharedParameters.DelaySeconds
                [PSCustomObject]@{
                    ChunkIndex = $Chunk.Index
                    Success = $true
                }
            }

            $results = @(Invoke-XdrTimelineChunkQueue -Chunks $chunks -WorkerScript $worker -SharedParameters @{ DelaySeconds = 3 } -ThrottleLimit 1 -TimeoutSeconds 1 -Activity 'Pester Timeline Timeout Manifest')
            foreach ($result in $results) {
                Update-XdrEndpointTimelineManifestJob -Manifest $manifest -Result $result
            }

            $pending = @(Get-XdrEndpointTimelinePendingChunk -Manifest $manifest | Sort-Object Index)
            $failureClasses = @($manifest.Jobs | ForEach-Object { Get-XdrTimelineObjectValue -InputObject $_ -Name 'FailureClass' } | Sort-Object -Unique)

            $pending.Count | Should -Be 2
            $failureClasses | Should -Be @('Timeout')
            $pending[0].Index | Should -Be 0
            $pending[1].Index | Should -Be 1
        }
    }

    It 'classifies retryable timeline request failures' {
        InModuleScope XDRInternals {
            Mock Invoke-RestMethod {
                if (-not $script:RetryAttempt) { $script:RetryAttempt = 0 }
                $script:RetryAttempt++
                if ($script:RetryAttempt -eq 1) {
                    throw [System.Net.WebException]::new('transient')
                }

                [pscustomobject]@{ ok = $true }
            } -ModuleName XDRInternals

            $result = Invoke-XdrTimelineRequestWithRetry -Uri 'https://example.invalid' -MaxRetries 2 -RetryDelaySeconds 0 -TimeoutSeconds 10

            $result.ok | Should -BeTrue
            Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2
        }
    }

    It 'sanitizes request context metadata without serializing cookie or header values' {
        InModuleScope XDRInternals {
            $summary = ConvertTo-XdrSanitizedRequestContext -RequestContext ([pscustomobject]@{
                    BaseUrl = 'https://security.microsoft.com'
                    CookieData = @([pscustomobject]@{ Name = 'sccauth'; Value = 'secret-cookie'; Domain = 'security.microsoft.com'; Path = '/' })
                    HeadersData = @{ 'X-XSRF-TOKEN' = 'secret-token'; 'x-tid' = 'tenant-id' }
                })

            $json = $summary | ConvertTo-Json -Depth 10 -Compress
            $json | Should -Not -Match 'secret-cookie'
            $json | Should -Not -Match 'secret-token'
            $summary.CookieNames | Should -Contain 'sccauth'
            $summary.HeaderNames | Should -Contain 'X-XSRF-TOKEN'
        }
    }

    It 'classifies auth expiration separately from authorization failures' {
        InModuleScope XDRInternals {
            Get-XdrHttpFailureClass -StatusCode 401 | Should -Be 'AuthExpired'
            Get-XdrHttpFailureClass -StatusCode 403 -Message 'XSRF token expired' | Should -Be 'AuthExpired'
            Get-XdrHttpFailureClass -StatusCode 403 -Message 'Forbidden' | Should -Be 'Authz'
            Get-XdrHttpFailureClass -StatusCode 429 | Should -Be 'RateLimited'
            Get-XdrHttpFailureClass -StatusCode 503 | Should -Be 'Transient'
            Get-XdrHttpFailureClass -Message 'Chunk 28 exceeded MaxPagesPerChunk=40.' | Should -Be 'Fatal'
        }
    }

    It 'writes raw event exports atomically without reserializing payloads' {
        $exportPath = Join-Path $TestDrive 'raw-events.ndjson'
        InModuleScope XDRInternals -Parameters @{ ExportPath = $exportPath } {
            param($ExportPath)

            $records = @(
                [pscustomobject]@{ RawJson = '{"z":1,"nested":{"a":[1,2,3]}}' }
            )

            Write-XdrTimelineRawEventExport -Path $ExportPath -Record $records -Format Ndjson

            (Get-Content -Path $ExportPath -Raw).Trim() | Should -Be '{"z":1,"nested":{"a":[1,2,3]}}'
        }
    }

    It 'rejects incompatible manifests and accepts matching command shape' {
        InModuleScope XDRInternals {
            $compatibility = @{
                Command        = 'Get-XdrEndpointDeviceTimeline'
                TenantId       = 'tenant-a'
                DeviceId       = 'device-a'
                SchemaVersion  = 3
                PlannerVersion = 'EndpointTimelineAdaptiveManifestV3'
                FromTicksUtc   = 1
                ToTicksUtc     = 2
                PageSize       = 999
                OverlapSeconds = 10
            }
            $manifest = [pscustomobject]@{ Compatibility = [pscustomobject]$compatibility }

            Test-XdrTimelineManifestCompatibility -Manifest $manifest -Compatibility $compatibility | Should -BeTrue

            $changed = $compatibility.Clone()
            $changed.PageSize = 1000
            Test-XdrTimelineManifestCompatibility -Manifest $manifest -Compatibility $changed | Should -BeFalse

            $v2 = $compatibility.Clone()
            $v2.SchemaVersion = 2
            $v2.PlannerVersion = 'EndpointTimelineAdaptiveManifestV2'
            Test-XdrTimelineManifestCompatibility -Manifest $manifest -Compatibility $v2 | Should -BeFalse
        }
    }

    It 'marks completed manifest jobs pending when the payload hash no longer matches' {
        $chunkPath = Join-Path $TestDrive 'chunk.json'
        Set-Content -Path $chunkPath -Value '{"Events":[],"EventCount":0}' -Encoding UTF8

        InModuleScope XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            $chunks = @([pscustomobject]@{
                    Index = 0
                    FromDate = [datetime]'2026-01-01T00:00:00Z'
                    ToDate = [datetime]'2026-01-01T01:00:00Z'
                })
            $manifest = [pscustomobject]@{
                Jobs = @([pscustomobject]@{
                        ChunkIndex = 0
                        Status = 'Succeeded'
                        FilePath = $ChunkPath
                        FileSha256 = 'not-the-real-hash'
                    })
            }

            $pending = @(Get-XdrEndpointTimelinePendingChunk -Chunks $chunks -Manifest $manifest)

            $pending.Count | Should -Be 1
            $pending[0].Index | Should -Be 0
        }
    }

    It 'splits dense endpoint manifest jobs into children with boundary overlap' {
        InModuleScope XDRInternals {
            $chunk = [pscustomobject]@{
                Index         = 0
                FromDate      = [datetime]'2026-01-01T00:00:00Z'
                ToDate        = [datetime]'2026-01-01T04:00:00Z'
                OwnerFromDate = [datetime]'2026-01-01T00:00:00Z'
                OwnerToDate   = [datetime]'2026-01-01T04:00:00Z'
                ChunkHours    = 4
                ChunkMinutes  = 240
                Strategy      = 'Test'
            }
            $manifest = New-XdrEndpointTimelineManifestState -Compatibility @{ Command = 'test' } -Chunks @($chunk)
            $result = [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $false
                Error          = 'Chunk 0 exceeded MaxPagesPerChunk=40.'
                FailureClass   = 'Fatal'
                PagesRetrieved = 40
                EventCount     = 39961
            }

            $children = @(Split-XdrEndpointTimelineManifestJob -Manifest $manifest -Result $result -GlobalFromDate ([datetime]'2026-01-01T00:00:00Z') -GlobalToDate ([datetime]'2026-01-01T04:00:00Z') -OverlapSeconds 10)
            $jobs = @(Get-XdrEndpointTimelineManifestJob -Manifest $manifest)
            $pending = @(Get-XdrEndpointTimelinePendingChunk -Manifest $manifest | Sort-Object OwnerFromDate)

            $children.Count | Should -Be 2
            $jobs[0]['Status'] | Should -Be 'Superseded'
            $jobs[0]['SplitStrategy'] | Should -Be 'EqualTime'
            @($jobs[0]['ChildJobIds']).Count | Should -Be 2
            $pending.Count | Should -Be 2
            $pending[0].OwnerFromDate | Should -Be ([datetime]'2026-01-01T00:00:00Z')
            $pending[0].OwnerToDate | Should -Be ([datetime]'2026-01-01T02:00:00Z')
            $pending[0].FromDate | Should -Be ([datetime]'2026-01-01T00:00:00Z')
            $pending[0].ToDate | Should -Be ([datetime]'2026-01-01T02:00:10Z')
            $pending[1].FromDate | Should -Be ([datetime]'2026-01-01T01:59:50Z')
            $pending[1].ToDate | Should -Be ([datetime]'2026-01-01T04:00:00Z')
        }
    }

    It 'uses timestamp-guided split boundaries when dense page diagnostics are trustworthy' {
        InModuleScope XDRInternals {
            $chunk = [pscustomobject]@{
                Index         = 0
                FromDate      = [datetime]'2026-01-01T00:00:00Z'
                ToDate        = [datetime]'2026-01-01T04:00:00Z'
                OwnerFromDate = [datetime]'2026-01-01T00:00:00Z'
                OwnerToDate   = [datetime]'2026-01-01T04:00:00Z'
                ChunkHours    = 4
                ChunkMinutes  = 240
                Strategy      = 'Test'
            }
            $manifest = New-XdrEndpointTimelineManifestState -Compatibility @{ Command = 'test' } -Chunks @($chunk)
            $pages = @(
                [pscustomobject]@{ PageIndex = 0; RawItemCount = 999; FirstEventTimestamp = '2026-01-01T00:20:00Z'; LastEventTimestamp = '2026-01-01T00:20:10Z' },
                [pscustomobject]@{ PageIndex = 1; RawItemCount = 999; FirstEventTimestamp = '2026-01-01T00:25:00Z'; LastEventTimestamp = '2026-01-01T00:25:10Z' },
                [pscustomobject]@{ PageIndex = 2; RawItemCount = 999; FirstEventTimestamp = '2026-01-01T00:30:00Z'; LastEventTimestamp = '2026-01-01T00:30:10Z' },
                [pscustomobject]@{ PageIndex = 3; RawItemCount = 999; FirstEventTimestamp = '2026-01-01T00:35:00Z'; LastEventTimestamp = '2026-01-01T00:35:10Z' }
            )
            $result = [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $false
                Error          = 'Chunk 0 reached DensePageThreshold=32.'
                FailureClass   = 'Fatal'
                PagesRetrieved = 32
                EventCount     = 31968
                Pages          = $pages
            }

            $children = @(Split-XdrEndpointTimelineManifestJob -Manifest $manifest -Result $result -GlobalFromDate ([datetime]'2026-01-01T00:00:00Z') -GlobalToDate ([datetime]'2026-01-01T04:00:00Z') -OverlapSeconds 10)
            $jobs = @(Get-XdrEndpointTimelineManifestJob -Manifest $manifest)
            $pending = @(Get-XdrEndpointTimelinePendingChunk -Manifest $manifest | Sort-Object OwnerFromDate)

            $children.Count | Should -Be 2
            $jobs[0]['Status'] | Should -Be 'Superseded'
            $jobs[0]['SplitStrategy'] | Should -Be 'TimestampGuided'
            $jobs[0]['SplitMetadata']['SampledPageCount'] | Should -Be 4
            $pending[0].OwnerFromDate | Should -Be ([datetime]'2026-01-01T00:00:00Z')
            $pending[0].OwnerToDate | Should -BeGreaterThan ([datetime]'2026-01-01T00:15:00Z')
            $pending[0].OwnerToDate | Should -BeLessThan ([datetime]'2026-01-01T02:00:00Z')
            $pending[1].OwnerFromDate | Should -Be $pending[0].OwnerToDate
            $pending[1].OwnerToDate | Should -Be ([datetime]'2026-01-01T04:00:00Z')
        }
    }

    It 'records early-density split lineage when the worker stops before dense threshold' {
        InModuleScope XDRInternals {
            $chunk = [pscustomobject]@{
                Index         = 0
                FromDate      = [datetime]'2026-01-01T00:00:00Z'
                ToDate        = [datetime]'2026-01-01T04:00:00Z'
                OwnerFromDate = [datetime]'2026-01-01T00:00:00Z'
                OwnerToDate   = [datetime]'2026-01-01T04:00:00Z'
                ChunkHours    = 4
                ChunkMinutes  = 240
                Strategy      = 'Test'
            }
            $manifest = New-XdrEndpointTimelineManifestState -Compatibility @{ Command = 'test' } -Chunks @($chunk)
            $result = [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $false
                Error          = 'Chunk 0 reached EarlyDensityThreshold after 3 page(s); observed timestamp span 12s.'
                FailureClass   = 'Fatal'
                PagesRetrieved = 3
                EventCount     = 2997
                Pages          = @(
                    [pscustomobject]@{ PageIndex = 0; RawItemCount = 999; FirstEventTimestamp = '2026-01-01T00:05:00Z'; LastEventTimestamp = '2026-01-01T00:05:04Z' },
                    [pscustomobject]@{ PageIndex = 1; RawItemCount = 999; FirstEventTimestamp = '2026-01-01T00:05:05Z'; LastEventTimestamp = '2026-01-01T00:05:08Z' },
                    [pscustomobject]@{ PageIndex = 2; RawItemCount = 999; FirstEventTimestamp = '2026-01-01T00:05:09Z'; LastEventTimestamp = '2026-01-01T00:05:12Z' }
                )
            }

            $children = @(Split-XdrEndpointTimelineManifestJob -Manifest $manifest -Result $result -GlobalFromDate ([datetime]'2026-01-01T00:00:00Z') -GlobalToDate ([datetime]'2026-01-01T04:00:00Z') -OverlapSeconds 10)
            $job = @(Get-XdrEndpointTimelineManifestJob -Manifest $manifest)[0]

            $children.Count | Should -Be 2
            $job['SplitStrategy'] | Should -Be 'EarlyDensity'
            $job['SplitMetadata']['PagesAvoidedEstimate'] | Should -Be 29
        }
    }

    It 'splits very dense endpoint jobs into four children' {
        InModuleScope XDRInternals {
            $chunk = [pscustomobject]@{
                Index         = 0
                FromDate      = [datetime]'2026-01-01T00:00:00Z'
                ToDate        = [datetime]'2026-01-01T04:00:00Z'
                OwnerFromDate = [datetime]'2026-01-01T00:00:00Z'
                OwnerToDate   = [datetime]'2026-01-01T04:00:00Z'
                ChunkHours    = 4
                ChunkMinutes  = 240
                Strategy      = 'Test'
            }
            $manifest = New-XdrEndpointTimelineManifestState -Compatibility @{ Command = 'test' } -Chunks @($chunk)
            $result = [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $false
                Error          = 'Chunk 0 exceeded MaxPagesPerChunk=40.'
                FailureClass   = 'Fatal'
                PagesRetrieved = 64
                EventCount     = 50000
            }

            $children = @(Split-XdrEndpointTimelineManifestJob -Manifest $manifest -Result $result -GlobalFromDate ([datetime]'2026-01-01T00:00:00Z') -GlobalToDate ([datetime]'2026-01-01T04:00:00Z') -OverlapSeconds 10)

            $children.Count | Should -Be 4
            @(Get-XdrEndpointTimelinePendingChunk -Manifest $manifest).Count | Should -Be 4
        }
    }

    It 'does not split endpoint jobs at the minimum adaptive chunk size' {
        InModuleScope XDRInternals {
            $chunk = [pscustomobject]@{
                Index         = 0
                FromDate      = [datetime]'2026-01-01T00:00:00Z'
                ToDate        = [datetime]'2026-01-01T00:15:00Z'
                OwnerFromDate = [datetime]'2026-01-01T00:00:00Z'
                OwnerToDate   = [datetime]'2026-01-01T00:15:00Z'
                ChunkHours    = 0.25
                ChunkMinutes  = 15
                Strategy      = 'Test'
            }
            $manifest = New-XdrEndpointTimelineManifestState -Compatibility @{ Command = 'test' } -Chunks @($chunk)
            $result = [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $false
                Error          = 'Chunk 0 exceeded MaxPagesPerChunk=40.'
                FailureClass   = 'Fatal'
                PagesRetrieved = 40
                EventCount     = 40000
            }

            Update-XdrEndpointTimelineManifestJob -Manifest $manifest -Result $result
            $children = @(Split-XdrEndpointTimelineManifestJob -Manifest $manifest -Result $result -GlobalFromDate ([datetime]'2026-01-01T00:00:00Z') -GlobalToDate ([datetime]'2026-01-01T00:15:00Z') -OverlapSeconds 10 -MinimumChunkMinutes 15)
            $job = @(Get-XdrEndpointTimelineManifestJob -Manifest $manifest)[0]

            $children.Count | Should -Be 0
            $job['Status'] | Should -Be 'Failed'
            $job['SplitReason'] | Should -Be 'MinimumChunkSizeReached'
            $job['SplitStrategy'] | Should -Be 'MinimumChunkSizeReached'
        }
    }

    It 'keeps endpoint timeline public code free of PS5 branches' {
        $endpointTimelineContent = Get-Content -Path (Join-Path $PSScriptRoot '..\..\XDRInternals\functions\Get-XdrEndpointDeviceTimeline.ps1') -Raw

        $endpointTimelineContent | Should -Not -Match 'PSEdition'
        $endpointTimelineContent | Should -Not -Match 'WindowsPowerShell'
        $endpointTimelineContent | Should -Not -Match 'PSVersionTable'
    }

    It 'updates hashtable-backed manifest jobs from chunk results' {
        $chunkPath = Join-Path $TestDrive 'chunk-update.json'
        Set-Content -Path $chunkPath -Value '{"Events":[{"Id":"one"}],"EventCount":1}' -Encoding UTF8

        InModuleScope XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            $manifest = [ordered]@{
                Jobs = @(
                    [ordered]@{
                        ChunkIndex = 0
                        Status = 'Pending'
                        Attempts = 0
                        FilePath = $null
                        FileSha256 = $null
                        EventCount = 0
                        UniqueKeyCount = 0
                        KeySetHash = $null
                        FirstTimestamp = $null
                        LastTimestamp = $null
                        MissingTimestampCount = 0
                        FailureClass = $null
                        Error = $null
                    }
                )
            }
            $result = [pscustomobject]@{
                ChunkIndex = 0
                Success = $true
                FilePath = $ChunkPath
                FileSha256 = (Get-FileHash -LiteralPath $ChunkPath -Algorithm SHA256).Hash
                EventCount = 1
                UniqueKeyCount = 1
            }

            Update-XdrEndpointTimelineManifestJob -Manifest $manifest -Result $result

            $manifest.Jobs[0]['Status'] | Should -Be 'Succeeded'
            $manifest.Jobs[0]['Attempts'] | Should -Be 1
            $manifest.Jobs[0]['FileSha256'] | Should -Be $result.FileSha256
            @(Get-XdrEndpointTimelinePendingChunk -Chunks @([pscustomobject]@{ Index = 0 }) -Manifest $manifest).Count | Should -Be 0
        }
    }

    It 'does not log passkey credential paths in authentication helpers' {
        $connectContent = Get-Content -Path (Join-Path $PSScriptRoot '..\..\XDRInternals\functions\Connect-XdrBySoftwarePasskey.ps1') -Raw
        $passkeyContent = Get-Content -Path (Join-Path $PSScriptRoot '..\..\XDRInternals\internal\functions\Invoke-XdrPasskeyAuthentication.ps1') -Raw

        $connectContent | Should -Not -Match 'Authenticating with software passkey:\s*\$KeyFilePath'
        $passkeyContent | Should -Not -Match 'Loading credential file:\s*\$KeyFilePath'
        $passkeyContent | Should -Not -Match 'vault:\s*\$\('
        $passkeyContent | Should -Not -Match 'Initiating authentication flow for \$targetUser'
    }
}
