BeforeAll {
    if (-not ('EndpointDeviceTimelineTestJob' -as [type])) {
        Add-Type -TypeDefinition @"
using System.Management.Automation;

public sealed class EndpointDeviceTimelineTestJob : Job
{
    public EndpointDeviceTimelineTestJob() : base("Get-XdrEndpointDeviceTimeline", "EndpointDeviceTimelineTestJob")
    {
        SetJobState(JobState.Completed);
    }

    public override string StatusMessage => string.Empty;

    public override bool HasMoreData => false;

    public override string Location => "localhost";

    public override void StopJob()
    {
    }
}
"@
    }
}

Describe 'Get-XdrEndpointDeviceTimeline' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrEndpointDevice {
            [pscustomobject]@{
                MachineId          = $script:DeviceId
                SenseMachineId     = $script:DeviceId
                ComputerDnsName    = 'device.example.com'
                SenseClientVersion = '10.0.22621.1'
            }
        } -ModuleName XDRInternals
        Mock Invoke-XdrTimelineChunkQueue { $script:FakeTimelineResults } -ModuleName XDRInternals
        Mock Invoke-XdrConnectionRenewal {} -ModuleName XDRInternals

        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
        }

        $script:DeviceId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        $script:FromDate = [datetime]'2026-01-01T00:00:00Z'
        $script:ToDate = [datetime]'2026-01-01T02:00:00Z'
        $script:FakeTimelineResults = @()
    }

    It 'exposes the AllowPartial parameter' {
        $command = Get-Command Get-XdrEndpointDeviceTimeline

        $command.Parameters.ContainsKey('AllowPartial') | Should -BeTrue
        $command.Parameters.ContainsKey('ManifestPath') | Should -BeTrue
        $command.Parameters.ContainsKey('DiagnosticsPath') | Should -BeTrue
        $command.Parameters.ContainsKey('PaginationDelayMinMilliseconds') | Should -BeTrue
        $command.Parameters.ContainsKey('PaginationDelayMaxMilliseconds') | Should -BeTrue
    }

    It 'uses four-hour chunks by default for multi-day ranges' {
        $script:CapturedChunkPlanParameters = $null
        Mock New-XdrTimelineChunkPlan {
            param(
                [datetime]$FromDate,
                [datetime]$ToDate,
                [double]$ChunkHours,
                [int]$ChunkMinutes,
                [int]$TargetChunkCount,
                [string]$Strategy
            )

            $script:CapturedChunkPlanParameters = $PSBoundParameters
            [pscustomobject]@{
                ChunkIndex   = 0
                FromDate     = $FromDate
                ToDate       = $ToDate
                ChunkHours   = $ChunkHours
                ChunkMinutes = $ChunkHours * 60
            }
        } -ModuleName XDRInternals

        Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate ([datetime]'2026-01-01T00:00:00Z') -ToDate ([datetime]'2026-01-08T00:00:00Z') -WorkingDirectory $TestDrive | Out-Null

        $script:CapturedChunkPlanParameters.ChunkHours | Should -Be 4
        $script:CapturedChunkPlanParameters.Strategy | Should -Be 'DefaultMultiDayFourHourChunks'
    }

    It 'throws when a chunk fails and partial results are not allowed' {
        $goodFile = Join-Path $TestDrive 'device-timeline-good.json'
        $exportPath = Join-Path $TestDrive 'device-timeline-good-export.json'
        Set-Content -Path $goodFile -Value '{"Events":[{"ActionType":"ProcessCreated"}],"EventCount":1}' -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $goodFile
                EventCount     = 1
                FromDate       = $script:FromDate
                ToDate         = $script:FromDate.AddHours(1)
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
                Pages          = @(
                    [pscustomobject]@{
                        PageIndex                 = 0
                        ElapsedMilliseconds       = 123.45
                        ItemCount                 = 1
                        EventPayloadBytes         = 256
                        HasNext                   = $true
                        HasPrev                   = $false
                        NextShape                 = 'Relative'
                        PrevShape                 = 'None'
                        NextHash                  = 'abc'
                        PrevHash                  = $null
                        RequestUriHash            = 'def'
                        FirstEventTimestamp       = '2026-01-01T00:00:00.0000000Z'
                        LastEventTimestamp        = '2026-01-01T00:00:00.0000000Z'
                        DuplicateWithinChunkCount = 0
                    }
                )
            },
            [pscustomobject]@{
                ChunkIndex     = 1
                Success        = $false
                Error          = 'boom'
                FromDate       = $script:FromDate.AddHours(1)
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 0
                FileSizeKB     = 0
            }
        )

        {
            Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ChunkHours 1 -OutputPath $exportPath -WorkingDirectory $TestDrive
        } | Should -Throw -ExpectedMessage '*Failed to retrieve endpoint device timeline chunks: chunk 1: boom. Completed chunk files and manifest were preserved for resume. Re-run with -AllowPartial to export validated partial data.*'
    }

    It 'returns events from successful chunks when partial results are allowed' {
        $goodFile = Join-Path $TestDrive 'device-timeline-partial-good.json'
        Set-Content -Path $goodFile -Value '{"Events":[{"ActionType":"ProcessCreated"}],"EventCount":1}' -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $goodFile
                EventCount     = 1
                FromDate       = $script:FromDate
                ToDate         = $script:FromDate.AddHours(1)
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
                Pages          = @(
                    [pscustomobject]@{
                        PageIndex                 = 0
                        ElapsedMilliseconds       = 123.45
                        ItemCount                 = 1
                        EventPayloadBytes         = 256
                        HasNext                   = $true
                        HasPrev                   = $false
                        NextShape                 = 'Relative'
                        PrevShape                 = 'None'
                        NextHash                  = 'abc'
                        PrevHash                  = $null
                        RequestUriHash            = 'def'
                        FirstEventTimestamp       = '2026-01-01T00:00:00.0000000Z'
                        LastEventTimestamp        = '2026-01-01T00:00:00.0000000Z'
                        DuplicateWithinChunkCount = 0
                    }
                )
            },
            [pscustomobject]@{
                ChunkIndex     = 1
                Success        = $false
                Error          = 'boom'
                FromDate       = $script:FromDate.AddHours(1)
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 0
                FileSizeKB     = 0
            }
        )

        $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ChunkHours 1 -WorkingDirectory $TestDrive -AllowPartial)

        $result.Count | Should -Be 1
        $result[0].ActionType | Should -Be 'ProcessCreated'
    }

    It 'merges readable partial failed chunk files when partial results are allowed' {
        $goodFile = Join-Path $TestDrive 'device-timeline-partial-good.json'
        $partialFile = Join-Path $TestDrive 'device-timeline-partial-failed.json'
        Set-Content -Path $goodFile -Value '{"Events":[{"ActionType":"ProcessCreated","Id":"good"}],"EventCount":1,"Partial":false}' -Encoding UTF8
        Set-Content -Path $partialFile -Value '{"Events":[{"ActionType":"NetworkConnection","Id":"partial"}],"EventCount":1,"Partial":true,"Error":"guard"}' -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $goodFile
                EventCount     = 1
                FromDate       = $script:FromDate
                ToDate         = $script:FromDate.AddHours(1)
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
                Pages          = @(
                    [pscustomobject]@{
                        PageIndex                 = 0
                        ElapsedMilliseconds       = 123.45
                        ItemCount                 = 1
                        EventPayloadBytes         = 256
                        HasNext                   = $true
                        HasPrev                   = $false
                        NextShape                 = 'Relative'
                        PrevShape                 = 'None'
                        NextHash                  = 'abc'
                        PrevHash                  = $null
                        RequestUriHash            = 'def'
                        FirstEventTimestamp       = '2026-01-01T00:00:00.0000000Z'
                        LastEventTimestamp        = '2026-01-01T00:00:00.0000000Z'
                        DuplicateWithinChunkCount = 0
                    }
                )
            },
            [pscustomobject]@{
                ChunkIndex     = 1
                Success        = $false
                FilePath       = $partialFile
                Error          = 'guard'
                FromDate       = $script:FromDate.AddHours(1)
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 1
                EventCount     = 1
                FileSizeKB     = 1
                Partial        = $true
            }
        )

        $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ChunkHours 1 -WorkingDirectory $TestDrive -AllowPartial -WarningAction SilentlyContinue)

        $result.Count | Should -Be 2
        @($result | ForEach-Object ActionType) | Should -Contain 'ProcessCreated'
        @($result | ForEach-Object ActionType) | Should -Contain 'NetworkConnection'
    }

    It 'skips unreadable completed chunk files when partial results are allowed' {
        $goodFile = Join-Path $TestDrive 'device-timeline-readable.json'
        $badFile = Join-Path $TestDrive 'device-timeline-unreadable.json'
        Set-Content -Path $goodFile -Value '{"Events":[{"ActionType":"ProcessCreated"}],"EventCount":1}' -Encoding UTF8
        Set-Content -Path $badFile -Value '{"Events":[{"ActionType":"Broken"}' -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $goodFile
                EventCount     = 1
                FromDate       = $script:FromDate
                ToDate         = $script:FromDate.AddHours(1)
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
                Pages          = @(
                    [pscustomobject]@{
                        PageIndex                 = 0
                        ElapsedMilliseconds       = 123.45
                        ItemCount                 = 1
                        EventPayloadBytes         = 256
                        HasNext                   = $true
                        HasPrev                   = $false
                        NextShape                 = 'Relative'
                        PrevShape                 = 'None'
                        NextHash                  = 'abc'
                        PrevHash                  = $null
                        RequestUriHash            = 'def'
                        FirstEventTimestamp       = '2026-01-01T00:00:00.0000000Z'
                        LastEventTimestamp        = '2026-01-01T00:00:00.0000000Z'
                        DuplicateWithinChunkCount = 0
                    }
                )
            },
            [pscustomobject]@{
                ChunkIndex     = 1
                Success        = $true
                FilePath       = $badFile
                EventCount     = 1
                FromDate       = $script:FromDate.AddHours(1)
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
            }
        )

        $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ChunkHours 1 -WorkingDirectory $TestDrive -AllowPartial -WarningAction SilentlyContinue)

        $result.Count | Should -Be 1
        $result[0].ActionType | Should -Be 'ProcessCreated'
    }

    It 'skips unreadable completed chunk files during export when partial results are allowed' {
        $goodFile = Join-Path $TestDrive 'device-timeline-export-readable.json'
        $badFile = Join-Path $TestDrive 'device-timeline-export-unreadable.json'
        $exportPath = Join-Path $TestDrive 'device-timeline-export.json'
        $diagnosticsPath = Join-Path $TestDrive 'device-timeline-export.diagnostics.json'
        Set-Content -Path $goodFile -Value '{"Events":[{"ActionType":"ProcessCreated"}],"EventCount":1}' -Encoding UTF8
        Set-Content -Path $badFile -Value '{"Events":[{"ActionType":"Broken"}' -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $goodFile
                EventCount     = 1
                FromDate       = $script:FromDate
                ToDate         = $script:FromDate.AddHours(1)
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
                Pages          = @(
                    [pscustomobject]@{
                        PageIndex                 = 0
                        ElapsedMilliseconds       = 123.45
                        ItemCount                 = 1
                        EventPayloadBytes         = 256
                        HasNext                   = $true
                        HasPrev                   = $false
                        NextShape                 = 'Relative'
                        PrevShape                 = 'None'
                        NextHash                  = 'abc'
                        PrevHash                  = $null
                        RequestUriHash            = 'def'
                        FirstEventTimestamp       = '2026-01-01T00:00:00.0000000Z'
                        LastEventTimestamp        = '2026-01-01T00:00:00.0000000Z'
                        DuplicateWithinChunkCount = 0
                    }
                )
            },
            [pscustomobject]@{
                ChunkIndex     = 1
                Success        = $true
                FilePath       = $badFile
                EventCount     = 1
                FromDate       = $script:FromDate.AddHours(1)
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
            }
        )

        $result = Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ChunkHours 1 -OutputPath $exportPath -WorkingDirectory $TestDrive -AllowPartial -DiagnosticsPath $diagnosticsPath -PaginationDelayMinMilliseconds 0 -PaginationDelayMaxMilliseconds 250 -WarningAction SilentlyContinue
        $exportedEvents = Get-Content -Path $exportPath -Raw | ConvertFrom-Json
        $diagnostics = Get-Content -Path $diagnosticsPath -Raw | ConvertFrom-Json
        $manifest = Get-Content -Path "$exportPath.manifest.json" -Raw | ConvertFrom-Json

        $result.ExportPath | Should -Be $exportPath
        $result.DiagnosticsPath | Should -Be $diagnosticsPath
        $result.TotalEvents | Should -Be 1
        @($exportedEvents).Count | Should -Be 1
        $exportedEvents[0].ActionType | Should -Be 'ProcessCreated'
        $diagnostics.Totals.ReturnedEvents | Should -Be 1
        $diagnostics.Request.ReturnMode | Should -Be 'Export'
        $diagnostics.Request.PaginationDelayMinMilliseconds | Should -Be 0
        $diagnostics.Request.PaginationDelayMaxMilliseconds | Should -Be 250
        $diagnostics.Totals.KeySetHash | Should -Match '^[0-9A-F]{64}$'
        $manifest.Summary.KeySetHash | Should -Be $diagnostics.Totals.KeySetHash
        $pageDiagnostics = @($diagnostics.Chunks.Pages | Where-Object { $_.ItemCount -eq 1 })
        $pageDiagnostics.Count | Should -BeGreaterThan 0
        $pageDiagnostics[0].ItemCount | Should -Be 1
        $pageDiagnostics[0].HasNext | Should -BeTrue
        $pageDiagnostics[0].DuplicateWithinChunkCount | Should -Be 0
    }

    It 'exports successfully when completed chunks contain no events' {
        $goodFile = Join-Path $TestDrive 'device-timeline-export-with-event.json'
        $emptyFile = Join-Path $TestDrive 'device-timeline-export-empty.json'
        $exportPath = Join-Path $TestDrive 'device-timeline-with-empty-chunk.json'
        Set-Content -Path $goodFile -Value '{"Events":[{"ActionType":"ProcessCreated","Id":"nonempty"}],"EventCount":1}' -Encoding UTF8
        Set-Content -Path $emptyFile -Value '{"Events":[],"EventCount":0}' -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $goodFile
                EventCount     = 1
                FromDate       = $script:FromDate
                ToDate         = $script:FromDate.AddHours(1)
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
                Pages          = @()
            },
            [pscustomobject]@{
                ChunkIndex     = 1
                Success        = $true
                FilePath       = $emptyFile
                EventCount     = 0
                FromDate       = $script:FromDate.AddHours(1)
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
                Pages          = @()
            }
        )

        $result = Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ChunkHours 1 -ExportPath $exportPath -WorkingDirectory $TestDrive
        $exportedEvents = @(Get-Content -Path $exportPath -Raw | ConvertFrom-Json)

        $result.TotalEvents | Should -Be 1
        $exportedEvents.Count | Should -Be 1
        $exportedEvents[0].Id | Should -Be 'nonempty'
    }

    It 'automatically splits dense failed chunks and completes child jobs' {
        $childOneFile = Join-Path $TestDrive 'device-timeline-child-one.json'
        $childTwoFile = Join-Path $TestDrive 'device-timeline-child-two.json'
        Set-Content -Path $childOneFile -Value '{"Events":[{"ActionType":"ProcessCreated","Id":"child-one"}],"EventCount":1}' -Encoding UTF8
        Set-Content -Path $childTwoFile -Value '{"Events":[{"ActionType":"NetworkConnection","Id":"child-two"}],"EventCount":1}' -Encoding UTF8
        $script:QueueCall = 0
        $script:CapturedQueueChunks = @()

        Mock Invoke-XdrTimelineChunkQueue {
            param($Chunks)

            $script:QueueCall++
            $script:CapturedQueueChunks += ,@($Chunks)
            if ($script:QueueCall -eq 1) {
                return @(
                    [pscustomobject]@{
                        ChunkIndex     = 0
                        Success        = $false
                        FailureClass   = 'Fatal'
                        Error          = 'Chunk 0 exceeded MaxPagesPerChunk=40.'
                        EventCount     = 39961
                        PagesRetrieved = 40
                    }
                )
            }

            $files = @($childOneFile, $childTwoFile)
            $i = 0
            return @(
                foreach ($chunk in @($Chunks)) {
                    [pscustomobject]@{
                        ChunkIndex     = [int]$chunk.Index
                        Success        = $true
                        FilePath       = $files[$i]
                        FileSha256     = (Get-FileHash -LiteralPath $files[$i] -Algorithm SHA256).Hash
                        EventCount     = 1
                        UniqueKeyCount = 1
                        FromDate       = $chunk.FromDate
                        ToDate         = $chunk.ToDate
                        OwnerFromDate  = $chunk.OwnerFromDate
                        OwnerToDate    = $chunk.OwnerToDate
                        ElapsedSeconds = 1
                        PagesRetrieved = 1
                        FileSizeKB     = 1
                        Pages          = @()
                    }
                    $i++
                }
            )
        } -ModuleName XDRInternals

        $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate ([datetime]'2026-01-01T00:00:00Z') -ToDate ([datetime]'2026-01-01T04:00:00Z') -ChunkHours 4 -WorkingDirectory $TestDrive)

        $result.Count | Should -Be 2
        @($result | ForEach-Object Id) | Should -Contain 'child-one'
        @($result | ForEach-Object Id) | Should -Contain 'child-two'
        $script:QueueCall | Should -Be 2
        @($script:CapturedQueueChunks[0]).Count | Should -Be 1
        @($script:CapturedQueueChunks[1]).Count | Should -Be 2
    }

    It 'refreshes auth in parent scope and retries only auth-expired chunks' {
        $goodFile = Join-Path $TestDrive 'device-timeline-auth-retry.json'
        Set-Content -Path $goodFile -Value '{"Events":[{"ActionType":"ProcessCreated","Id":"retry"}],"EventCount":1}' -Encoding UTF8
        $script:QueueCall = 0
        $script:CapturedQueueChunks = @()
        Mock Invoke-XdrTimelineChunkQueue {
            $script:QueueCall++
            $script:CapturedQueueChunks += ,@($Chunks)
            if ($script:QueueCall -eq 1) {
                return @(
                    [pscustomobject]@{
                        ChunkIndex = 0
                        Success = $false
                        FailureClass = 'AuthExpired'
                        Error = 'token expired'
                        FromDate = $script:FromDate
                        ToDate = $script:ToDate
                        EventCount = 0
                    }
                )
            }

            @(
                [pscustomobject]@{
                    ChunkIndex = 0
                    Success = $true
                    FilePath = $goodFile
                    FileSha256 = (Get-FileHash -LiteralPath $goodFile -Algorithm SHA256).Hash
                    EventCount = 1
                    UniqueKeyCount = 1
                    FromDate = $script:FromDate
                    ToDate = $script:ToDate
                    OwnerFromDate = $script:FromDate
                    OwnerToDate = $script:ToDate
                    ElapsedSeconds = 1
                    PagesRetrieved = 1
                    FileSizeKB = 1
                    Pages = @()
                }
            )
        } -ModuleName XDRInternals

        $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -WorkingDirectory $TestDrive)

        $result.Count | Should -Be 1
        $result[0].Id | Should -Be 'retry'
        Should -Invoke Invoke-XdrConnectionRenewal -ModuleName XDRInternals -Times 1
        Should -Invoke Invoke-XdrTimelineChunkQueue -ModuleName XDRInternals -Times 2
    }

    It 'writes endpoint diagnostics without raw initial request URLs' {
        $goodFile = Join-Path $TestDrive 'device-timeline-diagnostics-good.json'
        $diagnosticsPath = Join-Path $TestDrive 'device-timeline-diagnostics.json'
        Set-Content -Path $goodFile -Value '{"Events":[{"ActionType":"ProcessCreated","Id":"diag"}],"EventCount":1}' -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex       = 0
                Success          = $true
                RequestShape     = 'EndpointDeviceTimelineInitialRequest'
                RequestShapeHash = 'ABC123'
                FilePath         = $goodFile
                FileSha256       = (Get-FileHash -LiteralPath $goodFile -Algorithm SHA256).Hash
                EventCount       = 1
                UniqueKeyCount   = 1
                FromDate         = $script:FromDate
                ToDate           = $script:ToDate
                OwnerFromDate    = $script:FromDate
                OwnerToDate      = $script:ToDate
                ElapsedSeconds   = 1
                PagesRetrieved   = 1
                FileSizeKB       = 1
                Pages            = @()
            }
        )

        Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -WorkingDirectory $TestDrive -DiagnosticsPath $diagnosticsPath | Out-Null

        $diagnosticsJson = Get-Content -Path $diagnosticsPath -Raw
        $diagnosticsJson | Should -Not -Match 'InitialUri'
        $diagnosticsJson | Should -Match 'RequestShapeHash'
        $diagnosticsJson | Should -Not -Match 'https://security.microsoft.com/apiproxy'
    }
}
