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
        Mock Start-ThreadJob {
            [EndpointDeviceTimelineTestJob]::new()
        } -ModuleName XDRInternals
        Mock Receive-Job { $script:FakeTimelineResults } -ModuleName XDRInternals
        Mock Remove-Job {} -ModuleName XDRInternals

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
    }

    It 'uses Prev for normal continuation and does not rely on Next' {
        $command = Get-Command Get-XdrEndpointDeviceTimeline
        $definition = $command.ScriptBlock.ToString()

        ([regex]::Matches($definition, 'IsNullOrWhiteSpace\(\$response\.Prev\)')).Count | Should -Be 2
        $definition | Should -Not -Match '\$response\.Next'
    }

    It 'throws when a chunk fails and partial results are not allowed' {
        $goodFile = Join-Path $TestDrive 'device-timeline-good.json'
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
            Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ExportPath $TestDrive
        } | Should -Throw -ExpectedMessage '*Failed to retrieve device timeline chunks: chunk 1: boom. Re-run with -AllowPartial to return completed chunks.*'
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

        $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ExportPath $TestDrive -AllowPartial)

        $result.Count | Should -Be 1
        $result[0].ActionType | Should -Be 'ProcessCreated'
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

        $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ExportPath $TestDrive -AllowPartial -WarningAction SilentlyContinue)

        $result.Count | Should -Be 1
        $result[0].ActionType | Should -Be 'ProcessCreated'
    }

    It 'uses ExportPath as the temporary chunk root when temp files are kept' {
        $chunkFile = Join-Path $TestDrive 'device-timeline-temp-root.json'
        $tempRoot = Join-Path $TestDrive 'chunk-root'
        Set-Content -Path $chunkFile -Value '{"Events":[{"ActionType":"ProcessCreated"}],"EventCount":1}' -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $chunkFile
                EventCount     = 1
                FromDate       = $script:FromDate
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
            }
        )

        $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ExportPath $tempRoot -KeepTempFiles)
        $deviceRoot = Join-Path $tempRoot $script:DeviceId

        $result.Count | Should -Be 1
        Test-Path -LiteralPath $deviceRoot | Should -BeTrue
        @(Get-ChildItem -Path $deviceRoot -Directory).Count | Should -Be 1
    }

    It 'defaults temporary chunk storage to the user temp folder when ExportPath is omitted' {
        $chunkFile = Join-Path $TestDrive 'device-timeline-default-temp-root.json'
        $deviceId = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        $deviceRoot = Join-Path (Join-Path ([System.IO.Path]::GetTempPath()) 'XdrTimeline') $deviceId
        Set-Content -Path $chunkFile -Value '{"Events":[{"ActionType":"ProcessCreated"}],"EventCount":1}' -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $chunkFile
                EventCount     = 1
                FromDate       = $script:FromDate
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
            }
        )

        if (Test-Path -LiteralPath $deviceRoot) {
            Remove-Item -LiteralPath $deviceRoot -Recurse -Force
        }

        try {
            $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $deviceId -FromDate $script:FromDate -ToDate $script:ToDate -KeepTempFiles)

            $result.Count | Should -Be 1
            Test-Path -LiteralPath $deviceRoot | Should -BeTrue
            @(Get-ChildItem -Path $deviceRoot -Directory).Count | Should -Be 1
        }
        finally {
            if (Test-Path -LiteralPath $deviceRoot) {
                Remove-Item -LiteralPath $deviceRoot -Recurse -Force
            }
        }
    }

    It 'canonicalizes a relative OutputPath before writing the export file' {
        $chunkFile = Join-Path $TestDrive 'device-timeline-export-relative.json'
        Set-Content -Path $chunkFile -Value '{"Events":[{"ActionType":"ProcessCreated"}],"EventCount":1}' -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $chunkFile
                EventCount     = 1
                FromDate       = $script:FromDate
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
            }
        )

        $startingLocation = Get-Location
        try {
            Set-Location $TestDrive
            $relativeOutputPath = '.\exports\timeline.json'
            $result = Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ExportPath (Join-Path $TestDrive 'chunk-root') -OutputPath $relativeOutputPath
            $expectedPath = [System.IO.Path]::GetFullPath($relativeOutputPath)
            $exportedEvents = Get-Content -Path $expectedPath -Raw | ConvertFrom-Json

            $result.OutputPath | Should -Be $expectedPath
            $result.TotalEvents | Should -Be 1
            Test-Path -LiteralPath $expectedPath | Should -BeTrue
            @($exportedEvents).Count | Should -Be 1
        }
        finally {
            Set-Location $startingLocation
        }
    }

    It 'exports events from formatted chunk JSON using parsed Events data' {
        $chunkFile = Join-Path $TestDrive 'device-timeline-export-formatted.json'
        $exportPath = Join-Path $TestDrive 'device-timeline-export-formatted-output.json'
        @"
{
  "ChunkIndex": 0,
  "Events": [
    {
      "ActionType": "ProcessCreated",
      "Nested": {
        "Value": 1
      }
    }
  ],
  "EventCount": 1
}
"@ | Set-Content -Path $chunkFile -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $chunkFile
                EventCount     = 1
                FromDate       = $script:FromDate
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
            }
        )

        $result = Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ExportPath (Join-Path $TestDrive 'chunk-root') -OutputPath $exportPath
        $exportedEvents = Get-Content -Path $exportPath -Raw | ConvertFrom-Json

        $result.TotalEvents | Should -Be 1
        @($exportedEvents).Count | Should -Be 1
        $exportedEvents[0].ActionType | Should -Be 'ProcessCreated'
        $exportedEvents[0].Nested.Value | Should -Be 1
    }

    It 'filters exported events by EventType and reports the emitted event count' {
        $chunkFile = Join-Path $TestDrive 'device-timeline-export-filtered.json'
        $exportPath = Join-Path $TestDrive 'device-timeline-export-filtered-output.json'
        @"
{
  "ChunkIndex": 0,
  "Events": [
    {
      "ActionType": "ProcessCreated",
      "Id": 1
    },
    {
      "ActionType": "NetworkConnectionSuccess",
      "Id": 2
    }
  ],
  "EventCount": 2
}
"@ | Set-Content -Path $chunkFile -Encoding UTF8

        $script:FakeTimelineResults = @(
            [pscustomobject]@{
                ChunkIndex     = 0
                Success        = $true
                FilePath       = $chunkFile
                EventCount     = 2
                FromDate       = $script:FromDate
                ToDate         = $script:ToDate
                ElapsedSeconds = 1
                PagesRetrieved = 1
                FileSizeKB     = 1
            }
        )

        $result = Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ExportPath (Join-Path $TestDrive 'chunk-root') -OutputPath $exportPath -EventType 'Process*'
        $exportedEvents = Get-Content -Path $exportPath -Raw | ConvertFrom-Json

        $result.TotalEvents | Should -Be 1
        @($exportedEvents).Count | Should -Be 1
        $exportedEvents[0].ActionType | Should -Be 'ProcessCreated'
        $exportedEvents[0].Id | Should -Be 1
    }

    It 'skips unreadable completed chunk files during export when partial results are allowed' {
        $goodFile = Join-Path $TestDrive 'device-timeline-export-readable.json'
        $badFile = Join-Path $TestDrive 'device-timeline-export-unreadable.json'
        $exportPath = Join-Path $TestDrive 'device-timeline-export.json'
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

        $result = Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -ExportPath (Join-Path $TestDrive 'chunk-root') -OutputPath $exportPath -AllowPartial -WarningAction SilentlyContinue
        $exportedEvents = Get-Content -Path $exportPath -Raw | ConvertFrom-Json

        $result.OutputPath | Should -Be $exportPath
        $result.TotalEvents | Should -Be 1
        @($exportedEvents).Count | Should -Be 1
        $exportedEvents[0].ActionType | Should -Be 'ProcessCreated'
    }
}
