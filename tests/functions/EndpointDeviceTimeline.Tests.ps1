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
            Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -OutputPath $TestDrive
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

        $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -OutputPath $TestDrive -AllowPartial)

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

        $result = @(Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -OutputPath $TestDrive -AllowPartial -WarningAction SilentlyContinue)

        $result.Count | Should -Be 1
        $result[0].ActionType | Should -Be 'ProcessCreated'
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

        $result = Get-XdrEndpointDeviceTimeline -DeviceId $script:DeviceId -FromDate $script:FromDate -ToDate $script:ToDate -OutputPath $TestDrive -ExportPath $exportPath -AllowPartial -WarningAction SilentlyContinue
        $exportedEvents = Get-Content -Path $exportPath -Raw | ConvertFrom-Json

        $result.ExportPath | Should -Be $exportPath
        $result.TotalEvents | Should -Be 1
        @($exportedEvents).Count | Should -Be 1
        $exportedEvents[0].ActionType | Should -Be 'ProcessCreated'
    }
}