BeforeAll {
    $script:HasStartThreadJob = $null -ne (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)

    if (-not ('IdentityUserTimelineTestJob' -as [type])) {
        Add-Type -TypeDefinition @"
using System.Management.Automation;

public sealed class IdentityUserTimelineTestJob : Job
{
    public IdentityUserTimelineTestJob() : base("Get-XdrIdentityUserTimeline", "IdentityUserTimelineTestJob")
    {
        SetJobState(JobState.Completed);
    }

    public override string StatusMessage => string.Empty;
    public override bool HasMoreData => false;
    public override string Location => "localhost";
    public override void StopJob() { }
}
"@
    }
}

Describe 'Get-XdrIdentityUserTimeline hardening' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrIdentityHeaders { @{} } -ModuleName XDRInternals
        Mock Get-XdrIdentityUser {
            [PSCustomObject]@{
                displayName = 'Timeline User'
                ids = [PSCustomObject]@{ aad = '11111111-1111-1111-1111-111111111111'; upn = 'user@contoso.com' }
            }
        } -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
        }

        $script:FromDate = [datetime]'2026-01-01T00:00:00Z'
        $script:ToDate = [datetime]'2026-01-01T02:00:00Z'
        $script:FakeIdentityTimelineResults = @()
        $script:ChunkEvents = @()

        if ($script:HasStartThreadJob) {
            Mock Start-ThreadJob {
                param($ArgumentList)
                $runTempPath = [string]$ArgumentList[4]
                if ($script:ChunkEvents.Count -gt 0) {
                    New-Item -Path $runTempPath -ItemType Directory -Force | Out-Null
                    $payload = [ordered]@{
                        ChunkIndex = 0
                        FromDate = $script:FromDate.ToString('o')
                        ToDate = $script:ToDate.ToString('o')
                        EventCount = $script:ChunkEvents.Count
                        Events = $script:ChunkEvents
                    } | ConvertTo-Json -Depth 20 -Compress
                    [System.IO.File]::WriteAllText(
                        (Join-Path $runTempPath 'chunk_0000_20260101_20260101.json'),
                        $payload,
                        [System.Text.UTF8Encoding]::new($false)
                    )
                }
                [IdentityUserTimelineTestJob]::new()
            } -ModuleName XDRInternals
            Mock Receive-Job { $script:FakeIdentityTimelineResults } -ModuleName XDRInternals
            Mock Remove-Job {} -ModuleName XDRInternals
        }
    }

    It 'exposes AllowPartial' {
        (Get-Command Get-XdrIdentityUserTimeline).Parameters.ContainsKey('AllowPartial') | Should -BeTrue
    }

    It 'classifies authentication and permanent HTTP failures as non-retryable' {
        $definition = (Get-Command Get-XdrIdentityUserTimeline).ScriptBlock.ToString()

        $definition | Should -Match '\$statusCode -in @\(401, 403\)'
        $definition | Should -Match '\$chunkFailureIsRetryable = \$false'
        $definition | Should -Match '\$nonRetryableChunkFailure'
    }

    It 'fails when any chunk fails unless partial output is explicitly allowed' {
        if (-not $script:HasStartThreadJob) {
            Set-ItResult -Skipped -Because 'Start-ThreadJob is unavailable in this session.'
        }
        $script:FakeIdentityTimelineResults = @(
            [PSCustomObject]@{
                ChunkIndex = 0; Success = $false; Error = 'simulated failure'
                FromDate = $script:FromDate; ToDate = $script:ToDate
                ElapsedSeconds = 1; PagesRetrieved = 0; FileSizeKB = 0
            }
        )

        {
            Get-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:ToDate -OutputPath $TestDrive
        } | Should -Throw -ExpectedMessage '*failed for 1 chunk*Use -AllowPartial*'
    }

    It 'retains distinct EventIds and returns completed chunks with AllowPartial' {
        if (-not $script:HasStartThreadJob) {
            Set-ItResult -Skipped -Because 'Start-ThreadJob is unavailable in this session.'
        }
        $script:ChunkEvents = @(
            [PSCustomObject]@{ EventId = 'event-1'; Id = 'volatile-1'; RowNumber = 1; Timestamp = '2026-01-01T01:00:00Z'; Title = 'Same' },
            [PSCustomObject]@{ EventId = 'event-2'; Id = 'volatile-2'; RowNumber = 2; Timestamp = '2026-01-01T01:00:00Z'; Title = 'Same' }
        )
        $script:FakeIdentityTimelineResults = @(
            [PSCustomObject]@{
                ChunkIndex = 0; Success = $true; EventCount = 2
                FromDate = $script:FromDate; ToDate = $script:ToDate
                ElapsedSeconds = 1; PagesRetrieved = 1; FileSizeKB = 1
            },
            [PSCustomObject]@{
                ChunkIndex = 1; Success = $false; Error = 'simulated failure'
                FromDate = $script:FromDate; ToDate = $script:ToDate
                ElapsedSeconds = 1; PagesRetrieved = 0; FileSizeKB = 0
            }
        )

        $result = @(Get-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:ToDate -OutputPath $TestDrive -AllowPartial -WarningAction SilentlyContinue)

        $result.Count | Should -Be 2
        @($result.EventId | Sort-Object) | Should -Be @('event-1', 'event-2')
        @($result.Id | Sort-Object) | Should -Be @('volatile-1', 'volatile-2')
    }

    It 'retains EventId reuse across timestamps and suppresses only volatile duplicate representations' {
        if (-not $script:HasStartThreadJob) {
            Set-ItResult -Skipped -Because 'Start-ThreadJob is unavailable in this session.'
        }
        $script:ChunkEvents = @(
            [PSCustomObject]@{ EventId = 'reused'; Timestamp = '2026-01-01T01:30:00Z'; Id = 'newer'; RowNumber = 1; Description = 'newer description'; Title = 'Stable' },
            [PSCustomObject]@{ EventId = 'reused'; Timestamp = '2026-01-01T01:00:00Z'; Id = 'first'; RowNumber = 2; Description = 'first description'; Title = 'Stable' },
            [PSCustomObject]@{ EventId = 'reused'; Timestamp = '2026-01-01T01:00:00Z'; Id = 'second'; RowNumber = 9; Description = 'second description'; Title = 'Stable' }
        )
        $script:FakeIdentityTimelineResults = @(
            [PSCustomObject]@{
                ChunkIndex = 0; Success = $true; EventCount = 3
                FromDate = $script:FromDate; ToDate = $script:ToDate
                ElapsedSeconds = 1; PagesRetrieved = 1; FileSizeKB = 1
            }
        )

        $result = @(Get-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:ToDate -OutputPath $TestDrive)

        $result.Count | Should -Be 2
        @($result.Id) | Should -Be @('newer', 'first')
        @($result.Description) | Should -Be @('newer description', 'first description')
    }

    It 'fails closed on <Name> unless partial output is explicitly allowed' -ForEach @(
        @{ Name = 'missing timestamps'; InvalidEvent = [PSCustomObject]@{ EventId = 'invalid-missing'; Title = 'Missing' }; Error = '*missing timestamp*' },
        @{ Name = 'timestamp parse errors'; InvalidEvent = [PSCustomObject]@{ EventId = 'invalid-parse'; Timestamp = 'not-a-date'; Title = 'Invalid' }; Error = '*timestamp parse error*' }
    ) {
        if (-not $script:HasStartThreadJob) {
            Set-ItResult -Skipped -Because 'Start-ThreadJob is unavailable in this session.'
        }
        $script:ChunkEvents = @(
            [PSCustomObject]@{ EventId = 'valid'; Timestamp = '2026-01-01T01:00:00Z'; Title = 'Valid' },
            $InvalidEvent
        )
        $script:FakeIdentityTimelineResults = @(
            [PSCustomObject]@{
                ChunkIndex = 0; Success = $true; EventCount = 2
                FromDate = $script:FromDate; ToDate = $script:ToDate
                ElapsedSeconds = 1; PagesRetrieved = 1; FileSizeKB = 1
            }
        )

        {
            Get-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate `
                -ToDate $script:ToDate -OutputPath $TestDrive
        } | Should -Throw -ExpectedMessage $Error

        $partialResult = @(Get-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate `
                -ToDate $script:ToDate -OutputPath $TestDrive -AllowPartial)
        $partialResult.Count | Should -Be 1
        $partialResult[0].EventId | Should -Be 'valid'
    }
}
