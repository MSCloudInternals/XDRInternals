Describe 'Endpoint timeline helpers' {
    It 'keeps OutputPath as the public export path and preserves ExportPath as an alias' {
        $command = Get-Command Get-XdrEndpointDeviceTimeline

        $command.Parameters.ContainsKey('OutputPath') | Should -BeTrue
        $command.Parameters.ContainsKey('WorkingDirectory') | Should -BeTrue
        $command.Parameters.ContainsKey('ExportFormat') | Should -BeTrue
        $command.Parameters.ContainsKey('AllowPartial') | Should -BeTrue
        $command.Parameters.ContainsKey('RequestTimeoutSeconds') | Should -BeTrue
        $command.Parameters.ContainsKey('DiagnosticsPath') | Should -BeTrue
        $command.Parameters.ContainsKey('PaginationDelayMinMilliseconds') | Should -BeTrue
        $command.Parameters.ContainsKey('PaginationDelayMaxMilliseconds') | Should -BeTrue
        $command.Parameters.ContainsKey('ExportPath') | Should -BeFalse
        $command.Parameters['OutputPath'].Aliases | Should -Contain 'ExportPath'
    }

    It 'validates LastNDays range before execution' {
        {
            Get-XdrEndpointDeviceTimeline -DeviceId ('a' * 40) -LastNDays 0
        } | Should -Throw '*LastNDays*'
    }

    It 'returns only Prev continuation paths' {
        InModuleScope XDRInternals {
            $responseWithPrev = [pscustomobject]@{
                Prev = '/machines/example/events?page=1'
            }
            $responseWithNextOnly = [pscustomobject]@{
                Next = '/machines/example/events?page=2'
            }

            (Get-XdrEndpointTimelineContinuationPath -Response $responseWithPrev) | Should -Be '/machines/example/events?page=1'
            (Get-XdrEndpointTimelineContinuationPath -Response $responseWithNextOnly) | Should -BeNullOrEmpty
        }
    }

    It 'builds continuation URIs from Prev links only' {
        InModuleScope XDRInternals {
            $relativeResponse = [pscustomobject]@{ Prev = '/machines/example/events?page=2' }
            $absoluteResponse = [pscustomobject]@{ Prev = 'https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/example/events?page=2' }

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

    It 'reads endpoint chunk files and skips unreadable ones when partial data is allowed' {
        $chunkPath = Join-Path $TestDrive 'chunk_bad.json'
        Set-Content -Path $chunkPath -Value '{"Events":[{"EventType":"ProcessCreated"}' -Encoding UTF8

        InModuleScope XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            $result = Read-XdrEndpointTimelineChunkFile -File (Get-Item -Path $ChunkPath) -AllowPartial -WarningAction SilentlyContinue

            $result | Should -BeNullOrEmpty
        }
    }

    It 'extracts raw event JSON from chunk envelopes' {
        $chunkPath = Join-Path $TestDrive 'chunk_good.json'
        Set-Content -Path $chunkPath -Value '{"ChunkIndex":0,"Events":[{"EventType":"ProcessCreated"},{"EventType":"NetworkConnection"}],"EventCount":2}' -Encoding UTF8

        InModuleScope XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            $result = Get-XdrEndpointTimelineChunkEventsJson -File (Get-Item -Path $ChunkPath)

            $result | Should -Be '{"EventType":"ProcessCreated"},{"EventType":"NetworkConnection"}'
        }
    }

    It 'throws unreadable endpoint chunk errors when partial data is not allowed' {
        $chunkPath = Join-Path $TestDrive 'chunk_bad_strict.json'
        Set-Content -Path $chunkPath -Value '{"Events":[{"EventType":"ProcessCreated"}' -Encoding UTF8

        InModuleScope XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            { Read-XdrEndpointTimelineChunkFile -File (Get-Item -Path $ChunkPath) } |
                Should -Throw '*Conversion from JSON failed*'
        }
    }

    It 'sorts endpoint events by timestamp descending' {
        InModuleScope XDRInternals {
            $events = @(
                [pscustomobject]@{ Timestamp = '2026-05-10T01:00:00Z'; EventType = 'Older' }
                [pscustomobject]@{ Timestamp = '2026-05-10T03:00:00Z'; EventType = 'Newer' }
                [pscustomobject]@{ Timestamp = '2026-05-10T02:00:00Z'; EventType = 'Middle' }
            )

            $sorted = Get-XdrEndpointTimelineSortedEvent -Events $events

            @($sorted | ForEach-Object EventType) | Should -Be @('Newer', 'Middle', 'Older')
        }
    }

    It 'allows empty event collections during chunk merges' {
        InModuleScope XDRInternals {
            $sorted = Get-XdrEndpointTimelineSortedEvent -Events @()

            @($sorted).Count | Should -Be 0
        }
    }

    It 'writes structured diagnostics to disk' {
        $diagnosticsPath = Join-Path $TestDrive 'timeline.diagnostics.json'

        InModuleScope XDRInternals -Parameters @{ DiagnosticsPath = $diagnosticsPath } {
            param($DiagnosticsPath)

            Write-XdrEndpointTimelineDiagnosticFile -Path $DiagnosticsPath -Diagnostics ([ordered]@{
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
}
