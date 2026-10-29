Describe 'Endpoint timeline service-bound precision' {
    BeforeAll {
        InModuleScope XDRInternals {
            function script:New-PrecisionPrev {
                param([string]$Uri, [datetime]$Cursor)
                $values = [ordered]@{}
                foreach ($pair in ([uri]$Uri).Query.TrimStart('?').Split('&')) {
                    $kv = $pair.Split('=', 2)
                    if ($kv[0] -ne 'correlationId') { $values[$kv[0]] = [uri]::UnescapeDataString($kv[1]) }
                }
                $values.toDate = $Cursor.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
                $values.IsScrollingForward = 'false'; $values.ReportIdForScrolling = 'opaque-test'
                $query = ($values.GetEnumerator() | ForEach-Object { $_.Key + '=' + [uri]::EscapeDataString([string]$_.Value) }) -join '&'
                return "/machines/$('a' * 40)/events?$query"
            }
        }
    }
    It 'follows two Prev pages using the sent millisecond bounds for fractional logical dates' {
        InModuleScope XDRInternals -Parameters @{ Root = $TestDrive } {
            $script:PrecisionCalls = 0
            $script:SentFrom = $null; $script:SentTo = $null
            Mock Invoke-RestMethod {
                param($Uri)
                $script:PrecisionCalls++
                if ($script:PrecisionCalls -eq 1) {
                    foreach ($pair in ([uri]$Uri).Query.TrimStart('?').Split('&')) {
                        $kv = $pair.Split('=', 2)
                        if ($kv[0] -eq 'fromDate') { $script:SentFrom = [uri]::UnescapeDataString($kv[1]) }
                        if ($kv[0] -eq 'toDate') { $script:SentTo = [uri]::UnescapeDataString($kv[1]) }
                    }
                    [pscustomobject]@{
                        Items = @([pscustomobject]@{ Id = 'first'; ActionTimeIsoString = '2026-01-01T00:30:00.1234567Z' })
                        PartialResponseReasons = @()
                        Prev = New-PrecisionPrev -Uri $Uri -Cursor ([datetime]'2026-01-01T00:30:00.1234566Z')
                    }
                } else {
                    [pscustomobject]@{ Items = @([pscustomobject]@{ Id = 'second'; ActionTimeIsoString = '2026-01-01T00:15:00.1234567Z' }); PartialResponseReasons = @(); Prev = $null }
                }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = @{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00.1234567Z'; ToDate = [datetime]'2026-01-01T01:00:00.9876543Z'; FileName = 'precision.ndjson' }
            $shared = @{ PartsPath = $Root; BaseUrl = 'https://security.microsoft.com'; DeviceId = ('a' * 40); PageSize = 1000; IncludeSentinelEvents = $false; MaxRetries = 1; MaxPagesPerChunk = 10; RequestTimeoutSeconds = 10; CookieData = @(); HeadersData = @{} }
            $status = [Collections.Concurrent.ConcurrentDictionary[int, object]]::new()
            $result = & $worker $chunk $shared $status
            $result.Success | Should -BeTrue -Because $result.Error
            $script:PrecisionCalls | Should -Be 2
            $script:SentFrom | Should -Be '2026-01-01T00:00:00.123Z'
            $script:SentTo | Should -Be '2026-01-01T01:00:00.988Z'
            @((Get-Content (Join-Path $Root 'precision.ndjson')) | ForEach-Object { ($_ | ConvertFrom-Json).Id }) | Should -Be @('first', 'second')
        }
    }

    It 'filters both millisecond padding margins while retaining exact logical lower boundary' {
        InModuleScope XDRInternals -Parameters @{ Root = $TestDrive } {
            Mock Invoke-RestMethod {
                [pscustomobject]@{ Items = @(
                    [pscustomobject]@{ Id = 'upper-padding'; ActionTimeIsoString = '2026-01-01T01:00:00.9876545Z' },
                    [pscustomobject]@{ Id = 'upper-boundary'; ActionTimeIsoString = '2026-01-01T01:00:00.9876543Z' },
                    [pscustomobject]@{ Id = 'inside'; ActionTimeIsoString = '2026-01-01T00:30:00.0000000Z' },
                    [pscustomobject]@{ Id = 'lower-boundary'; ActionTimeIsoString = '2026-01-01T00:00:00.1234567Z' },
                    [pscustomobject]@{ Id = 'lower-padding'; ActionTimeIsoString = '2026-01-01T00:00:00.1234000Z' }
                ); PartialResponseReasons = @(); Prev = $null }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = @{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00.1234567Z'; ToDate = [datetime]'2026-01-01T01:00:00.9876543Z'; FileName = 'padding.ndjson' }
            $shared = @{ PartsPath = $Root; BaseUrl = 'https://security.microsoft.com'; DeviceId = ('a' * 40); PageSize = 1000; IncludeSentinelEvents = $false; MaxRetries = 1; MaxPagesPerChunk = 10; RequestTimeoutSeconds = 10; CookieData = @(); HeadersData = @{} }
            $result = & $worker $chunk $shared ([Collections.Concurrent.ConcurrentDictionary[int, object]]::new())
            $result.Success | Should -BeTrue -Because $result.Error
            $result.EventCount | Should -Be 2
            $result.BoundaryTimestampCount | Should -Be 2
            @((Get-Content (Join-Path $Root 'padding.ndjson')) | ForEach-Object { ($_ | ConvertFrom-Json).Id }) | Should -Be @('inside', 'lower-boundary')
        }
    }

    It 'assigns a fractional shared boundary to exactly one adjacent chunk' {
        InModuleScope XDRInternals -Parameters @{ Root = $TestDrive } {
            $script:AdjacentCall = 0
            Mock Invoke-RestMethod {
                $script:AdjacentCall++
                [pscustomobject]@{ Items = @(
                    [pscustomobject]@{ Id = 'boundary'; ActionTimeIsoString = '2026-01-01T01:00:00.2222222Z' },
                    [pscustomobject]@{ Id = 'before'; ActionTimeIsoString = '2026-01-01T01:00:00.2222221Z' }
                ); PartialResponseReasons = @(); Prev = $null }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $shared = @{ PartsPath = $Root; BaseUrl = 'https://security.microsoft.com'; DeviceId = ('a' * 40); PageSize = 1000; IncludeSentinelEvents = $false; MaxRetries = 1; MaxPagesPerChunk = 10; RequestTimeoutSeconds = 10; CookieData = @(); HeadersData = @{} }
            $left = & $worker @{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00.1111111Z'; ToDate = [datetime]'2026-01-01T01:00:00.2222222Z'; FileName = 'left.ndjson' } $shared ([Collections.Concurrent.ConcurrentDictionary[int, object]]::new())
            $right = & $worker @{ Index = 1; FromDate = [datetime]'2026-01-01T01:00:00.2222222Z'; ToDate = [datetime]'2026-01-01T02:00:00.3333333Z'; FileName = 'right.ndjson' } $shared ([Collections.Concurrent.ConcurrentDictionary[int, object]]::new())
            $left.Success | Should -BeTrue -Because $left.Error
            $right.Success | Should -BeTrue -Because $right.Error
            (Get-Content (Join-Path $Root 'left.ndjson') | ConvertFrom-Json).Id | Should -Be 'before'
            (Get-Content (Join-Path $Root 'right.ndjson') | ConvertFrom-Json).Id | Should -Be 'boundary'
        }
    }

    It 'still rejects a timestamp outside the sent envelope: <Side>' -ForEach @(
        @{ Side = 'lower'; Timestamp = '2026-01-01T00:00:00.1229999Z' }
        @{ Side = 'upper'; Timestamp = '2026-01-01T01:00:00.9880001Z' }
    ) {
        InModuleScope XDRInternals -Parameters @{ Root = $TestDrive; Timestamp = $Timestamp } {
            Mock Invoke-RestMethod {
                [pscustomobject]@{ Items = @([pscustomobject]@{ ActionTimeIsoString = $Timestamp }); PartialResponseReasons = @(); Prev = $null }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = @{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00.1234567Z'; ToDate = [datetime]'2026-01-01T01:00:00.9876543Z'; FileName = 'outside.ndjson' }
            $shared = @{ PartsPath = $Root; BaseUrl = 'https://security.microsoft.com'; DeviceId = ('a' * 40); PageSize = 1000; IncludeSentinelEvents = $false; MaxRetries = 1; MaxPagesPerChunk = 10; RequestTimeoutSeconds = 10; CookieData = @(); HeadersData = @{} }
            $result = & $worker $chunk $shared ([Collections.Concurrent.ConcurrentDictionary[int, object]]::new())
            $result.Success | Should -BeFalse
            Test-Path (Join-Path $Root 'outside.ndjson') | Should -BeFalse
        }
    }
    It 'follows Prev through an upper-padding-only page and a lower-padding-only terminal page' {
        InModuleScope XDRInternals -Parameters @{ Root = $TestDrive } {
            $script:PaddingPage = 0
            Mock Invoke-RestMethod {
                param($Uri)
                $script:PaddingPage++
                switch ($script:PaddingPage) {
                    1 {
                        [pscustomobject]@{ Items = @(
                            [pscustomobject]@{ Id = 'upper-newer'; ActionTimeIsoString = '2026-01-01T01:00:00.9876546Z' },
                            [pscustomobject]@{ Id = 'upper-oldest'; ActionTimeIsoString = '2026-01-01T01:00:00.9876544Z' }
                        ); PartialResponseReasons = @(); Prev = New-PrecisionPrev -Uri $Uri -Cursor ([datetimeoffset]'2026-01-01T01:00:00.9876543Z').UtcDateTime }
                    }
                    2 {
                        [pscustomobject]@{ Items = @([pscustomobject]@{ Id = 'inside'; ActionTimeIsoString = '2026-01-01T00:30:00.0000000Z' }); PartialResponseReasons = @(); Prev = New-PrecisionPrev -Uri $Uri -Cursor ([datetimeoffset]'2026-01-01T00:29:59.9999999Z').UtcDateTime }
                    }
                    3 {
                        [pscustomobject]@{ Items = @([pscustomobject]@{ Id = 'lower-padding'; ActionTimeIsoString = '2026-01-01T00:00:00.1234000Z' }); PartialResponseReasons = @(); Prev = $null }
                    }
                    default { throw 'Unexpected extra page' }
                }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = @{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00.1234567Z'; ToDate = [datetime]'2026-01-01T01:00:00.9876543Z'; FileName = 'padding-pages.ndjson' }
            $shared = @{ PartsPath = $Root; BaseUrl = 'https://security.microsoft.com'; DeviceId = ('a' * 40); PageSize = 1000; IncludeSentinelEvents = $false; MaxRetries = 1; MaxPagesPerChunk = 10; RequestTimeoutSeconds = 10; CookieData = @(); HeadersData = @{} }
            $result = & $worker $chunk $shared ([Collections.Concurrent.ConcurrentDictionary[int, object]]::new())
            $result.Success | Should -BeTrue -Because $result.Error
            $result.PageCount | Should -Be 3
            $result.EventCount | Should -Be 1
            (Get-Content (Join-Path $Root 'padding-pages.ndjson') | ConvertFrom-Json).Id | Should -Be 'inside'
        }
    }

    It 'returns an empty part for a valid padding-only terminal response' {
        InModuleScope XDRInternals -Parameters @{ Root = $TestDrive } {
            Mock Invoke-RestMethod {
                [pscustomobject]@{ Items = @([pscustomobject]@{ ActionTimeIsoString = '2026-01-01T00:00:00.1234000Z' }); PartialResponseReasons = @(); Prev = $null }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = @{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00.1234567Z'; ToDate = [datetime]'2026-01-01T01:00:00.9876543Z'; FileName = 'padding-only.ndjson' }
            $shared = @{ PartsPath = $Root; BaseUrl = 'https://security.microsoft.com'; DeviceId = ('a' * 40); PageSize = 1000; IncludeSentinelEvents = $false; MaxRetries = 1; MaxPagesPerChunk = 10; RequestTimeoutSeconds = 10; CookieData = @(); HeadersData = @{} }
            $result = & $worker $chunk $shared ([Collections.Concurrent.ConcurrentDictionary[int, object]]::new())
            $result.Success | Should -BeTrue -Because $result.Error
            $result.EventCount | Should -Be 0
            $result.FileBytes | Should -Be 0
        }
    }

    It 'rejects reversed raw ordering even when all rows are envelope padding' {
        InModuleScope XDRInternals -Parameters @{ Root = $TestDrive } {
            Mock Invoke-RestMethod {
                [pscustomobject]@{ Items = @(
                    [pscustomobject]@{ ActionTimeIsoString = '2026-01-01T01:00:00.9876544Z' },
                    [pscustomobject]@{ ActionTimeIsoString = '2026-01-01T01:00:00.9876546Z' }
                ); PartialResponseReasons = @(); Prev = $null }
            }
            $worker = New-XdrEndpointTimelineExportWorker
            $chunk = @{ Index = 0; FromDate = [datetime]'2026-01-01T00:00:00.1234567Z'; ToDate = [datetime]'2026-01-01T01:00:00.9876543Z'; FileName = 'padding-order.ndjson' }
            $shared = @{ PartsPath = $Root; BaseUrl = 'https://security.microsoft.com'; DeviceId = ('a' * 40); PageSize = 1000; IncludeSentinelEvents = $false; MaxRetries = 1; MaxPagesPerChunk = 10; RequestTimeoutSeconds = 10; CookieData = @(); HeadersData = @{} }
            $result = & $worker $chunk $shared ([Collections.Concurrent.ConcurrentDictionary[int, object]]::new())
            $result.Success | Should -BeFalse
            $result.Error | Should -BeLike '*newest-first order*'
            Test-Path (Join-Path $Root 'padding-order.ndjson') | Should -BeFalse
        }
    }

}
