Describe 'Export-XdrCloudAppsActivityTimeline worker' {
    BeforeEach {
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
        }
    }

    It 'uses timestamp keyset pagination and writes every counted activity once' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $from = [datetime]'2026-01-01T00:00:00Z'
            $to = $from.AddHours(1)
            $firstTimestamp = [datetimeoffset]::new($from.AddMinutes(50)).ToUnixTimeMilliseconds()
            $firstPage = @(
                for ($i = 0; $i -lt 250; $i++) {
                    [ordered]@{ _id = "activity-$i"; timestamp = $firstTimestamp - $i; date = [datetimeoffset]::FromUnixTimeMilliseconds($firstTimestamp - $i).ToString('o') }
                }
            )
            $oldestTimestamp = [long]$firstPage[-1].timestamp
            $secondPage = @(
                $firstPage[-1],
                [ordered]@{ _id = 'activity-250'; timestamp = $oldestTimestamp - 1; date = [datetimeoffset]::FromUnixTimeMilliseconds($oldestTimestamp - 1).ToString('o') }
            )
            $script:ActivityRequest = 0
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') {
                    return [PSCustomObject]@{ total = 251; moreThanTotal = $false; searchedSince = 'test' }
                }
                $script:ActivityRequest++
                if ($script:ActivityRequest -eq 1) {
                    return [PSCustomObject]@{ data = $firstPage; hasNext = $true; performAsyncTotal = $true }
                }
                $request = $Body | ConvertFrom-Json
                $request.filters.date.lte | Should -Be $oldestTimestamp
                return [PSCustomObject]@{ data = $secondPage; hasNext = $false; performAsyncTotal = $true }
            }

            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = $from; ToDate = $to; Archived = $false; FileName = 'part.ndjson' }
            $shared = @{
                PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}
                CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1
                RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100
            }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 251
            $result.ExpectedEventCount | Should -Be 251
            $result.PageCount | Should -Be 2
            $result.RewindCount | Should -Be 1
            @(Get-Content -LiteralPath $result.FilePath) | Should -HaveCount 251
            Should -Invoke Invoke-RestMethod -Times 3 -Exactly
        }
    }

    It 'continues timestamp keyset pagination when a short page reports more data' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $from = [datetime]'2026-01-01T00:00:00Z'
            $newer = [datetimeoffset]::new($from.AddMinutes(40)).ToUnixTimeMilliseconds()
            $boundary = [datetimeoffset]::new($from.AddMinutes(30)).ToUnixTimeMilliseconds()
            $older = [datetimeoffset]::new($from.AddMinutes(20)).ToUnixTimeMilliseconds()
            $script:ActivityRequest = 0
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') {
                    return [PSCustomObject]@{ total = 3; moreThanTotal = $false; searchedSince = 'test' }
                }
                $script:ActivityRequest++
                if ($script:ActivityRequest -eq 1) {
                    return [PSCustomObject]@{
                        data = @(
                            [PSCustomObject]@{ _id = 'newer'; timestamp = $newer },
                            [PSCustomObject]@{ _id = 'boundary'; timestamp = $boundary }
                        )
                        hasNext = $true
                    }
                }
                $request = $Body | ConvertFrom-Json
                $request.filters.date.lte | Should -Be $boundary
                return [PSCustomObject]@{
                    data = @(
                        [PSCustomObject]@{ _id = 'boundary'; timestamp = $boundary },
                        [PSCustomObject]@{ _id = 'older'; timestamp = $older }
                    )
                    hasNext = $false
                }
            }

            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = $from; ToDate = $from.AddHours(1); Archived = $false; FileName = 'short-page.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 3
            $result.PageCount | Should -Be 2
            $result.RewindCount | Should -Be 1
            @(Get-Content -LiteralPath $result.FilePath) | Should -HaveCount 3
        }
    }

    It 'preserves response keys that differ only by case' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $from = [datetime]'2026-01-01T00:00:00Z'
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') {
                    return [PSCustomObject]@{ total = 1; moreThanTotal = $false; searchedSince = 'test' }
                }
                return '{"data":[{"_id":"activity-1","timestamp":1767227400000,"level":"low","Level":"High"}],"hasNext":false,"performAsyncTotal":true}'
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = $from; ToDate = $from.AddHours(1); Archived = $false; FileName = 'case.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status
            $line = Get-Content -LiteralPath $result.FilePath -Raw

            $result.Success | Should -BeTrue
            $line | Should -Match '"level":"low"'
            $line | Should -Match '"Level":"High"'
        }
    }

    It 'uses the archived range filter for archived chunks' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $from = [datetime]'2025-01-01T00:00:00Z'
            Mock Invoke-RestMethod {
                $request = $Body | ConvertFrom-Json
                $request.filters.date.range | Should -Not -BeNullOrEmpty
                $request.filters.date.PSObject.Properties.Name | Should -Not -Contain 'gte'
                if ($Uri -like '*/count/') {
                    $Uri | Should -BeLike '*/archived_activities/count/'
                    return [PSCustomObject]@{ total = 0; moreThanTotal = $false; searchedSince = 'test' }
                }
                $Uri | Should -BeLike '*/archived_activities/'
                return [PSCustomObject]@{ data = @(); hasNext = $false }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = $from; ToDate = $from.AddHours(1); Archived = $true; FileName = 'archived.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.Archived | Should -BeTrue
            $result.EventCount | Should -Be 0
        }
    }

    It 'accepts an empty response only when the count is zero' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') { return [PSCustomObject]@{ total = 0; moreThanTotal = $false; searchedSince = 'test' } }
                return [PSCustomObject]@{}
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'empty.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 0
            (Get-Item -LiteralPath $result.FilePath).Length | Should -Be 0
        }
    }

    It 'fails closed when the list does not match the count API' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $timestamp = [datetimeoffset]::new([datetime]'2026-01-01T00:30:00Z').ToUnixTimeMilliseconds()
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') { return [PSCustomObject]@{ total = 2; moreThanTotal = $false; searchedSince = 'test' } }
                return [PSCustomObject]@{ data = @([PSCustomObject]@{ _id = 'one'; timestamp = $timestamp }); hasNext = $false }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'mismatch.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.FailureClass | Should -Be 'PartialResponse'
            Test-Path -LiteralPath $result.FilePath | Should -BeFalse
        }
    }

    It 'records a persistent count overestimate after fresh-window retries are exhausted' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $timestamp = [datetimeoffset]::new([datetime]'2026-01-01T00:30:00Z').ToUnixTimeMilliseconds()
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') { return [PSCustomObject]@{ total = 2; moreThanTotal = $false; searchedSince = 'test' } }
                return [PSCustomObject]@{ data = @([PSCustomObject]@{ _id = 'one'; timestamp = $timestamp }); hasNext = $false }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'stable-mismatch.ndjson'; Attempt = 2 }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100; MaxCountMismatchRestarts = 2 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 1
            $result.ExpectedEventCount | Should -Be 2
            $result.CountDelta | Should -Be -1
        }
    }

    It 'suppresses repeated stable activity representations before count validation' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $newer = [datetimeoffset]::new([datetime]'2026-01-01T00:40:00Z').ToUnixTimeMilliseconds()
            $older = [datetimeoffset]::new([datetime]'2026-01-01T00:30:00Z').ToUnixTimeMilliseconds()
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') { return [PSCustomObject]@{ total = 2; moreThanTotal = $false; searchedSince = 'test' } }
                return [PSCustomObject]@{
                    data = @(
                        [PSCustomObject]@{ _id = 'one'; timestamp = $newer },
                        [PSCustomObject]@{ _id = 'one'; timestamp = $newer },
                        [PSCustomObject]@{ _id = 'two'; timestamp = $older }
                    )
                    hasNext = $false
                }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'duplicates.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 2
            $result.DuplicateRepresentationCount | Should -Be 1
            @(Get-Content -LiteralPath $result.FilePath) | Should -HaveCount 2
        }
    }

    It 'preserves unique activities returned beyond the count API snapshot' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $timestamp = [datetimeoffset]::new([datetime]'2026-01-01T00:30:00Z').ToUnixTimeMilliseconds()
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') { return [PSCustomObject]@{ total = 2; moreThanTotal = $false; searchedSince = 'test' } }
                return [PSCustomObject]@{
                    data = @(
                        [PSCustomObject]@{ _id = 'one'; timestamp = $timestamp + 2 },
                        [PSCustomObject]@{ _id = 'two'; timestamp = $timestamp + 1 },
                        [PSCustomObject]@{ _id = 'three'; timestamp = $timestamp }
                    )
                    hasNext = $false
                }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'count-delta.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 3
            $result.ExpectedEventCount | Should -Be 2
            $result.CountDelta | Should -Be 1
        }
    }

    It 'preserves identifier reuse at different timestamps' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $timestamp = [datetimeoffset]::new([datetime]'2026-01-01T00:30:00Z').ToUnixTimeMilliseconds()
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') { return [PSCustomObject]@{ total = 2; moreThanTotal = $false; searchedSince = 'test' } }
                return [PSCustomObject]@{
                    data = @(
                        [PSCustomObject]@{ _id = 'reused'; timestamp = $timestamp + 1 },
                        [PSCustomObject]@{ _id = 'reused'; timestamp = $timestamp }
                    )
                    hasNext = $false
                }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'reused.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 2
            $result.DuplicateRepresentationCount | Should -Be 0
        }
    }

    It 'preserves distinct payloads that share an identifier and timestamp' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $timestamp = [datetimeoffset]::new([datetime]'2026-01-01T00:30:00Z').ToUnixTimeMilliseconds()
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') { return [PSCustomObject]@{ total = 2; moreThanTotal = $false; searchedSince = 'test' } }
                return [PSCustomObject]@{
                    data = @(
                        [PSCustomObject]@{ _id = 'shared'; timestamp = $timestamp; detail = 'first' },
                        [PSCustomObject]@{ _id = 'shared'; timestamp = $timestamp; detail = 'second' }
                    )
                    hasNext = $false
                }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'shared.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 2
            $result.DuplicateRepresentationCount | Should -Be 0
        }
    }

    It 'fails closed on a missing activity timestamp' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') { return [PSCustomObject]@{ total = 1; moreThanTotal = $false; searchedSince = 'test' } }
                return [PSCustomObject]@{ data = @([PSCustomObject]@{ _id = 'missing' }); hasNext = $false }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'missing.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.MissingTimestampCount | Should -Be 1
        }
    }

    It 'classifies authentication failures without retrying them' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Forbidden)
                throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Forbidden', $response)
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'denied.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 3; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.FailureClass | Should -Be 'Authentication'
            $result.RetryCount | Should -Be 0
            Should -Invoke Invoke-RestMethod -Times 1 -Exactly
        }
    }

    It 'honors Retry-After when retrying a throttled request' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $script:RequestCount = 0
            Mock Start-Sleep {}
            Mock Invoke-RestMethod {
                $script:RequestCount++
                if ($script:RequestCount -eq 1) {
                    $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
                    $response.Headers.RetryAfter = [System.Net.Http.Headers.RetryConditionHeaderValue]::new([timespan]::FromSeconds(7))
                    throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Throttled', $response)
                }
                if ($Uri -like '*/count/') {
                    return [PSCustomObject]@{ total = 0; moreThanTotal = $false; searchedSince = 'test' }
                }
                return [PSCustomObject]@{ data = @(); hasNext = $false }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'throttled.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 2; RetryDelaySeconds = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.RetryCount | Should -Be 1
            Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -ge 7 }
        }
    }

    It 'retries transport and server failures before succeeding' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $script:RequestCount = 0
            Mock Start-Sleep {}
            Mock Invoke-RestMethod {
                $script:RequestCount++
                if ($script:RequestCount -eq 1) { throw [System.TimeoutException]::new('simulated timeout') }
                if ($script:RequestCount -eq 2) {
                    $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::InternalServerError)
                    throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('server failure', $response)
                }
                if ($Uri -like '*/count/') {
                    return [PSCustomObject]@{ total = 0; moreThanTotal = $false; searchedSince = 'test' }
                }
                return [PSCustomObject]@{ data = @(); hasNext = $false }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'transient.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 3; RetryDelaySeconds = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue
            $result.RetryCount | Should -Be 2
            Should -Invoke Start-Sleep -Times 2 -Exactly
            Should -Invoke Invoke-RestMethod -Times 4 -Exactly
        }
    }

    It 'uses created keyset pagination when one activity timestamp fills a complete page' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $from = [datetime]'2026-01-01T00:00:00Z'
            $expectedTimestampMilliseconds = [datetimeoffset]::new($from).ToUnixTimeMilliseconds()
            $firstCreated = $expectedTimestampMilliseconds + 1000
            $firstPage = @(
                for ($i = 0; $i -lt 250; $i++) {
                    [PSCustomObject]@{ _id = "dense-$i"; timestamp = $expectedTimestampMilliseconds; created = $firstCreated - $i }
                }
            )
            $oldestCreated = [long]$firstPage[-1].created
            $secondPage = @(
                $firstPage[-1],
                [PSCustomObject]@{ _id = 'dense-250'; timestamp = $expectedTimestampMilliseconds; created = $oldestCreated - 1 }
            )
            $script:ActivityRequest = 0
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') {
                    return [PSCustomObject]@{ total = 251; moreThanTotal = $false; searchedSince = 'test' }
                }
                $script:ActivityRequest++
                $request = $Body | ConvertFrom-Json
                if ($script:ActivityRequest -eq 1) {
                    $request.sortField | Should -Be 'date'
                    return [PSCustomObject]@{ data = $firstPage; hasNext = $true }
                }
                $request.sortField | Should -Be 'created'
                $request.filters.date.gte | Should -Be $expectedTimestampMilliseconds
                $request.filters.date.lte | Should -Be $expectedTimestampMilliseconds
                if ($script:ActivityRequest -eq 2) {
                    $request.filters.PSObject.Properties.Name | Should -Not -Contain 'created'
                    return [PSCustomObject]@{ data = $firstPage; hasNext = $true }
                }
                $request.filters.created.lte | Should -Be $oldestCreated
                return [PSCustomObject]@{ data = $secondPage; hasNext = $false }
            }

            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = $from; ToDate = $from.AddHours(1); Archived = $false; FileName = 'dense.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Error | Should -BeNullOrEmpty
            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 251
            $result.PageCount | Should -Be 3
            $result.RewindCount | Should -Be 2
            @(Get-Content -LiteralPath $result.FilePath) | Should -HaveCount 251
            Should -Invoke Invoke-RestMethod -Times 4 -Exactly
        }
    }

    It 'uses stable activity IDs to complete an archived dense timestamp' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $from = [datetime]'2025-01-01T00:00:00Z'
            $expectedTimestampMilliseconds = [datetimeoffset]::new($from).ToUnixTimeMilliseconds()
            $firstCreated = $expectedTimestampMilliseconds + 1000
            $firstPage = @(
                for ($i = 0; $i -lt 250; $i++) {
                    [PSCustomObject]@{ _id = "archived-$i"; timestamp = $expectedTimestampMilliseconds; created = $firstCreated - $i }
                }
            )
            $lastPage = @(
                [PSCustomObject]@{ _id = 'archived-250'; timestamp = $expectedTimestampMilliseconds; created = $firstCreated - 250 }
            )
            $ascendingFirstPage = @($firstPage[249..0])
            $script:ActivityRequest = 0
            $script:CountRequest = 0
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') {
                    $script:CountRequest++
                    $count = if ($script:CountRequest -eq 1) { 251 } else { 252 }
                    return [PSCustomObject]@{ total = $count; moreThanTotal = $false; searchedSince = 'test' }
                }
                $script:ActivityRequest++
                $request = $Body | ConvertFrom-Json
                if ($script:ActivityRequest -eq 1) {
                    $request.sortField | Should -Be 'date'
                    return [PSCustomObject]@{ data = $firstPage; hasNext = $true }
                }
                $request.sortField | Should -Be 'created'
                $request.filters.date.range[0].start | Should -Be $expectedTimestampMilliseconds
                $request.filters.date.range[0].end | Should -Be $expectedTimestampMilliseconds
                if ($request.skip -eq 0) {
                    $request.skip | Should -Be 0
                    $page = if ($request.sortDirection -eq 'asc') { $ascendingFirstPage } else { $firstPage }
                    return [PSCustomObject]@{ data = $page; hasNext = $true }
                }
                $request.skip | Should -Be 250
                return [PSCustomObject]@{ data = $lastPage; hasNext = $false }
            }

            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = $from; ToDate = $from.AddHours(1); Archived = $true; FileName = 'archived-dense.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Error | Should -BeNullOrEmpty
            $result.Success | Should -BeTrue
            $result.EventCount | Should -Be 251
            $result.PageCount | Should -Be 7
            $result.RewindCount | Should -Be 1
            @(Get-Content -LiteralPath $result.FilePath) | Should -HaveCount 251
            Should -Invoke Invoke-RestMethod -Times 9 -Exactly
        }
    }

    It 'fails closed when a recent created timestamp also fills a complete page' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $timestamp = [datetimeoffset]::new([datetime]'2026-01-01T00:30:00Z').ToUnixTimeMilliseconds()
            $created = $timestamp + 1000
            $events = @(for ($i = 0; $i -lt 250; $i++) { [PSCustomObject]@{ _id = "created-$i"; timestamp = $timestamp; created = $created } })
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') { return [PSCustomObject]@{ total = 251; moreThanTotal = $false; searchedSince = 'test' } }
                return [PSCustomObject]@{ data = $events; hasNext = $true }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'dense-created.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.FailureClass | Should -Be 'UnpageableBoundary'
            $result.Error | Should -BeLike '*one created timestamp millisecond filled*'
        }
    }

    It 'fails closed when an archived stable identifier maps to different dense payloads' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $expectedTimestampMilliseconds = [datetimeoffset]::new([datetime]'2025-01-01T00:30:00Z').ToUnixTimeMilliseconds()
            $primaryEvents = @(for ($i = 0; $i -lt 250; $i++) { [PSCustomObject]@{ _id = "primary-$i"; timestamp = $expectedTimestampMilliseconds; created = ($expectedTimestampMilliseconds + 1000 - $i) } })
            $script:CountRequest = 0
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') {
                    $script:CountRequest++
                    return [PSCustomObject]@{ total = $(if ($script:CountRequest -eq 1) { 250 } else { 2 }); moreThanTotal = $false; searchedSince = 'test' }
                }
                $request = $Body | ConvertFrom-Json
                if ($request.sortField -eq 'date') {
                    return [PSCustomObject]@{ data = $primaryEvents; hasNext = $true }
                }
                return [PSCustomObject]@{
                    data = @(
                        [PSCustomObject]@{ _id = 'reused'; timestamp = $expectedTimestampMilliseconds; created = ($expectedTimestampMilliseconds + 2); detail = 'first' },
                        [PSCustomObject]@{ _id = 'reused'; timestamp = $expectedTimestampMilliseconds; created = ($expectedTimestampMilliseconds + 1); detail = 'second' }
                    )
                    hasNext = $false
                }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2025-01-01Z'; ToDate = [datetime]'2025-01-01T01:00:00Z'; Archived = $true; FileName = 'dense-id-collision.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.Error | Should -BeLike '*different archived dense-timestamp payloads*'
            $result.FailureClass | Should -Be 'UnpageableBoundary'
        }
    }

    It 'fails when created cannot disambiguate a full activity timestamp page' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $timestamp = [datetimeoffset]::new([datetime]'2026-01-01T00:30:00Z').ToUnixTimeMilliseconds()
            $events = @(for ($i = 0; $i -lt 250; $i++) { [PSCustomObject]@{ _id = "same-$i"; timestamp = $timestamp } })
            Mock Invoke-RestMethod {
                if ($Uri -like '*/count/') { return [PSCustomObject]@{ total = 250; moreThanTotal = $false; searchedSince = 'test' } }
                return [PSCustomObject]@{ data = $events; hasNext = $false }
            }
            $worker = New-XdrCloudAppsActivityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; Archived = $false; FileName = 'unpageable.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; Filters = @{}; CookieData = @(); HeadersData = @{}; PageSize = 250; MaxRetries = 1; RequestTimeoutSeconds = 30; MaxPagesPerChunk = 100 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.FailureClass | Should -Be 'UnpageableBoundary'
        }
    }
}

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

    It 'exports newest windows first and publishes a validated manifest' {
        $from = [datetime]'2026-01-01T00:00:00Z'
        $outputPath = Join-Path $TestDrive 'cloud-apps.ndjson'

        $result = Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(7) -Path $outputPath
        $manifest = Get-Content -LiteralPath "$outputPath.manifest.json" -Raw | ConvertFrom-Json

        $result.TotalEvents | Should -Be 2
        $result.TotalChunks | Should -Be 2
        $manifest.State | Should -Be 'Complete'
        @(Get-Content -LiteralPath $outputPath) | Should -Be @('{"chunk":0}', '{"chunk":1}')
        (Get-FileHash -LiteralPath $outputPath).Hash.ToLowerInvariant() | Should -Be $result.FileSha256
        Test-Path -LiteralPath "$outputPath.parts" | Should -BeFalse
    }

    It 'splits a range crossing the archive boundary into both API routes' {
        $to = [datetime]::UtcNow.AddDays(-29)
        $from = [datetime]::UtcNow.AddDays(-31)
        $outputPath = Join-Path $TestDrive 'mixed.ndjson'

        $null = Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $to -Path $outputPath
        $manifest = Get-Content -LiteralPath "$outputPath.manifest.json" -Raw | ConvertFrom-Json

        @($manifest.Chunks | Where-Object Archived).Count | Should -BeGreaterThan 0
        @($manifest.Chunks | Where-Object { -not $_.Archived }).Count | Should -BeGreaterThan 0
    }

    It 'rejects a caller-supplied date filter' {
        $from = [datetime]'2026-01-01T00:00:00Z'
        { Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path (Join-Path $TestDrive 'date.ndjson') -Filters @{ date = @{ gte = 1 } } } |
            Should -Throw -ExpectedMessage '*cannot contain date*'
    }

    It 'rejects a created filter when the range includes archived activity' {
        $from = [datetime]::UtcNow.AddDays(-31)
        $to = [datetime]::UtcNow.AddDays(-30).AddHours(-1)

        { Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $to -Path (Join-Path $TestDrive 'archived-created.ndjson') -Filters @{ created = @{ gte = 1 } } } |
            Should -Throw -ExpectedMessage '*archived API does not support that filter*'
    }

    It 'rejects incompatible filter state on resume' {
        Mock New-XdrCloudAppsActivityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                [void]$sharedParameters
                [void]$statusMap
                [PSCustomObject]@{
                    Success = $false; ChunkIndex = [int]$chunk.Index; EventCount = 0L; ExpectedEventCount = 0L
                    CountIsLowerBound = $false; PageCount = 0; RetryCount = 0; RewindCount = 0
                    FileBytes = 0L; FileSha256 = $null; MissingTimestampCount = 0L; BoundaryTimestampCount = 0L
                    ElapsedSeconds = 0.01; Error = 'stop after manifest creation'; FailureClass = 'PermanentHttp'
                }
            }
        } -ModuleName XDRInternals
        $from = [datetime]'2026-01-01T00:00:00Z'
        $outputPath = Join-Path $TestDrive 'incompatible.ndjson'
        { Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath -Filters @{ app = @{ eq = @('One') } } } | Should -Throw

        { Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath -Filters @{ app = @{ eq = @('Two') } } } |
            Should -Throw -ExpectedMessage '*does not match this request*'
    }

    It 'resumes validated completed parts after an interrupted export' {
        $script:ResumePhase = 1
        Mock New-XdrCloudAppsActivityTimelineExportWorker {
            if ($script:ResumePhase -eq 1) {
                return {
                    param($chunk, $sharedParameters, $statusMap)
                    [void]$statusMap
                    if ([int]$chunk.Index -eq 1) {
                        return [PSCustomObject]@{
                            Success = $false; ChunkIndex = 1; EventCount = 0L; ExpectedEventCount = 0L
                            CountIsLowerBound = $false; CountDelta = 0L; PageCount = 0; RetryCount = 0
                            RewindCount = 0; FileBytes = 0L; FileSha256 = $null; MissingTimestampCount = 0L
                            BoundaryTimestampCount = 0L; DuplicateRepresentationCount = 0L; ElapsedSeconds = 0.01
                            Error = 'simulated interruption'; FailureClass = 'PermanentHttp'
                        }
                    }
                    $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                    [System.IO.File]::WriteAllText($filePath, "{`"chunk`":$([int]$chunk.Index)}`n", [System.Text.UTF8Encoding]::new($false))
                    return [PSCustomObject]@{
                        Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; ExpectedEventCount = 1L
                        CountIsLowerBound = $false; CountDelta = 0L; PageCount = 1; RetryCount = 0
                        RewindCount = 0; FileBytes = (Get-Item $filePath).Length
                        FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant(); MissingTimestampCount = 0L
                        BoundaryTimestampCount = 0L; DuplicateRepresentationCount = 0L; ElapsedSeconds = 0.01
                        Error = $null; FailureClass = $null
                    }
                }
            }
            return {
                param($chunk, $sharedParameters, $statusMap)
                [void]$statusMap
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                [System.IO.File]::WriteAllText($filePath, "{`"chunk`":$([int]$chunk.Index)}`n", [System.Text.UTF8Encoding]::new($false))
                [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; ExpectedEventCount = 1L
                    CountIsLowerBound = $false; CountDelta = 0L; PageCount = 1; RetryCount = 0
                    RewindCount = 0; FileBytes = (Get-Item $filePath).Length
                    FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant(); MissingTimestampCount = 0L
                    BoundaryTimestampCount = 0L; DuplicateRepresentationCount = 0L; ElapsedSeconds = 0.01
                    Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals
        $from = [datetime]'2026-01-01T00:00:00Z'
        $outputPath = Join-Path $TestDrive 'resume.ndjson'

        { Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(13) -Path $outputPath } | Should -Throw
        $script:ResumePhase = 2
        $result = Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(13) -Path $outputPath

        $result.TotalEvents | Should -Be 3
        $result.ResumedChunks | Should -Be 2
        @(Get-Content -LiteralPath $outputPath) | Should -Be @('{"chunk":0}', '{"chunk":1}', '{"chunk":2}')
    }

    It 'replans pending windows when resume crosses the moving archive boundary' {
        $script:ArchiveResumePhase = 1
        Mock New-XdrCloudAppsActivityTimelineExportWorker {
            if ($script:ArchiveResumePhase -eq 1) {
                return {
                    param($chunk, $sharedParameters, $statusMap)
                    [void]$sharedParameters
                    [void]$statusMap
                    [PSCustomObject]@{
                        Success = $false; ChunkIndex = [int]$chunk.Index; EventCount = 0L; ExpectedEventCount = 0L
                        CountIsLowerBound = $false; CountDelta = 0L; PageCount = 0; RetryCount = 0; RewindCount = 0
                        FileBytes = 0L; FileSha256 = $null; MissingTimestampCount = 0L; BoundaryTimestampCount = 0L
                        DuplicateRepresentationCount = 0L; ElapsedSeconds = 0.01
                        Error = 'simulated interruption'; FailureClass = 'PermanentHttp'
                    }
                }
            }
            return {
                param($chunk, $sharedParameters, $statusMap)
                [void]$statusMap
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                [System.IO.File]::WriteAllText($filePath, "{`"archived`":$(([bool]$chunk.Archived).ToString().ToLowerInvariant())}`n", [System.Text.UTF8Encoding]::new($false))
                [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; ExpectedEventCount = 1L
                    CountIsLowerBound = $false; CountDelta = 0L; PageCount = 1; RetryCount = 0; RewindCount = 0
                    FileBytes = (Get-Item $filePath).Length; FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant()
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; DuplicateRepresentationCount = 0L
                    ElapsedSeconds = 0.01; Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals

        $boundary = [datetime]::UtcNow.AddDays(-30)
        $from = $boundary.AddHours(-1)
        $to = $boundary.AddHours(1)
        $outputPath = Join-Path $TestDrive 'archive-boundary-resume.ndjson'
        { Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $to -Path $outputPath } | Should -Throw

        $manifestPath = "$outputPath.manifest.json"
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
        $pending = $manifest.Chunks[0]
        $pending.FromDateUtc = $from.ToString('o')
        $pending.ToDateUtc = $to.ToString('o')
        $pending.DurationTicks = ($to - $from).Ticks
        $pending.Archived = $false
        $pending.Status = 'Pending'
        $manifest.Chunks = @($pending)
        $manifest.ArchiveBoundaryUtc = $boundary.AddDays(-1).ToString('o')
        [System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 30), [System.Text.UTF8Encoding]::new($false))

        $script:ArchiveResumePhase = 2
        $result = Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $to -Path $outputPath
        $resumedManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

        $result.TotalChunks | Should -Be 2
        $result.ArchivedChunks | Should -Be 1
        @($resumedManifest.Chunks | Where-Object Archived).Count | Should -Be 1
        @($resumedManifest.Chunks | Where-Object { -not $_.Archived }).Count | Should -Be 1
        @(Get-Content -LiteralPath $outputPath) | Should -Be @('{"archived":false}', '{"archived":true}')
    }

    It 'preserves an existing final file when a forced replacement fails' {
        Mock New-XdrCloudAppsActivityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                [void]$sharedParameters
                [void]$statusMap
                [PSCustomObject]@{
                    Success = $false; ChunkIndex = [int]$chunk.Index; EventCount = 0L; ExpectedEventCount = 0L
                    CountIsLowerBound = $false; PageCount = 0; RetryCount = 0; RewindCount = 0
                    FileBytes = 0L; FileSha256 = $null; MissingTimestampCount = 0L; BoundaryTimestampCount = 0L
                    ElapsedSeconds = 0.01; Error = 'simulated failure'; FailureClass = 'PermanentHttp'
                }
            }
        } -ModuleName XDRInternals
        $from = [datetime]'2026-01-01T00:00:00Z'
        $outputPath = Join-Path $TestDrive 'existing.ndjson'
        Set-Content -LiteralPath $outputPath -Value 'original' -NoNewline

        { Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath -Force } | Should -Throw

        Get-Content -LiteralPath $outputPath -Raw | Should -Be 'original'
    }

    It 'recovers a publishing manifest from a validated partial output' {
        $from = [datetime]'2026-01-01T00:00:00Z'
        $outputPath = Join-Path $TestDrive 'publishing.ndjson'
        $null = Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath
        $manifestPath = "$outputPath.manifest.json"
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
        $manifest.State = 'Publishing'
        $manifest.Summary.PartsRetained = $true
        [System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 30), [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::Move($outputPath, "$outputPath.partial")

        $result = Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath

        $result.TotalEvents | Should -Be 1
        (Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).State | Should -Be 'Complete'
        (Get-FileHash -LiteralPath $outputPath).Hash.ToLowerInvariant() | Should -Be $result.FileSha256
    }

    It 'refuses a completed final file whose hash no longer matches its manifest' {
        $from = [datetime]'2026-01-01T00:00:00Z'
        $outputPath = Join-Path $TestDrive 'invalid-final.ndjson'
        $null = Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath
        [System.IO.File]::WriteAllText($outputPath, "changed`n", [System.Text.UTF8Encoding]::new($false))

        { Export-XdrCloudAppsActivityTimeline -FromDate $from -ToDate $from.AddHours(1) -Path $outputPath } |
            Should -Throw -ExpectedMessage '*failed validation*'
    }
}
