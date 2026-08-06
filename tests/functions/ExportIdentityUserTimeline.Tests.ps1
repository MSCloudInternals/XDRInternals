Describe 'Export-XdrIdentityUserTimeline' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrIdentityHeaders { @{} } -ModuleName XDRInternals
        Mock Get-XdrIdentityUser {
            [PSCustomObject]@{
                displayName = 'Timeline User'
                ids = [PSCustomObject]@{
                    aad = '11111111-1111-1111-1111-111111111111'
                    upn = 'user@contoso.com'
                }
            }
        } -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
        }
        $script:FromDate = [datetime]'2026-01-01T00:00:00Z'
        $script:ToDate = [datetime]'2026-01-05T01:00:00Z'
    }

    It 'keeps the public parameter surface intentionally small' {
        $command = Get-Command Export-XdrIdentityUserTimeline
        $publicParameters = @($command.Parameters.Keys | Where-Object {
                $_ -notin [System.Management.Automation.PSCmdlet]::CommonParameters -and
                $_ -notin [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
            })

        $publicParameters | Sort-Object | Should -Be @('AadId', 'Force', 'FromDate', 'Path', 'RadiusUserId', 'Sid', 'ToDate', 'Upn')
    }

    It 'rejects invalid ranges and non-NDJSON output paths before collection' {
        { Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:ToDate -ToDate $script:FromDate -Path (Join-Path $TestDrive 'reversed.ndjson') } |
            Should -Throw -ExpectedMessage '*FromDate must be before ToDate*'
        { Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:FromDate.AddDays(181) -Path (Join-Path $TestDrive 'too-long.ndjson') } |
            Should -Throw -ExpectedMessage '*cannot exceed 180 days*'
        { Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:FromDate.AddHours(1) -Path (Join-Path $TestDrive 'wrong.json') } |
            Should -Throw -ExpectedMessage '*.ndjson extension*'
    }

    It 'uses exclusive API bounds to implement a logical half-open interval' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $script:RequestBody = $null
            Mock Invoke-RestMethod {
                param($Body)
                $script:RequestBody = $Body | ConvertFrom-Json
                [PSCustomObject]@{
                    count = 1
                    data = @([PSCustomObject]@{ EventId = 'lower'; Timestamp = '2026-01-01T00:00:00Z'; Id = 'raw' })
                    errors = [PSCustomObject]@{}
                }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{
                Index = 0; FromDate = [datetime]'2026-01-01T00:00:00Z'
                ToDate = [datetime]'2026-01-01T01:00:00Z'; FileName = 'bounds.ndjson'
            }
            $shared = @{
                PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'user@contoso.com' }
                CookieData = @(); HeadersData = @{}; PageSize = 1000; MaxRetries = 1; RequestTimeoutSeconds = 30
            }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue -Because $result.Error
            $result.EventCount | Should -Be 1
            $script:RequestBody.filters.Timeframe.between[0] | Should -Be 1767225599
            $script:RequestBody.filters.Timeframe.between[1] | Should -Be 1767229200
            (Get-Content -LiteralPath $result.FilePath -Raw | ConvertFrom-Json).Id | Should -Be 'raw'
        }
    }

    It 'fails closed on nonempty service errors' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{ count = 0; data = @(); errors = [PSCustomObject]@{ backend = 'partial' } }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-02Z'; FileName = 'errors.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 1000; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.FailureClass | Should -Be 'PartialResponse'
            $result.Error | Should -BeLike '*service errors*'
            Test-Path -LiteralPath (Join-Path $TestRoot 'errors.ndjson') | Should -BeFalse
        }
    }

    It 'fails closed when response count does not match data' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{ count = 2; data = @([PSCustomObject]@{ EventId = 1; Timestamp = '2026-01-01T12:00:00Z' }); errors = [PSCustomObject]@{} }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-02Z'; FileName = 'count.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 1000; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.FailureClass | Should -Be 'PartialResponse'
            $result.Error | Should -BeLike '*count=2*data contained 1*'
        }
    }

    It 'fails closed when a required response field is absent' -ForEach @('count', 'data', 'errors') {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive; MissingField = $_ } {
            Mock Invoke-RestMethod {
                $response = [ordered]@{ count = 0; data = @(); errors = [PSCustomObject]@{} }
                $response.Remove($MissingField)
                [PSCustomObject]$response
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-02Z'; FileName = 'missing-field.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 1000; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.FailureClass | Should -Be 'PartialResponse'
            $result.Error | Should -BeLike "*without '$MissingField'*"
        }
    }

    It 'rejects ascending events' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{ count = 2; data = @(
                        [PSCustomObject]@{ EventId = 'a'; Timestamp = '2026-01-01T01:00:00Z' },
                        [PSCustomObject]@{ EventId = 'b'; Timestamp = '2026-01-01T02:00:00Z' }
                    ); errors = [PSCustomObject]@{} }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-02Z'; FileName = 'invalid.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 1000; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.Error | Should -BeLike '*descending timestamp order*'
        }
    }

    It 'retains a reused EventId when its timestamp differs' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{ count = 2; data = @(
                        [PSCustomObject]@{ EventId = 'repeat'; Timestamp = '2026-01-01T02:00:00Z' },
                        [PSCustomObject]@{ EventId = 'repeat'; Timestamp = '2026-01-01T01:00:00Z' }
                    ); errors = [PSCustomObject]@{} }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-02Z'; FileName = 'reused-id.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 1000; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue -Because $result.Error
            $result.EventCount | Should -Be 2
        }
    }

    It 'suppresses only request-volatile duplicate representations and retains the first raw object' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{ count = 2; data = @(
                        [PSCustomObject]@{ EventId = 'same'; Timestamp = '2026-01-01T00:20:00Z'; Id = 'first'; RowNumber = 1; Description = 'first description'; Title = 'Stable' },
                        [PSCustomObject]@{ EventId = 'same'; Timestamp = '2026-01-01T00:20:00Z'; Id = 'second'; RowNumber = 9; Description = 'second description'; Title = 'Stable' }
                    ); errors = [PSCustomObject]@{} }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; FileName = 'duplicate-representation.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 1000; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status
            $eventItem = Get-Content -LiteralPath $result.FilePath -Raw | ConvertFrom-Json

            $result.Success | Should -BeTrue -Because $result.Error
            $result.EventCount | Should -Be 1
            $result.DuplicateRepresentationCount | Should -Be 1
            $eventItem.Id | Should -Be 'first'
            $eventItem.Description | Should -Be 'first description'
        }
    }

    It 'uses timestamp keyset pages without losing the tied boundary group' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                param($Body)
                $request = $Body | ConvertFrom-Json
                $to = [long]$request.filters.Timeframe.between[1]
                $pages = @{
                    '1767229200' = @('50', '40a', '40b')
                    '1767228001' = @('40a', '40b', '30')
                    '1767227401' = @('30')
                }
                $events = @($pages["$to"] | ForEach-Object {
                        $minute = ([string]$_ -replace '[ab]$')
                        [PSCustomObject]@{ EventId = $_; Timestamp = "2026-01-01T00:$minute`:00Z" }
                    })
                [PSCustomObject]@{ count = $events.Count; data = $events; errors = [PSCustomObject]@{} }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; FileName = 'keyset.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 3; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status
            $ids = @(Get-Content -LiteralPath $result.FilePath | ForEach-Object { ($_ | ConvertFrom-Json).EventId })

            $result.Success | Should -BeTrue -Because $result.Error
            $result.RewindCount | Should -Be 2
            $ids | Should -Be @('50', '40a', '40b', '30')
            Assert-MockCalled Invoke-RestMethod -Times 3 -Exactly -Scope It -ParameterFilter {
                ($Body | ConvertFrom-Json).skip -eq 0
            }
        }
    }

    It 'fails rather than dropping an unpageable timestamp' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                param($Body)
                [PSCustomObject]@{ count = 2; data = @(
                        [PSCustomObject]@{ EventId = 'first-a'; Timestamp = '2026-01-01T00:20:00Z' },
                        [PSCustomObject]@{ EventId = 'first-b'; Timestamp = '2026-01-01T00:20:00Z' }
                    ); errors = [PSCustomObject]@{} }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; FileName = 'unpageable.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 2; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.FailureClass | Should -Be 'UnpageableBoundary'
            $result.Error | Should -BeLike '*cannot prove completeness*one API timestamp second filled*'
            Test-Path -LiteralPath (Join-Path $TestRoot 'unpageable.ndjson') | Should -BeFalse
        }
    }

    It 'withholds the complete oldest API second when fractional timestamps share it' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                param($Body)
                $request = $Body | ConvertFrom-Json
                $to = [long]$request.filters.Timeframe.between[1]
                $events = if ($to -eq 1767229200) {
                    @(
                        [PSCustomObject]@{ EventId = 'newer'; Timestamp = '2026-01-01T00:50:00Z' },
                        [PSCustomObject]@{ EventId = 'fraction-a'; Timestamp = '2026-01-01T00:40:00.900Z' },
                        [PSCustomObject]@{ EventId = 'fraction-b'; Timestamp = '2026-01-01T00:40:00.100Z' }
                    )
                } else {
                    @(
                        [PSCustomObject]@{ EventId = 'fraction-a'; Timestamp = '2026-01-01T00:40:00.900Z' },
                        [PSCustomObject]@{ EventId = 'fraction-b'; Timestamp = '2026-01-01T00:40:00.100Z' }
                    )
                }
                [PSCustomObject]@{ count = $events.Count; data = $events; errors = [PSCustomObject]@{} }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-01T01:00:00Z'; FileName = 'fractional-keyset.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 3; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status
            $ids = @(Get-Content -LiteralPath $result.FilePath | ForEach-Object { ($_ | ConvertFrom-Json).EventId })

            $result.Success | Should -BeTrue -Because $result.Error
            $result.RewindCount | Should -Be 1
            $ids | Should -Be @('newer', 'fraction-a', 'fraction-b')
        }
    }

    It 'publishes newest-first validated parts and records the identity fingerprint' {
        Mock New-XdrIdentityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                $line = [string]::Format('{{"chunk":{0}}}{1}', [int]$chunk.Index, "`n")
                [System.IO.File]::WriteAllText($filePath, $line, [System.Text.UTF8Encoding]::new($false))
                [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; PageCount = 1
                    RetryCount = 0; RewindCount = 0; FileBytes = (Get-Item $filePath).Length
                    FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant(); MissingTimestampCount = 0L
                    BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'identity.ndjson'

        $result = Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:ToDate -Path $outputPath
        $manifest = Get-Content -LiteralPath "$outputPath.manifest.json" -Raw | ConvertFrom-Json
        $chunks = @(Get-Content -LiteralPath $outputPath | ForEach-Object { ($_ | ConvertFrom-Json).chunk })

        $result.TotalChunks | Should -Be 5
        $result.TotalEvents | Should -Be 5
        $chunks | Should -Be @(0, 1, 2, 3, 4)
        $manifest.IdentityFingerprint | Should -Match '^[0-9a-f]{64}$'
        $manifest.State | Should -Be 'Complete'
        $manifest.ChunkHours | Should -Be 24
        $manifest.PaginationStrategy | Should -Be 'TimestampKeysetV2'
        $result.FileSha256 | Should -Be (Get-FileHash -LiteralPath $outputPath).Hash.ToLowerInvariant()
    }

    It 'preserves an existing final file when a forced replacement fails' {
        Mock New-XdrIdentityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                [PSCustomObject]@{
                    Success = $false; ChunkIndex = [int]$chunk.Index; EventCount = 0L; PageCount = 0
                    RetryCount = 0; RewindCount = 0; FileBytes = 0L; FileSha256 = $null
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01
                    Error = 'simulated permanent failure'; FailureClass = 'PermanentHttp'
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'existing.ndjson'
        [System.IO.File]::WriteAllText($outputPath, "old`n", [System.Text.UTF8Encoding]::new($false))

        { Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:ToDate -Path $outputPath -Force } |
            Should -Throw -ExpectedMessage '*preserved for resume*'

        [System.IO.File]::ReadAllText($outputPath) | Should -Be "old`n"
        Test-Path -LiteralPath "$outputPath.parts" | Should -BeTrue
    }

    It 'resolves the selected identity exactly once' {
        Mock New-XdrIdentityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                [System.IO.File]::WriteAllText($filePath, "{}`n", [System.Text.UTF8Encoding]::new($false))
                [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; PageCount = 1
                    RetryCount = 0; RewindCount = 0; FileBytes = (Get-Item $filePath).Length
                    FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant(); MissingTimestampCount = 0L
                    BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'resolved-once.ndjson'

        $null = Export-XdrIdentityUserTimeline -AadId '11111111-1111-1111-1111-111111111111' `
            -FromDate $script:FromDate -ToDate $script:FromDate.AddHours(1) -Path $outputPath

        Should -Invoke Get-XdrIdentityUser -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $AadId -eq '11111111-1111-1111-1111-111111111111'
        }
    }

    It 'rounds subsecond logical bounds outward for the exclusive API' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $script:SubsecondBody = $null
            Mock Invoke-RestMethod {
                param($Body)
                $script:SubsecondBody = $Body | ConvertFrom-Json
                [PSCustomObject]@{
                    count = 1
                    data = @([PSCustomObject]@{ EventId = 'inside'; Timestamp = '2026-01-01T00:00:01Z' })
                    errors = [PSCustomObject]@{}
                }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{
                Index = 0; FromDate = [datetime]'2026-01-01T00:00:00.250Z'
                ToDate = [datetime]'2026-01-01T01:00:00.100Z'; FileName = 'subsecond.ndjson'
            }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 1000; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeTrue -Because $result.Error
            $script:SubsecondBody.filters.Timeframe.between[0] | Should -Be 1767225600
            $script:SubsecondBody.filters.Timeframe.between[1] | Should -Be 1767229201
        }
    }

    It 'retries transient transport failures but fails authentication without retrying' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            $script:RetryCall = 0
            Mock Start-Sleep {}
            Mock Invoke-RestMethod {
                $script:RetryCall++
                if ($script:RetryCall -eq 1) { throw 'temporary transport failure' }
                [PSCustomObject]@{ count = 0; data = @(); errors = [PSCustomObject]@{} }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-02Z'; FileName = 'retry.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 1000; MaxRetries = 2; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $retried = & $worker $chunk $shared $status

            $retried.Success | Should -BeTrue -Because $retried.Error
            $retried.RetryCount | Should -Be 1
            Should -Invoke Start-Sleep -Times 1 -Exactly

            Mock Invoke-RestMethod {
                $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Unauthorized)
                throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('unauthorized', $response)
            }
            $chunk.FileName = 'authentication.ndjson'
            $denied = & $worker $chunk $shared $status

            $denied.Success | Should -BeFalse
            $denied.FailureClass | Should -Be 'Authentication'
            $denied.RetryCount | Should -Be 0
        }
    }

    It 'fails closed on a missing timestamp' {
        InModuleScope XDRInternals -Parameters @{ TestRoot = $TestDrive } {
            Mock Invoke-RestMethod {
                [PSCustomObject]@{ count = 1; data = @([PSCustomObject]@{ EventId = 'missing' }); errors = [PSCustomObject]@{} }
            }
            $worker = New-XdrIdentityTimelineExportWorker
            $chunk = [PSCustomObject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-02Z'; FileName = 'missing.ndjson' }
            $shared = @{ PartsPath = $TestRoot; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{ upn = 'u' }; CookieData = @(); HeadersData = @{}; PageSize = 1000; MaxRetries = 1; RequestTimeoutSeconds = 30 }
            $status = [System.Collections.Concurrent.ConcurrentDictionary[int, object]]::new()

            $result = & $worker $chunk $shared $status

            $result.Success | Should -BeFalse
            $result.MissingTimestampCount | Should -Be 1
            Test-Path -LiteralPath (Join-Path $TestRoot 'missing.ndjson') | Should -BeFalse
        }
    }

    It 'rejects incompatible resumable state' {
        Mock New-XdrIdentityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                [PSCustomObject]@{
                    Success = $false; ChunkIndex = [int]$chunk.Index; EventCount = 0L; PageCount = 0
                    RetryCount = 0; RewindCount = 0; FileBytes = 0L; FileSha256 = $null
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01
                    Error = 'stop after manifest creation'; FailureClass = 'PermanentHttp'
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'incompatible.ndjson'
        { Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:ToDate -Path $outputPath } | Should -Throw

        { Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate.AddSeconds(1) -ToDate $script:ToDate -Path $outputPath } |
            Should -Throw -ExpectedMessage '*does not match this request*'
    }

    It 're-downloads corrupted completed parts and resumes only validated parts' {
        $script:ResumePhase = 1
        Mock New-XdrIdentityTimelineExportWorker {
            if ($script:ResumePhase -eq 1) {
                return {
                    param($chunk, $sharedParameters, $statusMap)
                    if ([int]$chunk.Index -eq 1) {
                        return [PSCustomObject]@{
                            Success = $false; ChunkIndex = 1; EventCount = 0L; PageCount = 0; RetryCount = 0
                            RewindCount = 0; FileBytes = 0L; FileSha256 = $null; MissingTimestampCount = 0L
                            BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = 'simulated interruption'; FailureClass = 'PermanentHttp'
                        }
                    }
                    $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                    [System.IO.File]::WriteAllText($filePath, "{`"chunk`":$([int]$chunk.Index)}`n", [System.Text.UTF8Encoding]::new($false))
                    return [PSCustomObject]@{
                        Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; PageCount = 1; RetryCount = 0
                        RewindCount = 0; FileBytes = (Get-Item $filePath).Length; FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant()
                        MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = $null; FailureClass = $null
                    }
                }
            }
            return {
                param($chunk, $sharedParameters, $statusMap)
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                [System.IO.File]::WriteAllText($filePath, "{`"chunk`":$([int]$chunk.Index)}`n", [System.Text.UTF8Encoding]::new($false))
                [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; PageCount = 1; RetryCount = 0
                    RewindCount = 0; FileBytes = (Get-Item $filePath).Length; FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant()
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'resume-corrupt.ndjson'

        { Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:ToDate -Path $outputPath } | Should -Throw
        $manifest = Get-Content -LiteralPath "$outputPath.manifest.json" -Raw | ConvertFrom-Json
        $corruptPart = Join-Path "$outputPath.parts" ([string]$manifest.Chunks[0].FileName)
        [System.IO.File]::AppendAllText($corruptPart, "corrupt`n", [System.Text.UTF8Encoding]::new($false))

        $script:ResumePhase = 2
        $result = Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:ToDate -Path $outputPath

        $result.ResumedChunks | Should -Be 3
        $result.TotalEvents | Should -Be 5
        Test-Path -LiteralPath "$outputPath.parts" | Should -BeFalse
    }

    It 'completes a manifest left in Publishing after validating the partial output' {
        Mock New-XdrIdentityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                [System.IO.File]::WriteAllText($filePath, "{`"recovered`":true}`n", [System.Text.UTF8Encoding]::new($false))
                [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; PageCount = 1; RetryCount = 0
                    RewindCount = 0; FileBytes = (Get-Item $filePath).Length; FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant()
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'publishing.ndjson'
        $null = Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:FromDate.AddHours(1) -Path $outputPath
        $manifestPath = "$outputPath.manifest.json"
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
        $manifest.State = 'Publishing'
        $manifest.Summary.PartsRetained = $true
        [System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::Move($outputPath, "$outputPath.partial")

        $result = Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:FromDate.AddHours(1) -Path $outputPath

        $result.TotalEvents | Should -Be 1
        (Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).State | Should -Be 'Complete'
        (Get-FileHash -LiteralPath $outputPath).Hash.ToLowerInvariant() | Should -Be $result.FileSha256
    }

    It 'refuses a completed final file whose hash no longer matches its manifest' {
        Mock New-XdrIdentityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                [System.IO.File]::WriteAllText($filePath, "{`"valid`":true}`n", [System.Text.UTF8Encoding]::new($false))
                [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; PageCount = 1; RetryCount = 0
                    RewindCount = 0; FileBytes = (Get-Item $filePath).Length; FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant()
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'invalid-final.ndjson'
        $null = Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:FromDate.AddHours(1) -Path $outputPath
        [System.IO.File]::WriteAllText($outputPath, "changed but same?`n", [System.Text.UTF8Encoding]::new($false))

        { Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:FromDate.AddHours(1) -Path $outputPath } |
            Should -Throw -ExpectedMessage '*failed validation*'
    }

    It 'preserves completed parts when available disk space is insufficient' {
        Mock New-XdrIdentityTimelineExportWorker {
            return {
                param($chunk, $sharedParameters, $statusMap)
                $filePath = Join-Path $sharedParameters.PartsPath ([string]$chunk.FileName)
                [System.IO.File]::WriteAllText($filePath, "{}`n", [System.Text.UTF8Encoding]::new($false))
                [PSCustomObject]@{
                    Success = $true; ChunkIndex = [int]$chunk.Index; EventCount = 1L; PageCount = 1; RetryCount = 0
                    RewindCount = 0; FileBytes = ([long]::MaxValue / 2); FileSha256 = (Get-FileHash $filePath).Hash.ToLowerInvariant()
                    MissingTimestampCount = 0L; BoundaryTimestampCount = 0L; ElapsedSeconds = 0.01; Error = $null; FailureClass = $null
                }
            }
        } -ModuleName XDRInternals
        $outputPath = Join-Path $TestDrive 'no-space.ndjson'

        { Export-XdrIdentityUserTimeline -Upn 'user@contoso.com' -FromDate $script:FromDate -ToDate $script:FromDate.AddHours(1) -Path $outputPath } |
            Should -Throw -ExpectedMessage '*requires at least*free*'

        Test-Path -LiteralPath $outputPath | Should -BeFalse
        Test-Path -LiteralPath "$outputPath.parts" | Should -BeTrue
    }
}
