function Get-XdrCloudAppsActivityTimeline {
    <#
    .SYNOPSIS
        Retrieves timeline of activities from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        The Get-XdrCloudAppsActivityTimeline cmdlet retrieves activities from the Microsoft Defender
        for Cloud Apps activity log. You can filter by date, apply custom filters, and use parallel
        chunked requests to improve performance for large date ranges.

        For date filtering:
        - Requests within 30 days use the regular activities API
        - Requests older than 30 days use the archived activities API exclusively
        - Maximum date range is 180 days

        For large date ranges, the cmdlet automatically splits the request into time-based chunks
        and processes them in parallel for improved performance. Results are written to temporary
        files and merged at the end.

        Use -Metadata or -ArchivedMetadata to retrieve filter and sorting field definitions.
        Use -CountOnly to retrieve just the activity count without full data.

    .PARAMETER Metadata
        Returns simplified metadata about available filters for the regular activities API.
        Shows filter name, supported operators, and input type.

    .PARAMETER ArchivedMetadata
        Returns simplified metadata about available filters for the archived activities API.
        Shows filter name, supported operators, and input type.

    .PARAMETER Raw
        When used with -Metadata or -ArchivedMetadata, returns the full raw metadata response
        instead of the simplified view.

    .PARAMETER CountOnly
        Returns only the count of matching activities without the full activity data.

    .PARAMETER FromDate
        The start date for filtering activities. Cannot be in the future or older than 180 days.

    .PARAMETER ToDate
        The end date for filtering activities. Defaults to current time if not specified.
        If in the future, will be adjusted to current time with a warning.

    .PARAMETER LastNDays
        Retrieves activities from the last N days. Maximum is 180 days.
        Alternative to using -FromDate/-ToDate.

    .PARAMETER PageSize
        The number of activities to retrieve per page. Default and maximum is 250.

    .PARAMETER Filters
        A hashtable of additional filters to apply to the activity query.
        Use -Metadata to see available filter options.

    .PARAMETER IncludeThreatScores
        When specified, retrieves threat scores for returned activities and adds them as a
        ThreatScore property on each activity object.
        Note: Only available for recent activities (within 30 days).

    .PARAMETER ThrottleLimit
        The maximum number of concurrent requests for parallel processing. Defaults to 10.

    .PARAMETER ChunkHours
        The size of each time chunk in hours for parallel processing. Defaults to 24 hours.
        Maximum is 168 hours (7 days) due to archived API limits.
        For time windows of 48 hours or less, chunks are auto-calculated.

    .PARAMETER TimeoutSeconds
        Maximum time in seconds to wait for all requests to complete. Defaults to 3600 (1 hour).

    .PARAMETER MaxRetries
        Maximum number of retry attempts for failed API requests. Defaults to 3.

    .PARAMETER RetryDelaySeconds
        Base delay in seconds between retry attempts (uses exponential backoff). Defaults to 5.

    .PARAMETER OutputPath
        Optional. The path to store temporary JSON files. Defaults to system temp folder.

    .PARAMETER KeepTempFiles
        If specified, keeps the temporary JSON files after merging.

    .PARAMETER ExportPath
        Optional. Export results directly to a JSON file at the specified path.
        Uses streaming merge for memory efficiency with large datasets.

    .PARAMETER PassThru
        When used with -ExportPath, returns the full results in addition to exporting.
        By default, -ExportPath only returns a summary object.

    .PARAMETER Compress
        When used with -ExportPath, writes minified JSON instead of formatted.
        Reduces file size and disk I/O.

    .PARAMETER Force
        Bypasses the cache and retrieves fresh data from the API.

    .EXAMPLE
        Get-XdrCloudAppsActivityTimeline

        Retrieves the 250 most recent activities without date filtering.

    .EXAMPLE
        Get-XdrCloudAppsActivityTimeline -LastNDays 7

        Retrieves all activities from the last 7 days.

    .EXAMPLE
        Get-XdrCloudAppsActivityTimeline -LastNDays 60 -ThrottleLimit 10

        Retrieves 60 days of activities using 10 concurrent requests.

    .EXAMPLE
        Get-XdrCloudAppsActivityTimeline -FromDate (Get-Date).AddDays(-90) -ExportPath ".\activities.json"

        Retrieves 90 days of activities and exports directly to a JSON file.

    .EXAMPLE
        Get-XdrCloudAppsActivityTimeline -LastNDays 180 -ExportPath ".\activities.json" -Compress -PassThru

        Retrieves 180 days, exports to compressed JSON, and returns the results.

    .EXAMPLE
        $filters = @{ "activity.eventType" = @{ "eq" = @("EVENT_CATEGORY_LOGIN") } }
        Get-XdrCloudAppsActivityTimeline -LastNDays 30 -Filters $filters

        Retrieves login activities from the last 30 days.

    .EXAMPLE
        Get-XdrCloudAppsActivityTimeline -Metadata

        Retrieves simplified metadata about available filters.

    .NOTES
        Requires an active XDR session established via Connect-XdrByEstsCookie.
        Maximum date range is 180 days.
        Activities older than 30 days are retrieved from the archived activities API.
        PowerShell 7+ recommended for parallel processing performance.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Metadata is a common term in the API naming convention')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Raw', Justification = 'Parameter used in conditional logic')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'PassThru', Justification = 'Parameter used in conditional logic')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Compress', Justification = 'Parameter used in conditional logic')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Returns different types based on parameter set')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '', Justification = 'Variables passed via -ArgumentList to parallel jobs')]
    [OutputType([PSCustomObject[]])]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ParameterSetName = 'Metadata', Mandatory)]
        [switch]$Metadata,

        [Parameter(ParameterSetName = 'ArchivedMetadata', Mandatory)]
        [switch]$ArchivedMetadata,

        [Parameter(ParameterSetName = 'Metadata')]
        [Parameter(ParameterSetName = 'ArchivedMetadata')]
        [switch]$Raw,

        [Parameter(ParameterSetName = 'CountOnly', Mandatory)]
        [switch]$CountOnly,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [datetime]$FromDate,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [datetime]$ToDate,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [ValidateRange(1, 180)]
        [int]$LastNDays,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 250)]
        [int]$PageSize = 250,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [hashtable]$Filters = @{},

        [Parameter(ParameterSetName = 'Default')]
        [switch]$IncludeThreatScores,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = 10,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 168)]
        [int]$ChunkHours = 24,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(60, 86400)]
        [int]$TimeoutSeconds = 3600,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [ValidateRange(1, 10)]
        [int]$MaxRetries = 3,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySeconds = 5,

        [Parameter(ParameterSetName = 'Default')]
        [string]$OutputPath,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$KeepTempFiles,

        [Parameter(ParameterSetName = 'Default')]
        [string]$ExportPath,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$PassThru,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$Compress,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings

        # Constants
        $script:MaxDaysRegularApi = 30
        $script:MaxDaysTotal = 180
        $script:BaseUriActivities = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/activities/"
        $script:BaseUriArchived = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/archived_activities/"
        $script:XdrBaseUrl = "https://security.microsoft.com"
    }

    process {
        #region Metadata handling
        if ($Metadata -or $ArchivedMetadata) {
            $apiType = if ($Metadata) { "activities" } else { "archived_activities" }
            $CacheKey = "XdrCloudApps${apiType}Metadata"

            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached $apiType metadata"
                    if ($Raw) {
                        return $cache.Value
                    }
                    # Return simplified metadata
                    return $cache.Value.filters | ForEach-Object {
                        [PSCustomObject]@{
                            Name       = $_.name
                            Operators  = ($_.operators.id -join ', ')
                            InputType  = $_.inputType.type
                        }
                    }
                }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/${apiType}/metadata/?allowDeprecationFields=true"
            Write-Verbose "Retrieving $apiType metadata from $Uri"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15

                if ($Raw) {
                    return $result
                }
                # Return simplified metadata
                return $result.filters | ForEach-Object {
                    [PSCustomObject]@{
                        Name       = $_.name
                        Operators  = ($_.operators.id -join ', ')
                        InputType  = $_.inputType.type
                    }
                }
            }
            catch {
                Write-Error "Failed to retrieve $apiType metadata: $_"
                return
            }
        }
        #endregion

        #region Date validation and calculation
        $useArchived = $false

        if ($LastNDays) {
            $ToDate = [datetime]::UtcNow
            $FromDate = $ToDate.AddDays(-$LastNDays)
        }

        # Validate FromDate is not in the future
        if ($FromDate -and $FromDate -gt [datetime]::UtcNow) {
            Write-Error "FromDate cannot be in the future."
            return
        }

        # Adjust ToDate if in the future
        if ($ToDate -and $ToDate -gt [datetime]::UtcNow) {
            Write-Warning "ToDate is in the future, adjusting to current time."
            $ToDate = [datetime]::UtcNow
        }

        if ($FromDate) {
            if (-not $ToDate) {
                $ToDate = [datetime]::UtcNow
            }

            # Validate date range
            $daysDiff = ($ToDate - $FromDate).TotalDays
            if ($daysDiff -gt $script:MaxDaysTotal) {
                Write-Error "Date range cannot exceed $($script:MaxDaysTotal) days. Requested range: $([math]::Round($daysDiff, 1)) days."
                return
            }

            if ($daysDiff -lt 0) {
                Write-Error "FromDate must be before ToDate."
                return
            }

            # Determine which API to use - if range extends beyond 30 days, use archived exclusively
            $daysAgo = ([datetime]::UtcNow - $FromDate).TotalDays
            if ($daysAgo -gt $script:MaxDaysRegularApi) {
                $useArchived = $true
                Write-Verbose "Using archived activities API (date range extends beyond $($script:MaxDaysRegularApi) days)"
            }

            Write-Verbose "Date range: $FromDate to $ToDate ($('{0:N1}' -f $daysDiff) days, archived: $useArchived)"
        }
        #endregion

        #region CountOnly handling
        if ($CountOnly) {
            $Uri = if ($useArchived) { "$($script:BaseUriArchived)count/" } else { "$($script:BaseUriActivities)count/" }

            $allFilters = $Filters.Clone()
            if ($FromDate -and $ToDate) {
                $epochStart = [long]($FromDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds
                $epochEnd = [long]($ToDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds
                
                if ($useArchived) {
                    $allFilters["date"] = @{
                        "range" = @(
                            @{ "start" = $epochStart; "end" = $epochEnd }
                        )
                    }
                }
                else {
                    $allFilters["date"] = @{
                        "gte" = $epochStart
                        "lte" = $epochEnd
                    }
                }
            }

            $body = @{ filters = $allFilters }
            $jsonBody = $body | ConvertTo-Json -Depth 10

            Write-Verbose "Retrieving activity count from $Uri"
            Write-Verbose "Request body: $jsonBody"

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $jsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                return $result
            }
            catch {
                Write-Error "Failed to retrieve activity count: $_"
                return
            }
        }
        #endregion

        #region Activity retrieval - Simple mode (no date filter)
        if (-not $FromDate -and -not $LastNDays) {
            # Simple single-page request without date filtering
            $Uri = $script:BaseUriActivities
            
            # Check cache
            $filterHash = if ($Filters.Count -gt 0) { ($Filters | ConvertTo-Json -Compress) } else { "none" }
            $CacheKey = "XdrCloudAppsActivity_${PageSize}_${filterHash}"
            
            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Returning cached activities"
                    return $cache.Value
                }
            }

            $body = @{
                distributedId     = [guid]::NewGuid().ToString()
                filters           = $Filters
                limit             = $PageSize
                performAsyncTotal = $true
                skip              = 0
                sortDirection     = "desc"
                sortField         = "date"
            }
            $jsonBody = $body | ConvertTo-Json -Depth 10

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $jsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                
                if ($response -is [string]) {
                    $response = $response | ConvertFrom-Json -AsHashtable
                }

                $result = @()
                if ($null -ne $response.data) {
                    $result = $response.data | ForEach-Object {
                        if ($_ -is [hashtable]) {
                            $pso = [PSCustomObject]$_
                            $pso.PSObject.TypeNames.Insert(0, 'XdrCloudAppsActivity')
                            $pso
                        }
                        else {
                            $_.PSObject.TypeNames.Insert(0, 'XdrCloudAppsActivity')
                            $_
                        }
                    }
                }

                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                return $result
            }
            catch {
                Write-Error "Failed to retrieve activities: $_"
                return
            }
        }
        #endregion

        #region Activity retrieval - Parallel chunked mode (with date filter)
        
        # Set up output directory
        $baseTempPath = if ($OutputPath) {
            $OutputPath
        } else {
            Join-Path ([System.IO.Path]::GetTempPath()) 'XdrCloudAppsTimeline'
        }
        $runId = [guid]::NewGuid().ToString('N').Substring(0, 8)
        $runTempPath = Join-Path $baseTempPath $runId

        if (-not (Test-Path $runTempPath)) {
            New-Item -Path $runTempPath -ItemType Directory -Force | Out-Null
        }
        Write-Verbose "Temporary files will be stored in: $runTempPath"

        # Generate date chunks
        $dateChunks = [System.Collections.Generic.List[hashtable]]::new()
        $totalHours = ($ToDate - $FromDate).TotalHours

        # For small time windows (≤48 hours), auto-calculate chunk size
        $effectiveChunkHours = $ChunkHours
        if (-not $PSBoundParameters.ContainsKey('ChunkHours') -and $totalHours -le 48) {
            $effectiveChunkHours = [math]::Max(1, [math]::Ceiling($totalHours / 10))
            Write-Verbose "Auto-calculated ChunkHours=$effectiveChunkHours for $([math]::Round($totalHours, 1)) hour time window"
        }

        $currentDate = $FromDate
        $chunkIndex = 0
        while ($currentDate -lt $ToDate) {
            $chunkEnd = $currentDate.AddHours($effectiveChunkHours)
            if ($chunkEnd -gt $ToDate) {
                $chunkEnd = $ToDate
            }
            $dateChunks.Add(@{
                FromDate = $currentDate
                ToDate   = $chunkEnd
                Index    = $chunkIndex
            })
            $chunkIndex++
            $currentDate = $chunkEnd
        }
        Write-Information "Split $([math]::Round($totalHours, 1)) hours into $($dateChunks.Count) chunks ($effectiveChunkHours hour$(if($effectiveChunkHours -gt 1){'s'}) each)" -InformationAction Continue

        # Prepare session data for parallel execution
        $cookieContainer = $script:session.Cookies
        $cookies = $cookieContainer.GetCookies([Uri]$script:XdrBaseUrl)
        $cookieData = @()
        foreach ($cookie in $cookies) {
            $cookieData += @{
                Name   = $cookie.Name
                Value  = $cookie.Value
                Domain = $cookie.Domain
                Path   = $cookie.Path
            }
        }
        $headersData = @{}
        foreach ($key in $script:headers.Keys) {
            $headersData[$key] = $script:headers[$key]
        }

        # Prepare base parameters for parallel jobs
        $baseParams = @{
            UseArchived       = $useArchived
            Filters           = $Filters
            PageSize          = $PageSize
            MaxRetries        = $MaxRetries
            RetryDelaySeconds = $RetryDelaySeconds
            BaseUriActivities = $script:BaseUriActivities
            BaseUriArchived   = $script:BaseUriArchived
            MaxDaysRegularApi = $script:MaxDaysRegularApi
        }

        try {
            Write-Verbose "Starting parallel retrieval of $($dateChunks.Count) chunk(s) with throttle limit of $ThrottleLimit"
            $operationStartTime = [System.Diagnostics.Stopwatch]::StartNew()

            # Initialize progress
            Write-Progress -Activity "Retrieving Cloud Apps Activity Timeline" -Status "Processing chunks..." -PercentComplete 0 -Id 1

            if ($PSVersionTable.PSVersion.Major -ge 7) {
                # PowerShell 7+ parallel processing
                $totalChunks = $dateChunks.Count
                $parallelJob = Start-ThreadJob -ScriptBlock {
                    param($chunks, $throttle, $baseParams, $tempPath, $cookieInfo, $headerInfo)
                    
                    $chunks | ForEach-Object -ThrottleLimit $throttle -Parallel {
                        $chunk = $_
                        $params = $using:baseParams
                        $path = $using:tempPath
                        $cookies = $using:cookieInfo
                        $headers = $using:headerInfo

                        $chunkFromDate = $chunk.FromDate
                        $chunkToDate = $chunk.ToDate
                        $chunkIndex = $chunk.Index
                        $chunkStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                        # Recreate web session
                        $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
                        foreach ($c in $cookies) {
                            $cookie = [System.Net.Cookie]::new($c.Name, $c.Value, $c.Path, $c.Domain)
                            $webSession.Cookies.Add($cookie)
                        }

                        # Determine API for this chunk
                        $chunkUri = if ($params.UseArchived) { $params.BaseUriArchived } else { $params.BaseUriActivities }

                        # Build date filter
                        $epochStart = [long]($chunkFromDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds
                        $epochEnd = [long]($chunkToDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds

                        $chunkFilters = $params.Filters.Clone()
                        if ($params.UseArchived) {
                            $chunkFilters["date"] = @{
                                "range" = @(
                                    @{ "start" = $epochStart; "end" = $epochEnd }
                                )
                            }
                        }
                        else {
                            $chunkFilters["date"] = @{
                                "gte" = $epochStart
                                "lte" = $epochEnd
                            }
                        }

                        # Pagination within chunk
                        $chunkEvents = [System.Collections.Generic.List[object]]::new()
                        $skip = 0
                        $hasMore = $true
                        $pagesRetrieved = 0
                        $maxPages = 1000
                        $totalRetries = 0
                        $retryErrors = [System.Collections.Generic.List[string]]::new()

                        while ($hasMore -and $pagesRetrieved -lt $maxPages) {
                            $body = @{
                                distributedId     = [guid]::NewGuid().ToString()
                                filters           = $chunkFilters
                                limit             = $params.PageSize
                                performAsyncTotal = $true
                                skip              = $skip
                                sortDirection     = "desc"
                                sortField         = "date"
                            }
                            $jsonBody = $body | ConvertTo-Json -Depth 10

                            # Retry loop with exponential backoff and jitter
                            $attempt = 0
                            $response = $null
                            while ($attempt -lt $params.MaxRetries) {
                                $attempt++
                                try {
                                    $response = Invoke-RestMethod -Uri $chunkUri -Method Post -Body $jsonBody -ContentType "application/json" -WebSession $webSession -Headers $headers
                                    break
                                }
                                catch {
                                    $errorMsg = $_.Exception.Message
                                    if ($attempt -lt $params.MaxRetries) {
                                        $totalRetries++
                                        $delay = $params.RetryDelaySeconds * [math]::Pow(2, $attempt - 1)
                                        $jitter = Get-Random -Minimum 0 -Maximum ([math]::Max(1, [int]($delay * 0.2)))
                                        $totalDelay = [int]($delay + $jitter)
                                        $retryErrors.Add("Page $pagesRetrieved attempt $attempt : $errorMsg (retry in ${totalDelay}s)")
                                        Start-Sleep -Seconds $totalDelay
                                    }
                                    else {
                                        throw "Failed after $($params.MaxRetries) attempts: $errorMsg"
                                    }
                                }
                            }

                            if ($response -is [string]) {
                                $response = $response | ConvertFrom-Json -AsHashtable
                            }

                            if ($null -ne $response.data -and $response.data.Count -gt 0) {
                                $chunkEvents.AddRange($response.data)
                            }

                            $hasMore = $response.hasNext -eq $true
                            $skip += $params.PageSize
                            $pagesRetrieved++
                        }

                        # Write chunk to file
                        $fileName = "chunk_{0:D4}_{1:yyyyMMdd_HHmmss}_{2:yyyyMMdd_HHmmss}.json" -f $chunkIndex, $chunkFromDate, $chunkToDate
                        $filePath = Join-Path $path $fileName

                        $chunkData = @{
                            ChunkIndex = $chunkIndex
                            FromDate   = $chunkFromDate.ToString('o')
                            ToDate     = $chunkToDate.ToString('o')
                            EventCount = $chunkEvents.Count
                            Events     = $chunkEvents.ToArray()
                        }
                        $chunkData | ConvertTo-Json -Depth 20 -Compress | Set-Content -Path $filePath -Encoding UTF8

                        $chunkStopwatch.Stop()
                        $fileSizeKB = [math]::Round((Get-Item $filePath).Length / 1KB, 2)

                        [PSCustomObject]@{
                            ChunkIndex     = $chunkIndex
                            FromDate       = $chunkFromDate
                            ToDate         = $chunkToDate
                            EventCount     = $chunkEvents.Count
                            PagesRetrieved = $pagesRetrieved
                            RetryCount     = $totalRetries
                            RetryErrors    = $retryErrors.ToArray()
                            FilePath       = $filePath
                            FileSizeKB     = $fileSizeKB
                            ElapsedSeconds = [math]::Round($chunkStopwatch.Elapsed.TotalSeconds, 2)
                            Success        = $true
                        }
                    }
                } -ArgumentList $dateChunks, $ThrottleLimit, $baseParams, $runTempPath, $cookieData, $headersData

                # Poll for progress
                $lastCompletedCount = 0
                
                while ($parallelJob.State -in @('NotStarted', 'Running')) {
                    if ($operationStartTime.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                        Stop-Job -Job $parallelJob -ErrorAction SilentlyContinue
                        Write-Warning "Operation timed out after $TimeoutSeconds seconds."
                        break
                    }

                    $chunkFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue
                    $completedFiles = $chunkFiles.Count

                    if ($completedFiles -gt $lastCompletedCount) {
                        $lastCompletedCount = $completedFiles
                        $elapsed = $operationStartTime.Elapsed.TotalSeconds
                        $avgPerChunk = if ($completedFiles -gt 0) { $elapsed / $completedFiles } else { 0 }
                        $remaining = $totalChunks - $completedFiles
                        $etaSeconds = $avgPerChunk * $remaining
                        $etaText = if ($completedFiles -gt 2 -and $etaSeconds -gt 0) { " (~$([math]::Round($etaSeconds/60, 1)) min remaining)" } else { "" }
                        
                        $percentComplete = [math]::Min(99, [math]::Round(($completedFiles / [math]::Max(1, $totalChunks)) * 100))
                        Write-Progress -Activity "Retrieving Cloud Apps Activity Timeline" -Status "Downloaded $completedFiles of $totalChunks chunks$etaText" -PercentComplete $percentComplete -Id 1
                    }

                    Start-Sleep -Milliseconds 500
                }

                $results = Receive-Job -Job $parallelJob -Wait
                Remove-Job -Job $parallelJob -Force
                [System.GC]::Collect()
            }
            else {
                # PowerShell 5.1 fallback - sequential processing with progress
                Write-Warning "PowerShell 7+ recommended for parallel processing. Using sequential mode."
                $results = @()
                $chunkNum = 0
                
                foreach ($chunk in $dateChunks) {
                    $chunkNum++
                    $percentComplete = [math]::Round(($chunkNum / $dateChunks.Count) * 100)
                    Write-Progress -Activity "Retrieving Cloud Apps Activity Timeline" -Status "Processing chunk $chunkNum of $($dateChunks.Count)" -PercentComplete $percentComplete -Id 1

                    $chunkFromDate = $chunk.FromDate
                    $chunkToDate = $chunk.ToDate
                    $chunkIndex = $chunk.Index
                    $chunkStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                    $chunkUri = if ($useArchived) { $script:BaseUriArchived } else { $script:BaseUriActivities }

                    $epochStart = [long]($chunkFromDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds
                    $epochEnd = [long]($chunkToDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds

                    $chunkFilters = $Filters.Clone()
                    if ($useArchived) {
                        $chunkFilters["date"] = @{ "range" = @( @{ "start" = $epochStart; "end" = $epochEnd } ) }
                    }
                    else {
                        $chunkFilters["date"] = @{ "gte" = $epochStart; "lte" = $epochEnd }
                    }

                    $chunkEvents = [System.Collections.Generic.List[object]]::new()
                    $skip = 0
                    $hasMore = $true
                    $pagesRetrieved = 0
                    $totalRetries = 0
                    $retryErrors = [System.Collections.Generic.List[string]]::new()

                    while ($hasMore -and $pagesRetrieved -lt 1000) {
                        $body = @{
                            distributedId = [guid]::NewGuid().ToString()
                            filters = $chunkFilters
                            limit = $PageSize
                            performAsyncTotal = $true
                            skip = $skip
                            sortDirection = "desc"
                            sortField = "date"
                        }
                        $jsonBody = $body | ConvertTo-Json -Depth 10

                        $attempt = 0
                        $response = $null
                        while ($attempt -lt $MaxRetries) {
                            $attempt++
                            try {
                                $response = Invoke-RestMethod -Uri $chunkUri -Method Post -Body $jsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                                break
                            }
                            catch {
                                $errorMsg = $_.Exception.Message
                                if ($attempt -lt $MaxRetries) {
                                    $totalRetries++
                                    $delay = $RetryDelaySeconds * [math]::Pow(2, $attempt - 1)
                                    $jitter = Get-Random -Minimum 0 -Maximum ([math]::Max(1, [int]($delay * 0.2)))
                                    $totalDelay = [int]($delay + $jitter)
                                    $retryErrors.Add("Page $pagesRetrieved attempt $attempt : $errorMsg (retry in ${totalDelay}s)")
                                    Start-Sleep -Seconds $totalDelay
                                }
                                else { throw "Failed after $MaxRetries attempts: $errorMsg" }
                            }
                        }

                        if ($response -is [string]) { $response = $response | ConvertFrom-Json -AsHashtable }
                        if ($null -ne $response.data -and $response.data.Count -gt 0) { $chunkEvents.AddRange($response.data) }
                        $hasMore = $response.hasNext -eq $true
                        $skip += $PageSize
                        $pagesRetrieved++
                    }

                    $fileName = "chunk_{0:D4}_{1:yyyyMMdd_HHmmss}_{2:yyyyMMdd_HHmmss}.json" -f $chunkIndex, $chunkFromDate, $chunkToDate
                    $filePath = Join-Path $runTempPath $fileName
                    @{ ChunkIndex = $chunkIndex; FromDate = $chunkFromDate.ToString('o'); ToDate = $chunkToDate.ToString('o'); EventCount = $chunkEvents.Count; Events = $chunkEvents.ToArray() } | ConvertTo-Json -Depth 20 -Compress | Set-Content -Path $filePath -Encoding UTF8

                    $chunkStopwatch.Stop()
                    $results += [PSCustomObject]@{
                        ChunkIndex = $chunkIndex
                        FromDate = $chunkFromDate
                        ToDate = $chunkToDate
                        EventCount = $chunkEvents.Count
                        PagesRetrieved = $pagesRetrieved
                        RetryCount = $totalRetries
                        RetryErrors = $retryErrors.ToArray()
                        FilePath = $filePath
                        FileSizeKB = [math]::Round((Get-Item $filePath).Length / 1KB, 2)
                        ElapsedSeconds = [math]::Round($chunkStopwatch.Elapsed.TotalSeconds, 2)
                        Success = $true
                    }
                }
            }

            Write-Progress -Activity "Retrieving Cloud Apps Activity Timeline" -Completed -Id 1

            # Output statistics
            Write-Information "`n=== Chunk Download Statistics ===" -InformationAction Continue
            $totalElapsed = 0
            $totalEvents = 0
            $totalSizeKB = 0
            $totalRetries = 0
            foreach ($r in ($results | Sort-Object ChunkIndex)) {
                if ($r.Success) {
                    $totalElapsed += $r.ElapsedSeconds
                    $totalEvents += $r.EventCount
                    $totalSizeKB += $r.FileSizeKB
                    $totalRetries += $r.RetryCount
                    $eventsPerSec = if ($r.ElapsedSeconds -gt 0) { [math]::Round($r.EventCount / $r.ElapsedSeconds, 1) } else { 0 }
                    $retryInfo = if ($r.RetryCount -gt 0) { " | Retries: $($r.RetryCount)" } else { "" }
                    Write-Verbose "Chunk $($r.ChunkIndex): $($r.FromDate.ToString('yyyy-MM-dd HH:mm')) to $($r.ToDate.ToString('yyyy-MM-dd HH:mm')) | Events: $($r.EventCount) | Pages: $($r.PagesRetrieved) | Size: $($r.FileSizeKB) KB | Time: $($r.ElapsedSeconds)s | Rate: $eventsPerSec events/sec$retryInfo"
                    
                    # Log retry details if any occurred
                    if ($r.RetryCount -gt 0) {
                        Write-Warning "Chunk $($r.ChunkIndex) had $($r.RetryCount) retries"
                        foreach ($err in $r.RetryErrors) {
                            Write-Verbose "  Retry: $err"
                        }
                    }
                }
            }
            $wallClockSeconds = $operationStartTime.Elapsed.TotalSeconds
            $overallEventsPerSec = if ($wallClockSeconds -gt 0) { [math]::Round($totalEvents / $wallClockSeconds, 1) } else { 0 }
            Write-Information "=== Summary ===" -InformationAction Continue
            Write-Information "Total chunks: $($results.Count) | Total events: $totalEvents | Total size: $([math]::Round($totalSizeKB / 1024, 2)) MB" -InformationAction Continue
            Write-Information "Cumulative download time: $([math]::Round($totalElapsed, 2))s | Wall-clock time: $([math]::Round($wallClockSeconds, 2))s | Effective rate: $overallEventsPerSec events/sec" -InformationAction Continue
            if ($totalRetries -gt 0) {
                Write-Information "Total retries: $totalRetries (indicates API throttling or network issues)" -InformationAction Continue
            }

            # Merge results
            Write-Progress -Activity "Processing Results" -Status "Merging chunk files..." -PercentComplete 0 -Id 2
            $jsonFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue | Sort-Object Name

            if ($PSBoundParameters.ContainsKey('ExportPath')) {
                # Stream merge to export file (memory efficient)
                Write-Verbose "Exporting to file using streaming merge..."
                $exportDir = Split-Path -Parent $ExportPath
                if ($exportDir -and -not (Test-Path $exportDir)) {
                    New-Item -Path $exportDir -ItemType Directory -Force | Out-Null
                }

                $exportWriter = [System.IO.StreamWriter]::new($ExportPath, $false, [System.Text.Encoding]::UTF8)
                try {
                    $exportWriter.Write('[')
                    $firstEvent = $true
                    $fileIndex = 0
                    
                    foreach ($file in $jsonFiles) {
                        $fileIndex++
                        Write-Progress -Activity "Processing Results" -Status "Merging file $fileIndex of $($jsonFiles.Count)" -PercentComplete ([math]::Round(($fileIndex / [math]::Max(1, $jsonFiles.Count)) * 100)) -Id 2

                        $rawContent = Get-Content -Path $file.FullName -Raw
                        $chunkData = $rawContent | ConvertFrom-Json -AsHashtable
                        $rawContent = $null

                        foreach ($item in $chunkData.Events) {
                            if (-not $firstEvent) { $exportWriter.Write(',') }
                            $firstEvent = $false
                            
                            if ($Compress) {
                                $exportWriter.Write(($item | ConvertTo-Json -Depth 20 -Compress))
                            }
                            else {
                                $exportWriter.Write(($item | ConvertTo-Json -Depth 20))
                            }
                        }
                        $chunkData = $null
                    }
                    $exportWriter.Write(']')
                }
                finally {
                    $exportWriter.Close()
                    $exportWriter.Dispose()
                }

                Write-Progress -Activity "Processing Results" -Completed -Id 2
                Write-Information "Exported $totalEvents events to: $ExportPath" -InformationAction Continue

                # Clean up
                if (-not $KeepTempFiles) {
                    Remove-Item -Path $runTempPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                else {
                    Write-Verbose "Temporary files kept at: $runTempPath"
                }

                [System.GC]::Collect()

                if ($PassThru) {
                    # Load and return all events
                    $allEvents = [System.Collections.Generic.List[object]]::new()
                    $exportContent = Get-Content -Path $ExportPath -Raw | ConvertFrom-Json -AsHashtable
                    foreach ($item in $exportContent) {
                        if ($item -is [hashtable]) { $item = [PSCustomObject]$item }
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsActivity')
                        $allEvents.Add($item)
                    }
                    return $allEvents.ToArray()
                }

                return [PSCustomObject]@{
                    ExportPath   = $ExportPath
                    EventCount   = $totalEvents
                    ChunkCount   = $results.Count
                    TotalSizeMB  = [math]::Round($totalSizeKB / 1024, 2)
                    WallClockSec = [math]::Round($wallClockSeconds, 2)
                    FromDate     = $FromDate
                    ToDate       = $ToDate
                }
            }

            # In-memory merge
            $allEvents = [System.Collections.Generic.List[object]]::new([math]::Max(10000, $totalEvents))
            $fileIndex = 0
            
            foreach ($file in $jsonFiles) {
                $fileIndex++
                Write-Progress -Activity "Processing Results" -Status "Merging file $fileIndex of $($jsonFiles.Count)" -PercentComplete ([math]::Round(($fileIndex / [math]::Max(1, $jsonFiles.Count)) * 100)) -Id 2

                $rawContent = Get-Content -Path $file.FullName -Raw
                $chunkData = $rawContent | ConvertFrom-Json -AsHashtable
                $rawContent = $null

                if ($chunkData.Events) {
                    foreach ($item in $chunkData.Events) {
                        if ($item -is [hashtable]) { $item = [PSCustomObject]$item }
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsActivity')
                        $allEvents.Add($item)
                    }
                }
                $chunkData = $null

                if ($fileIndex % 50 -eq 0) {
                    [System.GC]::Collect()
                    [System.GC]::WaitForPendingFinalizers()
                }
            }

            Write-Progress -Activity "Processing Results" -Completed -Id 2

            # Clean up temp files
            if (-not $KeepTempFiles) {
                Remove-Item -Path $runTempPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            else {
                Write-Verbose "Temporary files kept at: $runTempPath"
            }

            # Enrich with threat scores if requested (only for non-archived data)
            if ($IncludeThreatScores -and -not $useArchived -and $allEvents.Count -gt 0) {
                Write-Verbose "Fetching threat scores for $($allEvents.Count) activities"

                $timestamps = $allEvents | ForEach-Object { $_.timestamp } | Where-Object { $_ -gt 0 }
                if ($timestamps.Count -gt 0) {
                    $minTimestamp = ($timestamps | Measure-Object -Minimum).Minimum
                    $maxTimestamp = ($timestamps | Measure-Object -Maximum).Maximum

                    $startDate = [DateTimeOffset]::FromUnixTimeMilliseconds($minTimestamp).UtcDateTime.AddDays(-1)
                    $endDate = [DateTimeOffset]::FromUnixTimeMilliseconds($maxTimestamp).UtcDateTime.AddDays(1)

                    $recordIds = @($allEvents | ForEach-Object { $_._id } | Where-Object { $_ })

                    if ($recordIds.Count -gt 0) {
                        try {
                            $threatScores = Get-XdrCloudAppsActivityThreatScore -RecordIds $recordIds -StartDate $startDate -EndDate $endDate -ErrorAction SilentlyContinue

                            if ($threatScores -and $threatScores.data -and $threatScores.data.Count -gt 0) {
                                Write-Verbose "Found $($threatScores.data.Count) threat scores"
                                $scoresByRecordId = @{}
                                foreach ($score in $threatScores.data) {
                                    if ($score.recordId) { $scoresByRecordId[$score.recordId] = $score }
                                }
                                foreach ($activity in $allEvents) {
                                    if ($scoresByRecordId.ContainsKey($activity._id)) {
                                        $activity | Add-Member -NotePropertyName 'ThreatScore' -NotePropertyValue $scoresByRecordId[$activity._id] -Force
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Warning "Failed to retrieve threat scores: $_"
                        }
                    }
                }
            }
            elseif ($IncludeThreatScores -and $useArchived) {
                Write-Warning "Threat scores are not available for archived activities (older than $($script:MaxDaysRegularApi) days)."
            }

            $result = $allEvents.ToArray()
            $allEvents.Clear()
            $allEvents = $null
            [System.GC]::Collect()

            return $result
        }
        catch {
            Write-Progress -Activity "Retrieving Cloud Apps Activity Timeline" -Completed -Id 1
            Write-Progress -Activity "Processing Results" -Completed -Id 2
            Write-Error "Failed to retrieve activity timeline: $_"
        }
        #endregion
    }
}
