function Get-XdrIdentityUserTimeline {
    <#
    .SYNOPSIS
        Retrieves the timeline of events for a specific user from Microsoft Defender for Identity.

    .DESCRIPTION
        Gets the timeline of security events for a user from Microsoft Defender for Identity with
        options to filter by date range, event types, and other parameters.

        Uses parallel chunked requests (1-day intervals) to improve performance and support longer
        date ranges up to 180 days.

        Supports two levels of parallelism:
        - Parallel day chunks for a single user
        - Parallel users when processing multiple users via pipeline

    .PARAMETER AadId
        The Entra (Azure AD) object ID of the user.

    .PARAMETER Upn
        The User Principal Name of the user.

    .PARAMETER Sid
        The Security Identifier (SID) of the user.

    .PARAMETER RadiusUserId
        The RADIUS user ID in format "User_{tenantId}_{userId}".

    .PARAMETER InputObject
        A user object from Get-XdrIdentityUser containing resolved identifiers.
        Accepts pipeline input.

    .PARAMETER FromDate
        The start date for the timeline. Defaults to 1 day before current time.

    .PARAMETER ToDate
        The end date for the timeline. Defaults to current time.

    .PARAMETER LastNDays
        Specifies the number of days to look back from current time.
        Cannot be used with FromDate or ToDate parameters.
        Maximum is 180 days.

    .PARAMETER EventType
        Filter events by type. Available types are retrieved dynamically from the FilterOptions API.
        Use -ListEventTypes to see available options.

    .PARAMETER ListEventTypes
        Lists available event types for filtering and exits without retrieving timeline data.

    .PARAMETER PageSize
        The number of events to return per page. Defaults to 50.

    .PARAMETER IncludeSentinelEvents
        Include Microsoft Sentinel UEBA anomaly events in the timeline results.
        Requires the user to have an armId (Sentinel entity ID) which is auto-detected from
        the resolved user identifiers.

    .PARAMETER ThrottleLimit
        The maximum number of concurrent requests. Defaults to 10.

    .PARAMETER TimeoutSeconds
        Maximum time in seconds to wait for all requests to complete. Defaults to 3600 (1 hour).

    .PARAMETER MaxRetries
        Maximum number of retry attempts for failed API requests. Defaults to 3.

    .PARAMETER RetryDelaySeconds
        Base delay in seconds between retry attempts (uses exponential backoff). Defaults to 30.

    .PARAMETER ChunkSizeHours
        Size of each time chunk in hours (1-24). Defaults to 12 hours.
        Smaller chunks allow faster failure recovery but increase API calls.
        Larger chunks are more efficient but lose more data if a chunk fails.

    .PARAMETER RequestTimeoutSeconds
        Timeout in seconds for individual HTTP requests (10-120). Defaults to 30.
        If a single API call takes longer than this, it will timeout and retry.

    .PARAMETER OutputPath
        Optional. The path to store temporary JSON files. Defaults to a temp folder.

    .PARAMETER KeepTempFiles
        If specified, keeps the temporary JSON files after merging.

    .PARAMETER ExportPath
        Optional. Export results directly to a JSON file at the specified path.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -Upn "nathan@contoso.com"

        Retrieves the last day of timeline events for the specified user.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -AadId "a2307c5a-76df-4513-b575-0537842c1d8b" -LastNDays 7

        Retrieves 7 days of timeline events.

    .EXAMPLE
        Get-XdrIdentityUser -Upn "nathan@contoso.com" | Get-XdrIdentityUserTimeline -LastNDays 30

        Retrieves user identity and pipes to timeline cmdlet for 30 days of events.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -Upn "nathan@contoso.com" -LastNDays 7 -IncludeSentinelEvents

        Retrieves timeline events including Sentinel UEBA anomalies.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -ListEventTypes

        Lists available event types for filtering.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -Upn "nathan@contoso.com" -LastNDays 90 -ExportPath "C:\Reports\user_timeline.json"

        Retrieves 90 days of timeline events and exports to JSON file.

    .OUTPUTS
        XdrIdentityUserTimelineEvent[]
        Returns an array of timeline event objects sorted by timestamp (newest first).

    .NOTES
        The identity timeline API uses Unix timestamps in seconds (not milliseconds).

        # TODO: Consider adding -SentinelWorkspaceId and -SentinelSubscriptionId parameters
        # if armId auto-detection doesn't work for a majority of users/tenants.
    #>
    [OutputType([System.Object[]])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Write-Host is used for ListEventTypes interactive output')]
    [CmdletBinding(DefaultParameterSetName = 'ByUpnDateRange')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ByAadIdDateRange')]
        [Parameter(Mandatory, ParameterSetName = 'ByAadIdLastNDays')]
        [Alias('aad', 'ObjectId')]
        [string]$AadId,

        [Parameter(Mandatory, ParameterSetName = 'ByUpnDateRange')]
        [Parameter(Mandatory, ParameterSetName = 'ByUpnLastNDays')]
        [Alias('UserPrincipalName', 'Email')]
        [string]$Upn,

        [Parameter(Mandatory, ParameterSetName = 'BySidDateRange')]
        [Parameter(Mandatory, ParameterSetName = 'BySidLastNDays')]
        [string]$Sid,

        [Parameter(Mandatory, ParameterSetName = 'ByRadiusUserIdDateRange')]
        [Parameter(Mandatory, ParameterSetName = 'ByRadiusUserIdLastNDays')]
        [string]$RadiusUserId,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'ByInputObjectDateRange')]
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'ByInputObjectLastNDays')]
        [PSObject]$InputObject,

        [Parameter(ParameterSetName = 'ByAadIdDateRange')]
        [Parameter(ParameterSetName = 'ByUpnDateRange')]
        [Parameter(ParameterSetName = 'BySidDateRange')]
        [Parameter(ParameterSetName = 'ByRadiusUserIdDateRange')]
        [Parameter(ParameterSetName = 'ByInputObjectDateRange')]
        [datetime]$FromDate = ((Get-Date).AddDays(-1)),

        [Parameter(ParameterSetName = 'ByAadIdDateRange')]
        [Parameter(ParameterSetName = 'ByUpnDateRange')]
        [Parameter(ParameterSetName = 'BySidDateRange')]
        [Parameter(ParameterSetName = 'ByRadiusUserIdDateRange')]
        [Parameter(ParameterSetName = 'ByInputObjectDateRange')]
        [datetime]$ToDate = (Get-Date),

        [Parameter(Mandatory, ParameterSetName = 'ByAadIdLastNDays')]
        [Parameter(Mandatory, ParameterSetName = 'ByUpnLastNDays')]
        [Parameter(Mandatory, ParameterSetName = 'BySidLastNDays')]
        [Parameter(Mandatory, ParameterSetName = 'ByRadiusUserIdLastNDays')]
        [Parameter(Mandatory, ParameterSetName = 'ByInputObjectLastNDays')]
        [ValidateRange(1, 180)]
        [int]$LastNDays,

        [Parameter()]
        [string[]]$EventType,

        [Parameter()]
        [switch]$ListEventTypes,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$PageSize = 50,

        [Parameter()]
        [switch]$IncludeSentinelEvents,

        [Parameter()]
        [ValidateRange(1, 20)]
        [int]$ThrottleLimit = 10,

        [Parameter()]
        [ValidateRange(60, 86400)]
        [int]$TimeoutSeconds = 3600,

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$MaxRetries = 3,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$RetryDelaySeconds = 30,

        [Parameter()]
        [ValidateRange(1, 24)]
        [int]$ChunkSizeHours = 12,

        [Parameter()]
        [ValidateRange(10, 120)]
        [int]$RequestTimeoutSeconds = 30,

        [Parameter()]
        [ValidateScript({ 
            if ([string]::IsNullOrWhiteSpace($_)) { return $true }
            if (-not (Test-Path -Path $_ -PathType Container)) {
                throw "OutputPath '$_' does not exist or is not a directory."
            }
            return $true
        })]
        [string]$OutputPath,

        [Parameter()]
        [switch]$KeepTempFiles,

        [Parameter()]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) { return $true }
            $parentDir = Split-Path -Path $_ -Parent
            if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -Path $parentDir -PathType Container)) {
                throw "Parent directory of ExportPath '$parentDir' does not exist."
            }
            return $true
        })]
        [string]$ExportPath
    )

    begin {
        Update-XdrConnectionSettings

        # Constants - centralized for maintainability (function-local scope)
        $UnixEpoch = [datetime]'1970-01-01'
        $StallTimeoutSeconds = 120           # Stall detection: no progress for this duration kills the job
        $RecentProgressSeconds = 30          # Progress files updated within this window reset stall timer
        $MaxPagesPerChunk = 50               # Safety limit: 50 pages * PageSize events max per chunk

        # Build headers with tenant-id and m-* headers required for MDI APIs
        $tenantIdCache = Get-XdrCache -CacheKey "XdrTenantId" -ErrorAction SilentlyContinue
        $tenantId = if ($null -ne $tenantIdCache) { $tenantIdCache.Value } else { $null }

        $mdiHeaders = @{}
        foreach ($key in $script:headers.Keys) {
            $mdiHeaders[$key] = $script:headers[$key]
        }
        if ($null -ne $tenantId) {
            $mdiHeaders["tenant-id"] = $tenantId
        }
        # Additional headers required by MDI identity API
        $mdiHeaders["accept-language"] = "en-us"
        $mdiHeaders["m-package"] = "identities"
        $mdiHeaders["m-type"] = "Page"
        $mdiHeaders["m-name"] = "UserPageRouteResolver[identities]"
        $mdiHeaders["m-componentName"] = "UserPageRouteResolver"
        $mdiHeaders["x-clientpage"] = "user@msec-identities"

        $script:XdrBaseUrl = "https://security.microsoft.com"
    }

    process {
        # Handle date parameters based on parameter set - use UTC to avoid timezone issues
        if ($PSCmdlet.ParameterSetName -like '*LastNDays') {
            $ToDate = (Get-Date).ToUniversalTime()
            $FromDate = $ToDate.AddDays(-$LastNDays)
        } else {
            # DateRange parameter sets - convert provided dates to UTC
            $ToDate = $ToDate.ToUniversalTime()
            $FromDate = $FromDate.ToUniversalTime()
        }

        # Validate time range (180 days max)
        if (($ToDate - $FromDate).TotalDays -gt 180) {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.ArgumentException]::new('The time range between FromDate and ToDate cannot exceed 180 days.'),
                    'TimeRangeExceeded',
                    [System.Management.Automation.ErrorCategory]::InvalidArgument,
                    $null
                )
            )
        }

        # Resolve user identifiers
        # Parameter set names include date range suffix (e.g., 'ByUpnDateRange', 'ByUpnLastNDays')
        # Use -like pattern matching to handle both variants
        $resolvedUser = $null
        $userIdentifiers = $null
        $fallbackDisplayName = $null
        $paramSetName = $PSCmdlet.ParameterSetName

        if ($paramSetName -like 'ByInputObject*') {
            # Already have resolved user from pipeline
            $resolvedUser = $InputObject
            $userIdentifiers = ConvertTo-XdrIdentityUserIdentifiers -ResolvedUser $resolvedUser
            $fallbackDisplayName = $resolvedUser.ids.upn ?? $resolvedUser.ids.aad
        }
        elseif ($paramSetName -like 'ByAadId*') {
            Write-Verbose "Resolving user by AAD ID: $AadId"
            $resolvedUser = Get-XdrIdentityUser -AadId $AadId
            if ($null -eq $resolvedUser) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.ArgumentException]::new("Could not resolve user with AAD ID: $AadId"),
                        'UserNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $AadId
                    )
                )
            }
            $userIdentifiers = ConvertTo-XdrIdentityUserIdentifiers -ResolvedUser $resolvedUser
            $fallbackDisplayName = $AadId
        }
        elseif ($paramSetName -like 'ByUpn*') {
            Write-Verbose "Resolving user by UPN: $Upn"
            $resolvedUser = Get-XdrIdentityUser -Upn $Upn
            if ($null -eq $resolvedUser) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.ArgumentException]::new("Could not resolve user with UPN: $Upn"),
                        'UserNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $Upn
                    )
                )
            }
            $userIdentifiers = ConvertTo-XdrIdentityUserIdentifiers -ResolvedUser $resolvedUser
            $fallbackDisplayName = $Upn
        }
        elseif ($paramSetName -like 'BySid*') {
            Write-Verbose "Resolving user by SID: $Sid"
            $resolvedUser = Get-XdrIdentityUser -Sid $Sid
            if ($null -eq $resolvedUser) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.ArgumentException]::new("Could not resolve user with SID: $Sid"),
                        'UserNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $Sid
                    )
                )
            }
            $userIdentifiers = ConvertTo-XdrIdentityUserIdentifiers -ResolvedUser $resolvedUser
            $fallbackDisplayName = $Sid
        }
        elseif ($paramSetName -like 'ByRadiusUserId*') {
            Write-Verbose "Resolving user by Radius User ID: $RadiusUserId"
            $resolvedUser = Get-XdrIdentityUser -RadiusUserId $RadiusUserId
            if ($null -eq $resolvedUser) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.ArgumentException]::new("Could not resolve user with Radius User ID: $RadiusUserId"),
                        'UserNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $RadiusUserId
                    )
                )
            }
            $userIdentifiers = ConvertTo-XdrIdentityUserIdentifiers -ResolvedUser $resolvedUser
            $fallbackDisplayName = $RadiusUserId
        }
        else {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.InvalidOperationException]::new("Unrecognized parameter set: $paramSetName"),
                    'InvalidParameterSet',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $paramSetName
                )
            )
        }

        # Set user display name: prefer displayName from resolved user, fallback to input identifier
        $userDisplayName = $resolvedUser.displayName ?? $fallbackDisplayName

        # Handle ListEventTypes
        if ($ListEventTypes) {
            $filterOptionsUri = "$script:XdrBaseUrl/apiproxy/mdi/identity/userapiservice/timeline/FilterOptions/mtp"
            $fromUnix = [int]($FromDate.ToUniversalTime() - $UnixEpoch).TotalSeconds
            $toUnix = [int]($ToDate.ToUniversalTime() - $UnixEpoch).TotalSeconds

            $filterBody = @{
                filterNames     = @("Type")
                userIdentifiers = $userIdentifiers
                filters         = @{
                    Timeframe = @{
                        between = @($fromUnix, $toUnix)
                    }
                }
                hasMultipleFilters = $false
            }

            try {
                $filterResponse = Invoke-RestMethod -Uri $filterOptionsUri `
                    -Method POST `
                    -ContentType "application/json" `
                    -Body ($filterBody | ConvertTo-Json -Depth 10) `
                    -WebSession $script:session `
                    -Headers $mdiHeaders `
                    -ErrorAction Stop

                Write-Host "Available event types for user '$userDisplayName':" -ForegroundColor Cyan
                if ($null -ne $filterResponse.data -and $filterResponse.data.Count -gt 0) {
                    $filterResponse.data | ForEach-Object { Write-Host "  - $($_.Type)" }
                } else {
                    Write-Host "  No event types found for this user and time range" -ForegroundColor Yellow
                }
                return
            } catch {
                Write-Warning "Failed to retrieve filter options: $($_.Exception.Message)"
                Write-Verbose "Full error: $($_.Exception.ToString())"
                return
            }
        }

        # Sanitize folder name
        $safeFolderName = $userDisplayName -replace '[\\/:*?"<>|]', '_'

        # Set up output directory
        $baseTempPath = if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
            $OutputPath
        } else {
            Join-Path ([System.IO.Path]::GetTempPath()) 'XdrIdentityTimeline'
        }
        $userTempPath = Join-Path $baseTempPath $safeFolderName
        $runId = [guid]::NewGuid().ToString('N').Substring(0, 8)
        $runTempPath = Join-Path $userTempPath $runId

        # Create temporary directory for chunk files
        if (-not (Test-Path $runTempPath)) {
            New-Item -Path $runTempPath -ItemType Directory -Force | Out-Null
        }
        Write-Verbose "Temporary files will be stored in: $runTempPath"

        # Build base query parameters
        $baseQueryParams = @{
            PageSize          = $PageSize
            MaxRetries        = $MaxRetries
            RetryDelaySeconds = $RetryDelaySeconds
            EventType         = if ($PSBoundParameters.ContainsKey('EventType')) { $EventType } else { $null }
            RequestTimeoutSec = $RequestTimeoutSeconds
            MaxPagesPerChunk  = $MaxPagesPerChunk
        }

        # Generate date chunks based on ChunkSizeHours parameter
        # Smaller chunks allow more parallel requests and faster failure recovery
        # 12-hour default provides best balance of efficiency and data loss on failure
        $dateChunks = [System.Collections.Generic.List[hashtable]]::new()
        $totalDays = ($ToDate - $FromDate).TotalDays
        $chunkHours = $ChunkSizeHours

        $currentDate = $FromDate
        $chunkIndex = 0
        while ($currentDate -lt $ToDate) {
            $chunkEnd = $currentDate.AddHours($chunkHours)
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
        Write-Information "Split $([math]::Round($totalDays, 1)) days into $($dateChunks.Count) chunks ($chunkHours hours each)" -InformationAction Continue

        # Store session cookies for parallel execution
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
        foreach ($key in $mdiHeaders.Keys) {
            $headersData[$key] = $mdiHeaders[$key]
        }

        try {
            Write-Verbose "Starting parallel retrieval of $($dateChunks.Count) chunk(s) with throttle limit of $ThrottleLimit"

            # Initialize progress tracking
            $progressParams = @{
                Activity        = "Retrieving User Timeline for $userDisplayName"
                Status          = "Processing chunks..."
                PercentComplete = 0
                Id              = 1
            }
            Write-Progress @progressParams

            $operationStartTime = [System.Diagnostics.Stopwatch]::StartNew()

            # Shared chunk processing script - used by both PS7 parallel and PS5.1 runspace approaches
            # Takes parameters for all required context since it runs in isolated threads/runspaces
            $chunkProcessingScript = {
                param($chunk, $userIds, $baseParams, $tempPath, $cookieInfo, $headerInfo, $baseUrl)

                $chunkFromDate = $chunk.FromDate
                $chunkToDate = $chunk.ToDate
                $chunkIndex = $chunk.Index

                # Recreate web session with cookies (required for isolated execution context)
                $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
                foreach ($c in $cookieInfo) {
                    $cookie = [System.Net.Cookie]::new($c.Name, $c.Value, $c.Path, $c.Domain)
                    $webSession.Cookies.Add($cookie)
                }

                # Convert dates to Unix timestamps (seconds)
                $unixEpoch = [datetime]'1970-01-01'
                $fromUnix = [int]($chunkFromDate.ToUniversalTime() - $unixEpoch).TotalSeconds
                $toUnix = [int]($chunkToDate.ToUniversalTime() - $unixEpoch).TotalSeconds

                $Uri = "$baseUrl/apiproxy/mdi/identity/userapiservice/timeline/mtp"
                $maxRetries = $baseParams.MaxRetries
                $baseDelay = $baseParams.RetryDelaySeconds
                $requestTimeout = $baseParams.RequestTimeoutSec
                $maxPages = $baseParams.MaxPagesPerChunk
                $pageSize = $baseParams.PageSize

                # Chunk-level retry loop
                $chunkAttempt = 0
                $chunkSuccess = $false
                $lastChunkError = $null

                while (-not $chunkSuccess -and $chunkAttempt -lt $maxRetries) {
                    $chunkAttempt++
                    $chunkEvents = [System.Collections.Generic.List[object]]::new()
                    $skip = 0

                    try {
                        $chunkStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                        $pagesRetrieved = 0

                        do {
                            # Check max pages safety limit
                            if ($pagesRetrieved -ge $maxPages) {
                                throw "Chunk $chunkIndex : Exceeded max pages limit ($maxPages)"
                            }

                            # Build request body
                            $requestBody = @{
                                count           = $pageSize
                                skip            = $skip
                                userIdentifiers = $userIds
                                filters         = @{
                                    Timeframe = @{
                                        between = @($fromUnix, $toUnix)
                                    }
                                }
                            }

                            # Add event type filter if specified
                            if ($baseParams.EventType -and $baseParams.EventType.Count -gt 0) {
                                $requestBody.filters['Type'] = @{
                                    values = $baseParams.EventType
                                }
                            }

                            $bodyJson = $requestBody | ConvertTo-Json -Depth 10

                            $attempt = 0
                            $success = $false

                            while (-not $success -and $attempt -lt $maxRetries) {
                                try {
                                    $attempt++
                                    $response = Invoke-RestMethod -Uri $Uri -Method POST -ContentType "application/json" -Body $bodyJson -WebSession $webSession -Headers $headerInfo -TimeoutSec $requestTimeout -ErrorAction Stop
                                    $success = $true
                                    $pagesRetrieved++

                                    # Signal page-level progress to outer loop
                                    $progressFile = Join-Path $tempPath "progress_$chunkIndex.txt"
                                    "$pagesRetrieved" | Out-File -FilePath $progressFile -Force -NoNewline
                                } catch {
                                    $statusCode = $null
                                    if ($_.Exception.Response) {
                                        $statusCode = [int]$_.Exception.Response.StatusCode
                                    }

                                    # Check if it's a timeout
                                    $isTimeout = $_.Exception.Message -like "*timeout*" -or $_.Exception.Message -like "*timed out*"

                                    if ($statusCode -eq 429 -or $statusCode -eq 403) {
                                        $delay = $baseDelay * [Math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 1 -Maximum 10)
                                        $delay = [Math]::Min($delay, 300)
                                        Start-Sleep -Seconds $delay
                                    } elseif ($isTimeout -and $attempt -lt $maxRetries) {
                                        # Retry on timeout with shorter delay
                                        Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 5)
                                    } elseif ($attempt -lt $maxRetries) {
                                        $delay = Get-Random -Minimum 5 -Maximum 15
                                        Start-Sleep -Seconds $delay
                                    } else {
                                        throw "Chunk $chunkIndex : Failed after $maxRetries attempts. Last error: $_"
                                    }
                                }
                            }

                            if ($response -and $response.data) {
                                $chunkEvents.AddRange($response.data)
                            }

                            # Check if there are more pages
                            $returnedCount = if ($response.data) { $response.data.Count } else { 0 }
                            if ($returnedCount -lt $pageSize) {
                                break
                            } else {
                                $skip += $pageSize
                                Start-Sleep -Milliseconds (Get-Random -Minimum 500 -Maximum 1500)
                            }
                        } while ($true)

                        $chunkStopwatch.Stop()
                        $chunkSuccess = $true
                        $elapsedSeconds = $chunkStopwatch.Elapsed.TotalSeconds

                        # Write results to JSON file
                        $fileName = "chunk_{0:D4}_{1:yyyyMMdd}_{2:yyyyMMdd}.json" -f $chunkIndex, $chunkFromDate, $chunkToDate
                        $filePath = Join-Path $tempPath $fileName

                        $jsonContent = @{
                            ChunkIndex = $chunkIndex
                            FromDate   = $chunkFromDate.ToString('o')
                            ToDate     = $chunkToDate.ToString('o')
                            EventCount = $chunkEvents.Count
                            Events     = $chunkEvents
                        } | ConvertTo-Json -Depth 10 -Compress

                        $jsonContent | Out-File -FilePath $filePath -Encoding utf8
                        $fileSizeKB = [math]::Round((Get-Item $filePath).Length / 1KB, 2)

                        @{
                            ChunkIndex     = $chunkIndex
                            FilePath       = $filePath
                            EventCount     = $chunkEvents.Count
                            FromDate       = $chunkFromDate
                            ToDate         = $chunkToDate
                            Success        = $true
                            ElapsedSeconds = [math]::Round($elapsedSeconds, 2)
                            PagesRetrieved = $pagesRetrieved
                            FileSizeKB     = $fileSizeKB
                            ChunkAttempts  = $chunkAttempt
                        }
                    } catch {
                        if ($chunkStopwatch) { $chunkStopwatch.Stop() }
                        $lastChunkError = $_.ToString()

                        # Non-retryable error or max retries reached
                        if ($chunkAttempt -ge $maxRetries) {
                            @{
                                ChunkIndex     = $chunkIndex
                                Success        = $false
                                Error          = "$lastChunkError (after $chunkAttempt chunk attempts)"
                                FromDate       = $chunkFromDate
                                ToDate         = $chunkToDate
                                ElapsedSeconds = if ($chunkStopwatch) { [math]::Round($chunkStopwatch.Elapsed.TotalSeconds, 2) } else { 0 }
                                ChunkAttempts  = $chunkAttempt
                            }
                        }
                    }
                }
            }

            # Process chunks in parallel using ForEach-Object -Parallel (PowerShell 7+)
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $totalChunks = $dateChunks.Count
                # Convert scriptblock to string for transfer to parallel runspaces
                $processingScriptString = $chunkProcessingScript.ToString()
                $parallelJob = Start-ThreadJob -ScriptBlock {
                    param($chunks, $throttle, $userIds, $baseParams, $tempPath, $cookieInfo, $headerInfo, $baseUrl, $scriptString)
                    $chunks | ForEach-Object -ThrottleLimit $throttle -Parallel {
                        $chunk = $_
                        # Recreate scriptblock from string in parallel context
                        $script = [scriptblock]::Create($using:scriptString)
                        & $script -chunk $chunk -userIds $using:userIds -baseParams $using:baseParams -tempPath $using:tempPath -cookieInfo $using:cookieInfo -headerInfo $using:headerInfo -baseUrl $using:baseUrl
                    }
                } -ArgumentList $dateChunks, $ThrottleLimit, $userIdentifiers, $baseQueryParams, $runTempPath, $cookieData, $headersData, $script:XdrBaseUrl, $processingScriptString

                # Poll for progress with stall detection
                $lastCompletedCount = 0
                $completedChunks = @{}
                $stallTimeoutSeconds = $StallTimeoutSeconds
                $recentProgressSeconds = $RecentProgressSeconds
                $lastProgressTime = [System.Diagnostics.Stopwatch]::StartNew()
                Write-Verbose "Stall detection timeout: $stallTimeoutSeconds seconds (page-level)"

                while ($parallelJob.State -in @('NotStarted', 'Running')) {
                    if ($operationStartTime.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                        Write-Warning "Operation timed out after $TimeoutSeconds seconds. Stopping job..."
                        Stop-Job -Job $parallelJob
                        break
                    }

                    # Check for page-level progress (progress_*.txt files updated by parallel jobs)
                    $progressFiles = Get-ChildItem -Path $runTempPath -Filter "progress_*.txt" -ErrorAction SilentlyContinue
                    $recentProgress = $progressFiles | Where-Object { ([datetime]::UtcNow - $_.LastWriteTimeUtc).TotalSeconds -lt $recentProgressSeconds }
                    if ($recentProgress) {
                        $lastProgressTime.Restart()  # Reset stall timer on any page-level progress
                    }

                    # Check for completed chunks
                    $chunkFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue
                    $completedFiles = $chunkFiles.Count

                    if ($completedFiles -gt $lastCompletedCount) {
                        foreach ($file in $chunkFiles) {
                            if (-not $completedChunks.ContainsKey($file.Name)) {
                                $completedChunks[$file.Name] = $true
                                $sizeKB = [math]::Round($file.Length / 1KB, 1)
                                Write-Verbose "  Downloaded chunk $($completedChunks.Count)/${totalChunks}: $($file.BaseName) ($sizeKB KB)"
                            }
                        }
                        $lastCompletedCount = $completedFiles
                        $lastProgressTime.Restart()  # Also reset on chunk completion
                    } elseif ($lastProgressTime.Elapsed.TotalSeconds -gt $stallTimeoutSeconds -and $completedFiles -lt $totalChunks) {
                        # No page-level or chunk-level progress - likely hung
                        $stalledCount = $totalChunks - $completedFiles
                        Write-Warning "No progress for $stallTimeoutSeconds seconds ($stalledCount chunks remaining). Stopping job..."
                        Stop-Job -Job $parallelJob
                        break
                    }

                    $percentComplete = [math]::Min(99, [math]::Round(($completedFiles / [math]::Max(1, $totalChunks)) * 100))
                    Write-Progress -Activity "Retrieving User Timeline for $userDisplayName" -Status "Downloaded $completedFiles of $totalChunks chunks" -PercentComplete $percentComplete -Id 1

                    Start-Sleep -Milliseconds 250
                }

                # Handle job terminal states
                $jobState = $parallelJob.State
                if ($jobState -eq 'Failed') {
                    $jobError = $parallelJob.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason } | Where-Object { $_ }
                    Write-Warning "Parallel job failed: $($jobError -join '; ')"
                } elseif ($jobState -eq 'Stopped') {
                    Write-Warning "Parallel job was stopped (likely due to timeout or stall)"
                }

                # Final check for completed chunks
                $chunkFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue
                foreach ($file in $chunkFiles) {
                    if (-not $completedChunks.ContainsKey($file.Name)) {
                        $completedChunks[$file.Name] = $true
                    }
                }

                $results = Receive-Job -Job $parallelJob -Wait
                Remove-Job -Job $parallelJob -Force
            } else {
                # Fallback for PowerShell 5.1 using runspace pool
                # Uses the shared $chunkProcessingScript defined above
                $runspacePool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
                $runspacePool.Open()

                $chunkQueue = [System.Collections.Generic.Queue[object]]::new($dateChunks)
                $activeJobs = [System.Collections.Generic.List[object]]::new()
                $results = @()
                $totalJobs = $dateChunks.Count
                $completedChunks = @{}

                $createJob = {
                    param($chunk)
                    $powershell = [powershell]::Create()
                    $powershell.RunspacePool = $runspacePool
                    [void]$powershell.AddScript($chunkProcessingScript)
                    [void]$powershell.AddParameter('chunk', $chunk)
                    [void]$powershell.AddParameter('userIds', $userIdentifiers)
                    [void]$powershell.AddParameter('baseParams', $baseQueryParams)
                    [void]$powershell.AddParameter('tempPath', $runTempPath)
                    [void]$powershell.AddParameter('cookieInfo', $cookieData)
                    [void]$powershell.AddParameter('headerInfo', $headersData)
                    [void]$powershell.AddParameter('baseUrl', $script:XdrBaseUrl)

                    @{
                        PowerShell = $powershell
                        Handle     = $powershell.BeginInvoke()
                        Chunk      = $chunk
                        StartTime  = [datetime]::UtcNow
                    }
                }

                while ($chunkQueue.Count -gt 0 -and $activeJobs.Count -lt $ThrottleLimit) {
                    $chunk = $chunkQueue.Dequeue()
                    $job = & $createJob $chunk
                    $activeJobs.Add($job)
                }

                # Stall timeout
                $stallTimeoutSeconds = $StallTimeoutSeconds
                $recentProgressSeconds = $RecentProgressSeconds
                $lastProgressTime = [System.Diagnostics.Stopwatch]::StartNew()
                $lastCompletedCount = 0

                while ($activeJobs.Count -gt 0) {
                    if ($operationStartTime.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                        Write-Warning "Operation timed out. Stopping remaining jobs..."
                        foreach ($job in $activeJobs) {
                            $job.PowerShell.Stop()
                            $job.PowerShell.Dispose()
                        }
                        break
                    }

                    # Check for page-level progress
                    $progressFiles = Get-ChildItem -Path $runTempPath -Filter "progress_*.txt" -ErrorAction SilentlyContinue
                    $recentProgress = $progressFiles | Where-Object { ([datetime]::UtcNow - $_.LastWriteTimeUtc).TotalSeconds -lt $recentProgressSeconds }
                    if ($recentProgress) {
                        $lastProgressTime.Restart()
                    }

                    $completedJobs = $activeJobs | Where-Object { $_.Handle.IsCompleted }

                    if ($completedJobs.Count -gt 0) {
                        $lastProgressTime.Restart()  # Reset stall timer on progress
                    } elseif ($lastProgressTime.Elapsed.TotalSeconds -gt $stallTimeoutSeconds) {
                        # No page-level or job-level progress - check for stalled jobs
                        $stalledJobs = $activeJobs | Where-Object { ([datetime]::UtcNow - $_.StartTime).TotalSeconds -gt $stallTimeoutSeconds }
                        if ($stalledJobs.Count -gt 0) {
                            Write-Warning "No progress for $stallTimeoutSeconds seconds ($($stalledJobs.Count) jobs appear stalled). Stopping stalled jobs..."
                            foreach ($job in $stalledJobs) {
                                $job.PowerShell.Stop()
                                $job.PowerShell.Dispose()
                                $results += @{
                                    ChunkIndex = $job.Chunk.Index
                                    Success    = $false
                                    Error      = "Job timed out after $stallTimeoutSeconds seconds"
                                    FromDate   = $job.Chunk.FromDate
                                    ToDate     = $job.Chunk.ToDate
                                }
                                $activeJobs.Remove($job)
                            }
                            $lastProgressTime.Restart()
                        }
                    }

                    foreach ($job in $completedJobs) {
                        try {
                            $result = $job.PowerShell.EndInvoke($job.Handle)
                            $results += $result
                        } catch {
                            $results += @{
                                ChunkIndex = $job.Chunk.Index
                                Success    = $false
                                Error      = $_.ToString()
                                FromDate   = $job.Chunk.FromDate
                                ToDate     = $job.Chunk.ToDate
                            }
                        }
                        $job.PowerShell.Dispose()
                        $activeJobs.Remove($job)

                        if ($chunkQueue.Count -gt 0) {
                            $nextChunk = $chunkQueue.Dequeue()
                            $newJob = & $createJob $nextChunk
                            $activeJobs.Add($newJob)
                        }
                    }

                    $chunkFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue
                    $completedFiles = $chunkFiles.Count
                    $percentComplete = [math]::Min(99, [math]::Round(($completedFiles / [math]::Max(1, $totalJobs)) * 100))
                    Write-Progress -Activity "Retrieving User Timeline for $userDisplayName" -Status "Downloaded $completedFiles of $totalJobs chunks" -PercentComplete $percentComplete -Id 1

                    Start-Sleep -Milliseconds 100
                }

                $runspacePool.Close()
                $runspacePool.Dispose()
            }

            Write-Progress -Activity "Retrieving User Timeline for $userDisplayName" -Completed -Id 1

            # Check for failures
            $failures = $results | Where-Object { -not $_.Success }
            if ($failures) {
                Write-Warning "Some chunks failed to retrieve: $($failures.Count) failures"
                foreach ($fail in $failures) {
                    Write-Warning "  Chunk $($fail.ChunkIndex) ($($fail.FromDate) - $($fail.ToDate)): $($fail.Error)"
                }
            }

            # Output timing information for each chunk
            Write-Information "`n=== Chunk Download Statistics ===" -InformationAction Continue
            $successfulResults = $results | Where-Object { $_.Success }
            $totalElapsed = 0
            $totalSizeKB = 0
            foreach ($result in ($successfulResults | Sort-Object ChunkIndex)) {
                $totalElapsed += $result.ElapsedSeconds
                $totalSizeKB += $result.FileSizeKB
            }

            # Show slowest chunks for analysis (verbose only)
            if ($successfulResults) {
                $timingStats = $successfulResults | Measure-Object -Property ElapsedSeconds -Minimum -Maximum -Average
                Write-Verbose "Chunk timing stats: Min=$([math]::Round($timingStats.Minimum, 2))s, Max=$([math]::Round($timingStats.Maximum, 2))s, Avg=$([math]::Round($timingStats.Average, 2))s"
                
                $slowest = $successfulResults | Sort-Object ElapsedSeconds -Descending | Select-Object -First 5
                Write-Verbose "Slowest chunks:"
                foreach ($chunk in $slowest) {
                    Write-Verbose "  Chunk $($chunk.ChunkIndex): $([math]::Round($chunk.ElapsedSeconds, 2))s ($($chunk.FileSizeKB) KB)"
                }
            }

            # Merge results from JSON files
            Write-Verbose "Merging results from chunk files..."
            $allEvents = [System.Collections.Generic.List[object]]::new()
            $chunkFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue | Sort-Object Name

            foreach ($file in $chunkFiles) {
                $chunkData = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
                if ($null -ne $chunkData.Events -and $chunkData.Events.Count -gt 0) {
                    foreach ($timelineEvent in $chunkData.Events) {
                        $timelineEvent.PSObject.TypeNames.Insert(0, 'XdrIdentityUserTimelineEvent')
                        $allEvents.Add($timelineEvent)
                    }
                }
            }

            # Include Sentinel events if requested
            if ($IncludeSentinelEvents -and $resolvedUser.ids.armId) {
                Write-Verbose "Fetching Sentinel UEBA anomaly events..."

                # Parse armId to extract subscription, resource group, workspace, and entity ID
                # Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/entities/{entityId}
                $armId = $resolvedUser.ids.armId
                if ($armId -match '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.OperationalInsights/workspaces/([^/]+)/providers/Microsoft.SecurityInsights/entities/([^/]+)') {
                    $subscriptionId = $Matches[1]
                    $resourceGroup = $Matches[2]
                    $workspace = $Matches[3]
                    $entityId = $Matches[4]

                    $sentinelUri = "$script:XdrBaseUrl/apiproxy/arm/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.OperationalInsights/workspaces/$workspace/providers/Microsoft.SecurityInsights/entities/$entityId/gettimeline?api-version=2022-10-01-preview"

                    $sentinelBody = @{
                        kinds         = @("Anomaly")
                        startTime     = $FromDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                        endTime       = $ToDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                        numberOfBucket = 6
                    }

                    try {
                        $sentinelResponse = Invoke-RestMethod -Uri $sentinelUri `
                            -Method POST `
                            -ContentType "application/json" `
                            -Body ($sentinelBody | ConvertTo-Json -Depth 10) `
                            -WebSession $script:session `
                            -Headers $mdiHeaders `
                            -ErrorAction Stop

                        if ($sentinelResponse.value -and $sentinelResponse.value.Count -gt 0) {
                            Write-Verbose "Retrieved $($sentinelResponse.value.Count) Sentinel anomaly events"
                            foreach ($timelineEvent in $sentinelResponse.value) {
                                $timelineEvent.PSObject.TypeNames.Insert(0, 'XdrIdentityUserTimelineEvent')
                                $timelineEvent | Add-Member -NotePropertyName 'SourceTable' -NotePropertyValue 'SentinelAnomaly' -Force
                                $allEvents.Add($timelineEvent)
                            }
                        } else {
                            Write-Verbose "No Sentinel anomaly events found for this time range"
                        }
                    } catch {
                        Write-Warning "Failed to retrieve Sentinel events: $($_.Exception.Message)"
                        Write-Verbose "Full error: $($_.Exception.ToString())"
                    }
                } else {
                    Write-Verbose "Could not parse armId for Sentinel API call: $armId"
                }
            } elseif ($IncludeSentinelEvents -and -not $resolvedUser.ids.armId) {
                Write-Verbose "User does not have an armId (Sentinel entity ID). Sentinel events cannot be retrieved."
                # TODO: Consider adding -SentinelWorkspaceId and -SentinelSubscriptionId parameters
                # if armId auto-detection doesn't work for a majority of users/tenants.
            }

            # Sort events by timestamp (newest first)
            $sortedEvents = $allEvents | Sort-Object -Property Timestamp -Descending

            $operationStartTime.Stop()
            $totalEvents = $sortedEvents.Count
            $successCount = ($results | Where-Object { $_.Success }).Count
            $failCount = ($results | Where-Object { -not $_.Success }).Count
            $wallClockSeconds = $operationStartTime.Elapsed.TotalSeconds
            $totalSizeMB = [math]::Round($totalSizeKB / 1024, 1)
            $effectiveRate = if ($wallClockSeconds -gt 0) { [math]::Round($totalEvents / $wallClockSeconds, 1) } else { 0 }

            Write-Information "=== Summary ===" -InformationAction Continue
            Write-Information "Total chunks: $successCount$(if ($failCount -gt 0) { " ($failCount failed)" }) | Total events: $totalEvents | Total size: $totalSizeMB MB" -InformationAction Continue
            Write-Information "Cumulative download time: $([math]::Round($totalElapsed, 2))s | Wall-clock time: $([math]::Round($wallClockSeconds, 2))s | Effective rate: $effectiveRate events/sec" -InformationAction Continue

            # Handle export
            if ($ExportPath) {
                Write-Verbose "Exporting results to $ExportPath"
                $sortedEvents | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding utf8
                Write-Information "Exported $totalEvents events to $ExportPath" -InformationAction Continue
            }

            # Cleanup temp files unless KeepTempFiles is specified
            # Always clean up progress_*.txt files - they're only used for stall detection
            Get-ChildItem -Path $runTempPath -Filter "progress_*.txt" -ErrorAction SilentlyContinue | 
                Remove-Item -Force -ErrorAction SilentlyContinue

            if (-not $KeepTempFiles -and -not $ExportPath) {
                Write-Verbose "Cleaning up temporary files in $runTempPath"
                Remove-Item -Path $runTempPath -Recurse -Force -ErrorAction SilentlyContinue
            } elseif ($KeepTempFiles) {
                Write-Information "Temporary files preserved in: $runTempPath" -InformationAction Continue
            }

            return $sortedEvents

        } catch {
            Write-Error -Exception $_.Exception -Message "Failed to retrieve user timeline: $($_.Exception.Message)"
            Write-Verbose "Full error: $($_.Exception.ToString())"

            # Cleanup on error
            if (-not $KeepTempFiles -and (Test-Path $runTempPath)) {
                Remove-Item -Path $runTempPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}