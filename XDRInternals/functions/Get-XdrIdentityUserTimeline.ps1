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

        Final merged results are strictly filtered to the requested [FromDate, ToDate) range.

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
        Lists available event types for filtering for the specified user and time range.
        Returns pipeline objects with EventType, Scope, and User properties.
        If no user identifier is supplied, returns global event types for the selected time range.

    .PARAMETER PageSize
        The number of events to return per page. Defaults to 1000.

    .PARAMETER IncludeSentinelEvents
        Include Microsoft Sentinel UEBA anomaly events in the timeline results.
        Requires the user to have an armId (Sentinel entity ID) which is auto-detected from
        the resolved user identifiers.

    .PARAMETER ThrottleLimit
        The maximum number of concurrent requests. Defaults to 32.

    .PARAMETER TimeoutSeconds
        Maximum time in seconds to wait for all requests to complete. Defaults to 3600 (1 hour).

    .PARAMETER MaxRetries
        Maximum number of retry attempts for failed API requests. Defaults to 3.

    .PARAMETER RetryDelaySeconds
        Base delay in seconds between retry attempts (uses exponential backoff). Defaults to 5.

    .PARAMETER ChunkSizeHours
        Maximum size of each time chunk in hours (1-168). Defaults to 72 hours.
        By default, adaptive chunking may reduce this value based on the requested range
        to improve throughput and avoid oversized identity timeline windows.

    .PARAMETER DisableAdaptiveChunking
        Disables adaptive chunk sizing and forces fixed-size chunks based on ChunkSizeHours.

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
        Get-XdrIdentityUserTimeline -Upn "user@domain.com"

        Retrieves the last day of timeline events for the specified user.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -AadId "a2307c5a-76df-4513-b575-0537842c1d8b" -LastNDays 7

        Retrieves 7 days of timeline events.

    .EXAMPLE
        Get-XdrIdentityUser -Upn "user@domain.com" | Get-XdrIdentityUserTimeline -LastNDays 30

        Retrieves user identity and pipes to timeline cmdlet for 30 days of events.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -Upn "user@domain.com" -LastNDays 7 -IncludeSentinelEvents

        Retrieves timeline events including Sentinel UEBA anomalies.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -Upn "user@domain.com" -LastNDays 7 -ListEventTypes

        Lists available event types for filtering for the specified user and time range.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -LastNDays 7 -ListEventTypes

        Lists global event types for the selected time range.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -LastNDays 7 -ListEventTypes | Select-Object -ExpandProperty EventType

        Returns only event type names for automation or downstream filtering.

    .EXAMPLE
        Get-XdrIdentityUserTimeline -Upn "user@domain.com" -LastNDays 90 -ExportPath "C:\Reports\user_timeline.json"

        Retrieves 90 days of timeline events and exports to JSON file.

    .OUTPUTS
        XdrIdentityUserTimelineEvent[]
        Returned when -ListEventTypes is not specified.

        PSCustomObject
        Returned when -ListEventTypes is specified, with EventType, Scope, and User properties.

    .NOTES
        The identity timeline API uses Unix timestamps in seconds (not milliseconds).

        # TODO: Consider adding -SentinelWorkspaceId and -SentinelSubscriptionId parameters
        # if armId auto-detection doesn't work for a majority of users/tenants.
    #>
    [OutputType([System.Object[]])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '')]
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
        [Parameter(ParameterSetName = 'ListEventTypesDateRange')]
        [datetime]$FromDate = ((Get-Date).AddDays(-1)),

        [Parameter(ParameterSetName = 'ByAadIdDateRange')]
        [Parameter(ParameterSetName = 'ByUpnDateRange')]
        [Parameter(ParameterSetName = 'BySidDateRange')]
        [Parameter(ParameterSetName = 'ByRadiusUserIdDateRange')]
        [Parameter(ParameterSetName = 'ByInputObjectDateRange')]
        [Parameter(ParameterSetName = 'ListEventTypesDateRange')]
        [datetime]$ToDate = (Get-Date),

        [Parameter(Mandatory, ParameterSetName = 'ByAadIdLastNDays')]
        [Parameter(Mandatory, ParameterSetName = 'ByUpnLastNDays')]
        [Parameter(Mandatory, ParameterSetName = 'BySidLastNDays')]
        [Parameter(Mandatory, ParameterSetName = 'ByRadiusUserIdLastNDays')]
        [Parameter(Mandatory, ParameterSetName = 'ByInputObjectLastNDays')]
        [Parameter(Mandatory, ParameterSetName = 'ListEventTypesLastNDays')]
        [ValidateRange(1, 180)]
        [int]$LastNDays,

        [Parameter()]
        [string[]]$EventType,

        [Parameter()]
        [Parameter(Mandatory, ParameterSetName = 'ListEventTypesDateRange')]
        [Parameter(Mandatory, ParameterSetName = 'ListEventTypesLastNDays')]
        [switch]$ListEventTypes,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$PageSize = 1000,

        [Parameter()]
        [switch]$IncludeSentinelEvents,

        [Parameter()]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = 32,

        [Parameter()]
        [ValidateRange(60, 86400)]
        [int]$TimeoutSeconds = 3600,

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$MaxRetries = 3,

        [Parameter()]
        [ValidateRange(1, 300)]
        [int]$RetryDelaySeconds = 5,

        [Parameter()]
        [ValidateRange(1, 168)]
        [int]$ChunkSizeHours = 72,

        [Parameter()]
        [switch]$DisableAdaptiveChunking,

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
        $IdentityMaxSkip = 9000            # Identity API skip values above 9000 are rejected

        # Build headers required for MDI identity APIs
        $mdiHeaders = Get-XdrIdentityHeaders

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

        # Resolve user identifiers when needed
        # Parameter set names include date range suffix (e.g., 'ByUpnDateRange', 'ByUpnLastNDays')
        # Use -like pattern matching to handle both variants
        $resolvedUser = $null
        $userIdentifiers = $null
        $fallbackDisplayName = $null
        $paramSetName = $PSCmdlet.ParameterSetName
        $isGlobalListEventTypes = $paramSetName -like 'ListEventTypes*'

        $throwResolveError = {
            param(
                [string]$IdentifierLabel,
                [string]$IdentifierValue,
                [System.Management.Automation.ErrorRecord]$ResolveError
            )

            $fqid = [string]$ResolveError.FullyQualifiedErrorId
            $isNotFound = $fqid -like 'XdrIdentityUserNotFound*' -or $fqid -like '*XdrIdentityUserNotFound*'

            if ($isNotFound) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.ArgumentException]::new("Could not resolve user with ${IdentifierLabel}: $IdentifierValue"),
                        'UserNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $IdentifierValue
                    )
                )
            }

            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.InvalidOperationException]::new("Failed to resolve user with $IdentifierLabel '$IdentifierValue': $($ResolveError.Exception.Message)"),
                    'UserResolveFailed',
                    [System.Management.Automation.ErrorCategory]::InvalidOperation,
                    $IdentifierValue
                )
            )
        }

        if (-not $isGlobalListEventTypes) {
            if ($paramSetName -like 'ByInputObject*') {
                # Already have resolved user from pipeline
                $resolvedUser = $InputObject
                try {
                    $userIdentifiers = ConvertTo-XdrIdentityUserIdentifiers -ResolvedUser $resolvedUser -ErrorAction Stop
                } catch {
                    $PSCmdlet.ThrowTerminatingError(
                        [System.Management.Automation.ErrorRecord]::new(
                            [System.ArgumentException]::new("InputObject does not contain usable identity identifiers: $($_.Exception.Message)"),
                            'InvalidInputObject',
                            [System.Management.Automation.ErrorCategory]::InvalidArgument,
                            $InputObject
                        )
                    )
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$resolvedUser.ids.upn)) {
                    $fallbackDisplayName = $resolvedUser.ids.upn
                } elseif (-not [string]::IsNullOrWhiteSpace([string]$resolvedUser.ids.aad)) {
                    $fallbackDisplayName = $resolvedUser.ids.aad
                }
            }
            elseif ($paramSetName -like 'ByAadId*') {
                Write-Verbose "Resolving user by AAD ID: $AadId"
                try {
                    $resolvedUser = Get-XdrIdentityUser -AadId $AadId -ErrorAction Stop
                } catch {
                    & $throwResolveError -IdentifierLabel 'AAD ID' -IdentifierValue $AadId -ResolveError $_
                }

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
                try {
                    $resolvedUser = Get-XdrIdentityUser -Upn $Upn -ErrorAction Stop
                } catch {
                    & $throwResolveError -IdentifierLabel 'UPN' -IdentifierValue $Upn -ResolveError $_
                }

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
                try {
                    $resolvedUser = Get-XdrIdentityUser -Sid $Sid -ErrorAction Stop
                } catch {
                    & $throwResolveError -IdentifierLabel 'SID' -IdentifierValue $Sid -ResolveError $_
                }

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
                try {
                    $resolvedUser = Get-XdrIdentityUser -RadiusUserId $RadiusUserId -ErrorAction Stop
                } catch {
                    & $throwResolveError -IdentifierLabel 'Radius User ID' -IdentifierValue $RadiusUserId -ResolveError $_
                }

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
            if (-not [string]::IsNullOrWhiteSpace([string]$resolvedUser.displayName)) {
                $userDisplayName = $resolvedUser.displayName
            } else {
                $userDisplayName = $fallbackDisplayName
            }
            if ([string]::IsNullOrWhiteSpace([string]$userDisplayName)) {
                $userDisplayName = 'UnknownUser'
            }
        } else {
            $userDisplayName = 'AllUsers'
        }

        # Handle ListEventTypes
        if ($ListEventTypes) {
            $filterOptionsUri = "$script:XdrBaseUrl/apiproxy/mdi/identity/userapiservice/timeline/FilterOptions/mtp"
            $fromUnix = [int]($FromDate.ToUniversalTime() - $UnixEpoch).TotalSeconds
            $toUnix = [int]($ToDate.ToUniversalTime() - $UnixEpoch).TotalSeconds

            $filterBody = @{
                filterNames = @('Type')
                filters = @{
                    Timeframe = @{
                        between = @($fromUnix, $toUnix)
                    }
                }
                hasMultipleFilters = $false
            }
            if ($null -ne $userIdentifiers -and $userIdentifiers.Count -gt 0) {
                $filterBody['userIdentifiers'] = $userIdentifiers
            }

            try {
                $filterResponse = Invoke-RestMethod -Uri $filterOptionsUri `
                    -Method POST `
                    -ContentType "application/json" `
                    -Body ($filterBody | ConvertTo-Json -Depth 10) `
                    -WebSession $script:session `
                    -Headers $mdiHeaders `
                    -ErrorAction Stop

                $scopeLabel = if ($isGlobalListEventTypes) { 'Global' } else { 'User' }
                if ($isGlobalListEventTypes) {
                    Write-Information 'Available global event types for the selected time range:' -InformationAction Continue
                } else {
                    Write-Information "Available event types for user '$userDisplayName':" -InformationAction Continue
                }

                $eventTypeResults = @()
                if ($null -ne $filterResponse.data -and $filterResponse.data.Count -gt 0) {
                    $eventTypeResults = $filterResponse.data |
                        Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_.Type) } |
                        ForEach-Object {
                            [PSCustomObject]@{
                                EventType = [string]$_.Type
                                Scope     = $scopeLabel
                                User      = if ($isGlobalListEventTypes) { $null } else { $userDisplayName }
                            }
                        } |
                        Sort-Object EventType -Unique
                }

                if ($eventTypeResults.Count -eq 0) {
                    if ($isGlobalListEventTypes) {
                        Write-Information 'No event types found for this time range.' -InformationAction Continue
                    } else {
                        Write-Information 'No event types found for this user and time range.' -InformationAction Continue
                    }
                    return
                }

                $eventTypeResults
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
            MaxSkip           = $IdentityMaxSkip
        }

        # Generate date chunks.
        # Adaptive chunking reduces chunk size using a tested range profile.
        $dateChunks = [System.Collections.Generic.List[hashtable]]::new()
        $totalTimespan = $ToDate - $FromDate
        $totalDays = $totalTimespan.TotalDays
        $totalHours = [int][Math]::Ceiling([Math]::Max(1, $totalTimespan.TotalHours))

        $configuredChunkHours = [int]$ChunkSizeHours
        $chunkHours = $configuredChunkHours
        $adaptiveChunkingApplied = $false

        $configuredChunkCount = [int][Math]::Ceiling($totalHours / [double][Math]::Max(1, $configuredChunkHours))

        # Adaptive chunk profile tuned from benchmark data after strict in-range filtering.
        # - <= 30 days: 72h chunks provide highest throughput.
        # - > 30 days : 48h chunks avoid long-tail slowdowns on larger windows.
        if (-not $DisableAdaptiveChunking) {
            $rangeMaxChunkHours = if ($totalDays -le 30) {
                72
            } else {
                48
            }

            $adaptiveChunkHours = [int][Math]::Min($configuredChunkHours, $rangeMaxChunkHours)
            if ($adaptiveChunkHours -lt $chunkHours) {
                $chunkHours = $adaptiveChunkHours
                $adaptiveChunkingApplied = $true
            }
        }

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

        if ($adaptiveChunkingApplied) {
            Write-Verbose "Adaptive chunking reduced chunk size from $configuredChunkHours to $chunkHours hours (configured chunks: $configuredChunkCount, generated chunks: $($dateChunks.Count), throttle: $ThrottleLimit)"
        } elseif ($DisableAdaptiveChunking) {
            Write-Verbose "Adaptive chunking disabled; using fixed chunk size of $chunkHours hours"
        }

        $chunkModeLabel = if ($adaptiveChunkingApplied) { 'adaptive' } else { 'fixed' }
        Write-Information "Split $([math]::Round($totalDays, 1)) days into $($dateChunks.Count) chunks ($chunkHours hours each, $chunkModeLabel)" -InformationAction Continue

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
                $maxSkip = $baseParams.MaxSkip
                $pageSize = $baseParams.PageSize

                # Chunk-level retry loop
                $chunkAttempt = 0
                $chunkSuccess = $false
                $lastChunkError = $null

                while (-not $chunkSuccess -and $chunkAttempt -lt $maxRetries) {
                    $chunkAttempt++
                    $chunkEvents = [System.Collections.Generic.List[object]]::new()
                    $skip = 0
                    $currentToUnix = $toUnix
                    $previousBoundaryTimestamp = $null
                    $progressFile = Join-Path $tempPath "progress_$chunkIndex.txt"
                    $lastProgressWriteUtc = [datetime]::MinValue

                    try {
                        $chunkStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                        $pagesRetrieved = 0
                        $boundaryTimestamp = $null
                        $boundaryCount = 0

                        do {
                            # Build request body
                            $requestBody = @{
                                count           = $pageSize
                                skip            = $skip
                                userIdentifiers = $userIds
                                filters         = @{
                                    Timeframe = @{
                                        between = @($fromUnix, $currentToUnix)
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
                            $response = $null

                            while (-not $success -and $attempt -lt $maxRetries) {
                                try {
                                    $attempt++
                                    $response = Invoke-RestMethod -Uri $Uri -Method POST -ContentType "application/json" -Body $bodyJson -WebSession $webSession -Headers $headerInfo -TimeoutSec $requestTimeout -ErrorAction Stop
                                    $success = $true
                                    $pagesRetrieved++

                                    # Signal page-level progress to outer loop (throttled to avoid excessive file I/O)
                                    if (([datetime]::UtcNow - $lastProgressWriteUtc).TotalSeconds -ge 1) {
                                        "$pagesRetrieved" | Out-File -FilePath $progressFile -Force -NoNewline
                                        $lastProgressWriteUtc = [datetime]::UtcNow
                                    }
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
                                        Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 5)
                                    } elseif ($attempt -lt $maxRetries) {
                                        $delay = Get-Random -Minimum 5 -Maximum 15
                                        Start-Sleep -Seconds $delay
                                    } else {
                                        throw "Chunk $chunkIndex : Failed after $maxRetries attempts. Last error: $_"
                                    }
                                }
                            }

                            $responseData = if ($response -and $response.data) { @($response.data) } else { @() }
                            if ($responseData.Count -eq 0) {
                                break
                            }

                            foreach ($timelineEvent in $responseData) {
                                $chunkEvents.Add($timelineEvent)

                                # Track the oldest timestamp and count events at that boundary.
                                if ($timelineEvent.PSObject.Properties['Timestamp'] -and $timelineEvent.Timestamp) {
                                    try {
                                        $eventTimestamp = [datetime]::Parse($timelineEvent.Timestamp).ToUniversalTime()
                                        if ($null -eq $boundaryTimestamp -or $eventTimestamp -lt $boundaryTimestamp) {
                                            $boundaryTimestamp = $eventTimestamp
                                            $boundaryCount = 1
                                        } elseif ($eventTimestamp -eq $boundaryTimestamp) {
                                            $boundaryCount++
                                        }
                                    } catch {
                                        Write-Verbose "Ignoring timestamp parse errors for boundary tracking."
                                    }
                                }
                            }

                            if ($responseData.Count -lt $pageSize) {
                                break
                            }

                            $nextSkip = $skip + $responseData.Count
                            if ($nextSkip -gt $maxSkip) {
                                if ($null -eq $boundaryTimestamp) {
                                    throw "Chunk $chunkIndex : Hit skip limit but no boundary timestamp was available"
                                }

                                # Pathological case: too many events in one second (> maxSkip + pageSize).
                                if ($null -ne $previousBoundaryTimestamp -and $boundaryTimestamp -eq $previousBoundaryTimestamp) {
                                    # API cannot page past this second. Drop all events for this second so output is deterministic.
                                    $keptEvents = [System.Collections.Generic.List[object]]::new()
                                    $droppedCount = 0
                                    foreach ($existingEvent in $chunkEvents) {
                                        $isBoundaryEvent = $false
                                        if ($existingEvent.PSObject.Properties['Timestamp'] -and $existingEvent.Timestamp) {
                                            try {
                                                $existingTs = [datetime]::Parse($existingEvent.Timestamp).ToUniversalTime()
                                                $isBoundaryEvent = ($existingTs -eq $boundaryTimestamp)
                                            } catch {
                                                Write-Verbose "Ignoring timestamp parse errors; treat event as non-boundary."
                                            }
                                        }

                                        if ($isBoundaryEvent) {
                                            $droppedCount++
                                        } else {
                                            $keptEvents.Add($existingEvent)
                                        }
                                    }
                                    $chunkEvents = $keptEvents

                                    Write-Warning "Chunk $chunkIndex : More than $($maxSkip + $pageSize) events at timestamp $($boundaryTimestamp.ToString('o')); dropped $droppedCount events at this second due to API pagination limits"

                                    # Move to older data and skip this second entirely.
                                    $currentToUnix = [int]($boundaryTimestamp.AddSeconds(-1) - $unixEpoch).TotalSeconds
                                    if ($currentToUnix -lt $fromUnix) {
                                        break
                                    }

                                    $skip = 0
                                    $previousBoundaryTimestamp = $null
                                    $boundaryTimestamp = $null
                                    $boundaryCount = 0
                                    continue
                                }
                                # Remove the incomplete boundary second and restart at that boundary.
                                if ($boundaryCount -gt 0 -and $boundaryCount -le $chunkEvents.Count) {
                                    $chunkEvents.RemoveRange($chunkEvents.Count - $boundaryCount, $boundaryCount)
                                }

                                $previousBoundaryTimestamp = $boundaryTimestamp
                                $currentToUnix = [int]($boundaryTimestamp.AddSeconds(1) - $unixEpoch).TotalSeconds
                                $skip = 0
                                $boundaryTimestamp = $null
                                $boundaryCount = 0
                                continue
                            }

                            $skip = $nextSkip
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
            $eventRows = [System.Collections.Generic.List[object]]::new()
            $stableEventKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            $mergeCounters = @{
                TotalCandidates     = 0
                Duplicates          = 0
                OutOfRange          = 0
                MissingTimestamp    = 0
                TimestampParseErrors = 0
            }
            $fromUtcInclusive = $FromDate.ToUniversalTime()
            $toUtcExclusive = $ToDate.ToUniversalTime()
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $chunkFiles = Get-ChildItem -Path $runTempPath -Filter "chunk_*.json" -ErrorAction SilentlyContinue | Sort-Object Name

            $addDedupedEvent = {
                param([PSObject]$eventObject)

                $eventTimestampUtc = $null

                if ($eventObject.PSObject.Properties['Timestamp'] -and $null -ne $eventObject.Timestamp -and -not [string]::IsNullOrWhiteSpace([string]$eventObject.Timestamp)) {
                    try {
                        $eventTimestampUtc = ([datetime]$eventObject.Timestamp).ToUniversalTime()
                    } catch {
                        $mergeCounters['TimestampParseErrors']++
                        return
                    }
                } elseif ($eventObject.PSObject.Properties['ActionTimeIsoString'] -and -not [string]::IsNullOrWhiteSpace([string]$eventObject.ActionTimeIsoString)) {
                    try {
                        $eventTimestampUtc = ([datetime]$eventObject.ActionTimeIsoString).ToUniversalTime()
                    } catch {
                        $mergeCounters['TimestampParseErrors']++
                        return
                    }
                } elseif ($eventObject.PSObject.Properties['TimeGenerated'] -and -not [string]::IsNullOrWhiteSpace([string]$eventObject.TimeGenerated)) {
                    try {
                        $eventTimestampUtc = ([datetime]$eventObject.TimeGenerated).ToUniversalTime()
                    } catch {
                        $mergeCounters['TimestampParseErrors']++
                        return
                    }
                } else {
                    $mergeCounters['MissingTimestamp']++
                    return
                }

                if ($eventTimestampUtc -lt $fromUtcInclusive -or $eventTimestampUtc -ge $toUtcExclusive) {
                    $mergeCounters['OutOfRange']++
                    return
                }

                $unstableProperties = @('Id', 'RowNumber', 'EventId', 'ReportId')
                $stablePayload = [ordered]@{}
                foreach ($property in ($eventObject.PSObject.Properties | Sort-Object Name)) {
                    if ($unstableProperties -notcontains $property.Name) {
                        $stablePayload[$property.Name] = $property.Value
                    }
                }

                $stableJson = $stablePayload | ConvertTo-Json -Depth 20 -Compress
                $stableHashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stableJson))
                $stableKey = [System.BitConverter]::ToString($stableHashBytes).Replace('-', '')
                $mergeCounters['TotalCandidates']++

                if ($stableEventKeys.Add($stableKey)) {
                    [void]$eventRows.Add([PSCustomObject]@{
                        Event        = $eventObject
                        TimestampKey = $eventTimestampUtc.ToString('o')
                        StableKey    = $stableKey
                    })
                } else {
                    $mergeCounters['Duplicates']++
                }
            }

            foreach ($file in $chunkFiles) {
                $chunkData = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
                if ($null -ne $chunkData.Events -and $chunkData.Events.Count -gt 0) {
                    foreach ($timelineEvent in $chunkData.Events) {
                        $timelineEvent.PSObject.TypeNames.Insert(0, 'XdrIdentityUserTimelineEvent')
                        $sourceTableProperty = $timelineEvent.PSObject.Properties['SourceTable']
                        if ($null -eq $sourceTableProperty -or -not $sourceTableProperty.Value) {
                            $timelineEvent | Add-Member -NotePropertyName 'SourceTable' -NotePropertyValue 'MDI' -Force
                        }
                        & $addDedupedEvent -eventObject $timelineEvent
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
                                & $addDedupedEvent -eventObject $timelineEvent
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

            $sha256.Dispose()
            Write-Verbose "Merge stats: candidates=$($mergeCounters.TotalCandidates), duplicates=$($mergeCounters.Duplicates), outOfRange=$($mergeCounters.OutOfRange), missingTimestamp=$($mergeCounters.MissingTimestamp), timestampParseErrors=$($mergeCounters.TimestampParseErrors)"

            # Sort events by timestamp (newest first) with deterministic tie-breaker
            $sortedEvents = $eventRows |
                Sort-Object -Property @{ Expression = 'TimestampKey'; Descending = $true }, @{ Expression = 'StableKey'; Descending = $false } |
                ForEach-Object { $_.Event }

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

            # Cleanup temp files unless KeepTempFiles is specified.
            # Progress files are always removed because they are only used for stall detection.
            Get-ChildItem -Path $runTempPath -Filter "progress_*.txt" -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue

            if (-not $KeepTempFiles) {
                Write-Verbose "Cleaning up temporary files in $runTempPath"
                Remove-Item -Path $runTempPath -Recurse -Force -ErrorAction SilentlyContinue
            } else {
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




