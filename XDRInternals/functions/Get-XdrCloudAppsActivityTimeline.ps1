function ConvertFrom-XdrCloudAppsActivityJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Json
    )

    if ((Get-Command ConvertFrom-Json -ErrorAction Stop).Parameters.ContainsKey('AsHashtable')) {
        return $Json | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    }

    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = [int]::MaxValue
    return $serializer.DeserializeObject($Json)
}

function Read-XdrCloudAppsActivityChunkFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,

        [Parameter()]
        [switch]$AllowPartial
    )

    try {
        return ConvertFrom-XdrCloudAppsActivityJson -Json (Get-Content -Path $File.FullName -Raw -ErrorAction Stop)
    }
    catch {
        if ($AllowPartial) {
            Write-Warning "Skipping unreadable Cloud Apps activity chunk file '$($File.Name)': $($_.Exception.Message)"
            return $null
        }

        throw
    }
}

function Get-XdrCloudAppsObjectValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string[]]$Name
    )

    foreach ($currentName in $Name) {
        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($currentName)) {
                return $InputObject[$currentName]
            }

            foreach ($key in $InputObject.Keys) {
                if ([string]$key -ceq $currentName) {
                    return $InputObject[$key]
                }
            }

            foreach ($key in $InputObject.Keys) {
                if ([string]$key -ieq $currentName) {
                    return $InputObject[$key]
                }
            }
        }
        elseif ($InputObject.PSObject.Properties[$currentName]) {
            return $InputObject.$currentName
        }
    }

    return $null
}

function Get-XdrCloudAppsActivityEventTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Activity
    )

    $timestampValue = Get-XdrCloudAppsObjectValue -InputObject $Activity -Name 'timestamp'
    if ($timestampValue) {
        $numericTimestamp = [double]$timestampValue
        if ($numericTimestamp -gt 9999999999) {
            return [DateTimeOffset]::FromUnixTimeMilliseconds([long]$numericTimestamp).UtcDateTime
        }

        return [DateTimeOffset]::FromUnixTimeSeconds([long]$numericTimestamp).UtcDateTime
    }

    $dateValue = Get-XdrCloudAppsObjectValue -InputObject $Activity -Name @('date', 'Date')
    if ($dateValue) {
        return ([datetime]$dateValue).ToUniversalTime()
    }

    return $null
}

function Get-XdrCloudAppsActivityStableKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Activity,

        [Parameter(Mandatory)]
        [System.Security.Cryptography.SHA256]$Sha256
    )

    foreach ($name in @('_id', 'id', 'recordId')) {
        $value = Get-XdrCloudAppsObjectValue -InputObject $Activity -Name $name
        if ($value) {
            return [string]$value
        }
    }

    $stableJson = $Activity | ConvertTo-Json -Depth 20 -Compress
    return [System.BitConverter]::ToString($Sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stableJson))).Replace('-', '')
}

function Get-XdrCloudAppsActivityTimeline {
    <#
    .SYNOPSIS
        Retrieves Microsoft Defender for Cloud Apps activity timeline data.

    .DESCRIPTION
        Retrieves Cloud Apps activity events with reliable chunking, retry handling,
        recent/archived API routing, export support, and typed admin-friendly output.

    .PARAMETER Metadata
        Returns filter metadata for the recent activities API.

    .PARAMETER ArchivedMetadata
        Returns filter metadata for the archived activities API.

    .PARAMETER Raw
        Returns raw API metadata or response data when supported.

    .PARAMETER CountOnly
        Returns activity counts without retrieving full activity records.

    .PARAMETER FromDate
        Start of the timeline range.

    .PARAMETER ToDate
        End of the timeline range.

    .PARAMETER LastNDays
        Retrieves activity from the last specified number of days.

    .PARAMETER PageSize
        Number of activities to request per page.

    .PARAMETER Filters
        Cloud Apps activity filters to include in the query body.

    .PARAMETER IncludeThreatScores
        Adds threat score data for recent activities when available.

    .PARAMETER ThrottleLimit
        Maximum number of chunks to retrieve concurrently.

    .PARAMETER ChunkHours
        Maximum hours represented by each activity chunk.

    .PARAMETER Aggressive
        Uses higher concurrency and smaller chunks for incident response investigations.

    .PARAMETER TimeoutSeconds
        Maximum total runtime for chunk retrieval.

    .PARAMETER MaxRetries
        Maximum retry attempts for each page request.

    .PARAMETER RetryDelaySeconds
        Base delay used for retry backoff.

    .PARAMETER RequestTimeoutSeconds
        Timeout for each individual HTTP request.

    .PARAMETER OutputPath
        Directory used for temporary chunk files.

    .PARAMETER KeepTempFiles
        Keeps temporary chunk files after the command completes.

    .PARAMETER ExportPath
        Writes retrieved activity events to a JSON file.

    .PARAMETER ExportFormat
        Export file format. Json preserves the existing array output; Ndjson
        streams one event per line and is preferred for large incident response exports.

    .PARAMETER PassThru
        Returns activity events after writing ExportPath.

    .PARAMETER Compress
        Writes compressed JSON when ExportPath is used.

    .PARAMETER AllowPartial
        Returns completed chunks instead of terminating when one or more chunks fail.

    .PARAMETER Force
        Bypasses cache-backed metadata requests.

    .EXAMPLE
        Get-XdrCloudAppsActivityTimeline -LastNDays 1

        Retrieves the last day of Cloud Apps activity.

    .EXAMPLE
        Get-XdrCloudAppsActivityTimeline -LastNDays 7 -Aggressive -ExportPath .\cloud-apps-activity.json

        Retrieves seven days of activity using aggressive incident response settings and exports to JSON.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Cloud Apps is the product name')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '', Justification = 'Parallel runspace values are passed explicitly or through using scope')]
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
        [int]$ThrottleLimit = 8,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 168)]
        [int]$ChunkHours = 6,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$Aggressive,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(60, 86400)]
        [int]$TimeoutSeconds = 3600,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [ValidateRange(1, 20)]
        [int]$MaxRetries = 5,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [ValidateRange(1, 300)]
        [int]$RetryDelaySeconds = 5,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(10, 300)]
        [int]$RequestTimeoutSeconds = 60,

        [Parameter(ParameterSetName = 'Default')]
        [string]$OutputPath,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$KeepTempFiles,

        [Parameter(ParameterSetName = 'Default')]
        [string]$ExportPath,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet('Json', 'Ndjson')]
        [string]$ExportFormat = 'Json',

        [Parameter(ParameterSetName = 'Default')]
        [switch]$PassThru,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$Compress,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$AllowPartial,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
        $regularApiPath = '/mcas/cas/api/v1/activities/'
        $archivedApiPath = '/mcas/cas/api/v1/archived_activities/'
        $maxDaysTotal = 180
        $regularBoundaryUtc = [datetime]::UtcNow.AddDays(-30)
        $xdrBaseUrl = 'https://security.microsoft.com'
    }

    process {
        if ($Metadata -or $ArchivedMetadata) {
            $apiType = if ($ArchivedMetadata) { 'archived_activities' } else { 'activities' }
            $activityMetadata = Invoke-XdrCloudAppsRequest -Path "/mcas/cas/api/v1/$apiType/metadata/?allowDeprecationFields=true" -TypeName 'XdrCloudAppsActivityMetadata' -CacheKey "XdrCloudApps-$apiType-Metadata" -TTLMinutes 15 -Raw:$Raw -Force:$Force
            if ($Raw) {
                return $activityMetadata
            }

            return $activityMetadata.filters | ForEach-Object {
                [PSCustomObject]@{
                    PSTypeName = 'XdrCloudAppsActivityMetadata'
                    Name       = $_.name
                    Operators  = ($_.operators.id -join ', ')
                    InputType  = $_.inputType.type
                    Deprecated = $_.deprecated
                }
            }
        }

        if ($PSBoundParameters.ContainsKey('LastNDays')) {
            $ToDate = [datetime]::UtcNow
            $FromDate = $ToDate.AddDays(-$LastNDays)
        }

        if ($PSBoundParameters.ContainsKey('FromDate')) { $FromDate = $FromDate.ToUniversalTime() }
        if ($PSBoundParameters.ContainsKey('ToDate')) { $ToDate = $ToDate.ToUniversalTime() }

        if ($FromDate -and -not $ToDate) {
            $ToDate = [datetime]::UtcNow
        }
        elseif ($ToDate -and -not $FromDate) {
            throw 'FromDate is required when ToDate is specified.'
        }

        if ($FromDate -and $ToDate) {
            if ($FromDate -ge $ToDate) { throw 'FromDate must be before ToDate.' }
            if ($FromDate -gt [datetime]::UtcNow) { throw 'FromDate cannot be in the future.' }
            if ($ToDate -gt [datetime]::UtcNow) {
                Write-Warning 'ToDate is in the future; adjusting to the current UTC time.'
                $ToDate = [datetime]::UtcNow
            }
            $rangeDays = ($ToDate - $FromDate).TotalDays
            if ($rangeDays -gt $maxDaysTotal) {
                throw "Date range cannot exceed $maxDaysTotal days. Requested range: $([math]::Round($rangeDays, 1)) days."
            }
        }

        if ($Aggressive) {
            if (-not $PSBoundParameters.ContainsKey('ThrottleLimit')) { $ThrottleLimit = 32 }
            if (-not $PSBoundParameters.ContainsKey('ChunkHours')) { $ChunkHours = 2 }
            if (-not $PSBoundParameters.ContainsKey('MaxRetries')) { $MaxRetries = 8 }
            if (-not $PSBoundParameters.ContainsKey('RequestTimeoutSeconds')) { $RequestTimeoutSeconds = 45 }
        }

        $newDateFilter = {
            param([datetime]$Start, [datetime]$End, [bool]$UseArchived, [hashtable]$BaseFilters)

            $epochStart = [long]($Start.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds
            $epochEnd = [long]($End.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds
            $queryFilters = $BaseFilters.Clone()
            if ($UseArchived) {
                $queryFilters.date = @{ range = @( @{ start = $epochStart; end = $epochEnd } ) }
            }
            else {
                $queryFilters.date = @{ gte = $epochStart; lte = $epochEnd }
            }
            $queryFilters
        }

        if ($CountOnly) {
            if (-not $FromDate) {
                $body = @{ filters = $Filters }
                return Invoke-XdrCloudAppsRequest -Path "${regularApiPath}count/" -Method Post -Body $body -Raw -Force:$Force
            }

            $countResults = @()
            $segments = [System.Collections.Generic.List[hashtable]]::new()
            if ($FromDate -lt $regularBoundaryUtc) {
                $archiveEnd = if ($ToDate -lt $regularBoundaryUtc) { $ToDate } else { $regularBoundaryUtc }
                $segments.Add(@{ FromDate = $FromDate; ToDate = $archiveEnd; Archived = $true })
            }
            if ($ToDate -gt $regularBoundaryUtc) {
                $recentStart = if ($FromDate -gt $regularBoundaryUtc) { $FromDate } else { $regularBoundaryUtc }
                $segments.Add(@{ FromDate = $recentStart; ToDate = $ToDate; Archived = $false })
            }

            foreach ($segment in $segments) {
                $segmentFilters = & $newDateFilter $segment.FromDate $segment.ToDate $segment.Archived $Filters
                $path = if ($segment.Archived) { "${archivedApiPath}count/" } else { "${regularApiPath}count/" }
                $countResults += Invoke-XdrCloudAppsRequest -Path $path -Method Post -Body @{ filters = $segmentFilters } -Raw -Force:$Force
            }
            return $countResults
        }

        if (-not $FromDate) {
            $body = @{
                distributedId     = [guid]::NewGuid().ToString()
                filters           = $Filters
                limit             = $PageSize
                performAsyncTotal = $true
                skip              = 0
                sortDirection     = 'desc'
                sortField         = 'date'
            }
            $result = Invoke-XdrCloudAppsRequest -Path $regularApiPath -Method Post -Body $body -TypeName 'XdrCloudAppsActivity' -Raw:$Raw -Force:$Force
            if ($Raw) { return $result }
            return $result | Add-XdrCloudAppsTypeName -TypeName 'XdrCloudAppsActivity'
        }

        $baseTempPath = if ($OutputPath) { $OutputPath } else { Join-Path ([System.IO.Path]::GetTempPath()) 'XdrCloudAppsTimeline' }
        if (-not (Test-Path -LiteralPath $baseTempPath)) {
            New-Item -Path $baseTempPath -ItemType Directory -Force | Out-Null
        }
        $runTempPath = Join-Path $baseTempPath ([guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -Path $runTempPath -ItemType Directory -Force | Out-Null

        $dateChunks = [System.Collections.Generic.List[hashtable]]::new()
        $addChunks = {
            param([datetime]$SegmentStart, [datetime]$SegmentEnd, [bool]$Archived)
            $totalHours = ($SegmentEnd - $SegmentStart).TotalHours
            $effectiveChunkHours = $ChunkHours
            if (-not $PSBoundParameters.ContainsKey('ChunkHours') -and $totalHours -le 24) {
                $effectiveChunkHours = [math]::Max(1, [math]::Ceiling($totalHours / 8))
            }
            $cursor = $SegmentStart
            while ($cursor -lt $SegmentEnd) {
                $chunkEnd = $cursor.AddHours($effectiveChunkHours)
                if ($chunkEnd -gt $SegmentEnd) { $chunkEnd = $SegmentEnd }
                $dateChunks.Add(@{
                    FromDate = $cursor
                    ToDate   = $chunkEnd
                    Archived = $Archived
                    Index    = $dateChunks.Count
                })
                $cursor = $chunkEnd
            }
        }

        if ($FromDate -lt $regularBoundaryUtc) {
            $archiveEnd = if ($ToDate -lt $regularBoundaryUtc) { $ToDate } else { $regularBoundaryUtc }
            & $addChunks $FromDate $archiveEnd $true
        }
        if ($ToDate -gt $regularBoundaryUtc) {
            $recentStart = if ($FromDate -gt $regularBoundaryUtc) { $FromDate } else { $regularBoundaryUtc }
            & $addChunks $recentStart $ToDate $false
        }

        Write-Information "Split activity range into $($dateChunks.Count) chunk(s); throttle=$ThrottleLimit; aggressive=$($Aggressive.IsPresent)" -InformationAction Continue

        $cookieData = @()
        foreach ($cookie in $script:session.Cookies.GetCookies([Uri]$xdrBaseUrl)) {
            $cookieData += @{ Name = $cookie.Name; Value = $cookie.Value; Domain = $cookie.Domain; Path = $cookie.Path }
        }
        $headersData = @{}
        foreach ($key in $script:headers.Keys) { $headersData[$key] = $script:headers[$key] }

        $baseParams = @{
            RegularApiPath        = "https://security.microsoft.com/apiproxy$regularApiPath"
            ArchivedApiPath       = "https://security.microsoft.com/apiproxy$archivedApiPath"
            Filters               = $Filters
            PageSize              = $PageSize
            MaxRetries            = $MaxRetries
            RetryDelaySeconds     = $RetryDelaySeconds
            RequestTimeoutSeconds = $RequestTimeoutSeconds
            TempPath              = $runTempPath
        }

        $chunkScript = {
            param($Chunk, $Params, $CookieInfo, $HeaderInfo)

            $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            foreach ($c in $CookieInfo) {
                $webSession.Cookies.Add([System.Net.Cookie]::new($c.Name, $c.Value, $c.Path, $c.Domain))
            }

            $chunkStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $fileName = 'chunk_{0:D4}_{1:yyyyMMdd_HHmmss}_{2:yyyyMMdd_HHmmss}.json' -f $Chunk.Index, $Chunk.FromDate, $Chunk.ToDate
            $filePath = Join-Path $Params.TempPath $fileName
            $progressPath = Join-Path $Params.TempPath ('progress_{0:D4}.txt' -f $Chunk.Index)
            $writer = $null
            $eventCount = 0
            $pagesRetrieved = 0
            $retryCount = 0
            $retryErrors = [System.Collections.Generic.List[string]]::new()

            try {
                $uri = if ($Chunk.Archived) { $Params.ArchivedApiPath } else { $Params.RegularApiPath }
                $epochStart = [long]($Chunk.FromDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds
                $epochEnd = [long]($Chunk.ToDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds
                $filters = $Params.Filters.Clone()
                if ($Chunk.Archived) {
                    $filters.date = @{ range = @( @{ start = $epochStart; end = $epochEnd } ) }
                }
                else {
                    $filters.date = @{ gte = $epochStart; lte = $epochEnd }
                }

                $writer = [System.IO.StreamWriter]::new($filePath, $false, [System.Text.Encoding]::UTF8)
                $writer.Write('{"ChunkIndex":' + $Chunk.Index + ',"FromDate":"' + $Chunk.FromDate.ToString('o') + '","ToDate":"' + $Chunk.ToDate.ToString('o') + '","Archived":' + $Chunk.Archived.ToString().ToLowerInvariant() + ',"Events":[')
                $first = $true
                $skip = 0
                $hasMore = $true
                while ($hasMore -and $pagesRetrieved -lt 10000) {
                    $body = @{
                        distributedId     = [guid]::NewGuid().ToString()
                        filters           = $filters
                        limit             = $Params.PageSize
                        performAsyncTotal = $true
                        skip              = $skip
                        sortDirection     = 'desc'
                        sortField         = 'date'
                    } | ConvertTo-Json -Depth 20 -Compress

                    $attempt = 0
                    $response = $null
                    while ($attempt -lt $Params.MaxRetries) {
                        $attempt++
                        try {
                            $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -WebSession $webSession -Headers $HeaderInfo -TimeoutSec $Params.RequestTimeoutSeconds -ErrorAction Stop
                            break
                        }
                        catch {
                            $statusCode = $null
                            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
                            if ($attempt -ge $Params.MaxRetries) { throw }
                            $retryCount++
                            $delay = [math]::Min(300, [int]($Params.RetryDelaySeconds * [math]::Pow(2, $attempt - 1)))
                            if ($statusCode -eq 429 -or $statusCode -eq 403) { $delay = [math]::Max($delay, 30) }
                            $delay += Get-Random -Minimum 0 -Maximum 5
                            $retryErrors.Add("Page $pagesRetrieved attempt $attempt failed: $($_.Exception.Message)")
                            Start-Sleep -Seconds $delay
                        }
                    }

                    if ($response -is [string] -and -not [string]::IsNullOrWhiteSpace($response)) {
                        if ((Get-Command ConvertFrom-Json -ErrorAction Stop).Parameters.ContainsKey('AsHashtable')) {
                            $response = $response | ConvertFrom-Json -AsHashtable -ErrorAction Stop
                        }
                        else {
                            Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
                            $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
                            $serializer.MaxJsonLength = [int]::MaxValue
                            $response = $serializer.DeserializeObject($response)
                        }
                    }
                    $responseData = if ($response -is [System.Collections.IDictionary]) { $response['data'] } else { $response.data }
                    foreach ($item in @($responseData)) {
                        if (-not $first) { $writer.Write(',') }
                        $writer.Write(($item | ConvertTo-Json -Depth 20 -Compress))
                        $first = $false
                        $eventCount++
                    }
                    $pagesRetrieved++
                    Set-Content -Path $progressPath -Value $pagesRetrieved -Encoding UTF8
                    $hasMoreValue = if ($response -is [System.Collections.IDictionary]) { $response['hasNext'] } else { $response.hasNext }
                    $hasMore = $hasMoreValue -eq $true
                    $skip += $Params.PageSize
                }
                $writer.Write('],"EventCount":' + $eventCount + '}')
                $writer.Close()
                $writer.Dispose()
                $writer = $null
                $chunkStopwatch.Stop()

                [PSCustomObject]@{
                    ChunkIndex     = $Chunk.Index
                    FromDate       = $Chunk.FromDate
                    ToDate         = $Chunk.ToDate
                    Archived       = $Chunk.Archived
                    FilePath       = $filePath
                    EventCount     = $eventCount
                    PagesRetrieved = $pagesRetrieved
                    RetryCount     = $retryCount
                    RetryErrors    = $retryErrors.ToArray()
                    FileSizeKB     = [math]::Round((Get-Item $filePath).Length / 1KB, 2)
                    ElapsedSeconds = [math]::Round($chunkStopwatch.Elapsed.TotalSeconds, 2)
                    Success        = $true
                }
            }
            catch {
                if ($writer) {
                    try {
                        $writer.Dispose()
                    }
                    catch {
                        Write-Verbose "Failed to dispose Cloud Apps activity chunk writer: $($_.Exception.Message)"
                    }
                }
                $chunkStopwatch.Stop()
                [PSCustomObject]@{
                    ChunkIndex     = $Chunk.Index
                    FromDate       = $Chunk.FromDate
                    ToDate         = $Chunk.ToDate
                    Archived       = $Chunk.Archived
                    FilePath       = $filePath
                    EventCount     = $eventCount
                    PagesRetrieved = $pagesRetrieved
                    RetryCount     = $retryCount
                    RetryErrors    = $retryErrors.ToArray()
                    ElapsedSeconds = [math]::Round($chunkStopwatch.Elapsed.TotalSeconds, 2)
                    Success        = $false
                    Error          = $_.Exception.Message
                }
            }
            finally {
                Remove-Item -Path $progressPath -Force -ErrorAction SilentlyContinue
            }
        }

        $operationStart = [System.Diagnostics.Stopwatch]::StartNew()
        $results = @()
        try {
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $parallelJob = Start-ThreadJob -ScriptBlock {
                    param($Chunks, $Throttle, $Params, $CookieInfo, $HeaderInfo, $ScriptText)
                    $Chunks | ForEach-Object -Parallel {
                        & ([scriptblock]::Create($using:ScriptText)) -Chunk $_ -Params $using:Params -CookieInfo $using:CookieInfo -HeaderInfo $using:HeaderInfo
                    } -ThrottleLimit $Throttle
                } -ArgumentList $dateChunks.ToArray(), $ThrottleLimit, $baseParams, $cookieData, $headersData, $chunkScript.ToString()

                $lastProgress = [System.Diagnostics.Stopwatch]::StartNew()
                $lastCompleted = 0
                while ($parallelJob.State -in @('NotStarted', 'Running')) {
                    if ($operationStart.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
                        Stop-Job -Job $parallelJob -ErrorAction SilentlyContinue
                        throw "Activity timeline timed out after $TimeoutSeconds seconds."
                    }
                    $completedFiles = @(Get-ChildItem -Path $runTempPath -Filter 'chunk_*.json' -ErrorAction SilentlyContinue).Count
                    $recentProgress = Get-ChildItem -Path $runTempPath -Filter 'progress_*.txt' -ErrorAction SilentlyContinue |
                        Where-Object { ([datetime]::UtcNow - $_.LastWriteTimeUtc).TotalSeconds -lt 60 }
                    if ($completedFiles -gt $lastCompleted -or $recentProgress) {
                        $lastCompleted = $completedFiles
                        $lastProgress.Restart()
                    }
                    elseif ($lastProgress.Elapsed.TotalSeconds -gt 180 -and $completedFiles -lt $dateChunks.Count) {
                        Stop-Job -Job $parallelJob -ErrorAction SilentlyContinue
                        throw 'Activity timeline stalled with no chunk or page progress for 180 seconds.'
                    }
                    $percent = [math]::Min(99, [math]::Round(($completedFiles / [math]::Max(1, $dateChunks.Count)) * 100))
                    Write-Progress -Activity 'Retrieving Cloud Apps Activity Timeline' -Status "Downloaded $completedFiles of $($dateChunks.Count) chunks" -PercentComplete $percent
                    Start-Sleep -Milliseconds 300
                }
                $results = Receive-Job -Job $parallelJob -Wait
                Remove-Job -Job $parallelJob -Force
            }
            else {
                foreach ($chunk in $dateChunks) {
                    $results += & $chunkScript -Chunk $chunk -Params $baseParams -CookieInfo $cookieData -HeaderInfo $headersData
                }
            }

            Write-Progress -Activity 'Retrieving Cloud Apps Activity Timeline' -Completed
            $failures = @($results | Where-Object { -not $_.Success })
            if ($failures.Count -gt 0 -and -not $AllowPartial) {
                $failureDetails = $failures | Sort-Object ChunkIndex | ForEach-Object {
                    "chunk $($_.ChunkIndex): $($_.Error)"
                }
                throw "Failed to retrieve Cloud Apps activity chunks: $($failureDetails -join '; '). Re-run with -AllowPartial to return completed chunks."
            }
            elseif ($failures.Count -gt 0) {
                $failureDetails = $failures | Sort-Object ChunkIndex | ForEach-Object {
                    "chunk $($_.ChunkIndex): $($_.Error)"
                }
                Write-Warning "Returning partial timeline data; failed chunks: $($failureDetails -join '; ')"
            }

            $fromUtc = $FromDate.ToUniversalTime()
            $toUtc = $ToDate.ToUniversalTime()
            $jsonFiles = @(
                $results |
                    Where-Object { $_.Success -and $_.FilePath -and (Test-Path -LiteralPath $_.FilePath) } |
                    ForEach-Object { Get-Item -LiteralPath $_.FilePath } |
                    Sort-Object Name
            )

            if ($ExportPath -and $ExportFormat -eq 'Ndjson' -and -not $PassThru -and -not $IncludeThreatScores) {
                $parent = Split-Path -Path $ExportPath -Parent
                if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }

                $seenExportKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                $exportSha256 = [System.Security.Cryptography.SHA256]::Create()
                $exportCount = 0
                $writer = [System.IO.StreamWriter]::new($ExportPath, $false, [System.Text.Encoding]::UTF8)
                try {
                    foreach ($file in @($jsonFiles | Sort-Object Name -Descending)) {
                        $chunkData = Read-XdrCloudAppsActivityChunkFile -File $file -AllowPartial:$AllowPartial
                        if ($null -eq $chunkData) { continue }
                        foreach ($activity in @(Get-XdrCloudAppsObjectValue -InputObject $chunkData -Name 'Events')) {
                            $eventUtc = Get-XdrCloudAppsActivityEventTime -Activity $activity

                            if ($null -eq $eventUtc -or $eventUtc -lt $fromUtc -or $eventUtc -ge $toUtc) {
                                continue
                            }

                            $stableKey = Get-XdrCloudAppsActivityStableKey -Activity $activity -Sha256 $exportSha256

                            if ($seenExportKeys.Add($stableKey)) {
                                $writer.WriteLine(($activity | ConvertTo-Json -Depth 20 -Compress))
                                $exportCount++
                            }
                        }
                    }
                }
                finally {
                    $writer.Dispose()
                    $exportSha256.Dispose()
                }

                $operationStart.Stop()
                return [PSCustomObject]@{
                    PSTypeName       = 'XdrCloudAppsActivityTimelineExport'
                    ExportPath       = $ExportPath
                    ExportFormat     = 'Ndjson'
                    TotalEvents      = $exportCount
                    TotalChunks      = $dateChunks.Count
                    FailedChunks     = @($failures).Count
                    WallClockSeconds = [math]::Round($operationStart.Elapsed.TotalSeconds, 2)
                    FromDate         = $FromDate
                    ToDate           = $ToDate
                }
            }

            $eventRows = [System.Collections.Generic.List[object]]::new()
            $seenKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            foreach ($file in $jsonFiles) {
                $chunkData = Read-XdrCloudAppsActivityChunkFile -File $file -AllowPartial:$AllowPartial
                if ($null -eq $chunkData) { continue }
                foreach ($activity in @(Get-XdrCloudAppsObjectValue -InputObject $chunkData -Name 'Events')) {
                    $eventUtc = Get-XdrCloudAppsActivityEventTime -Activity $activity

                    if ($null -eq $eventUtc -or $eventUtc -lt $fromUtc -or $eventUtc -ge $toUtc) {
                        continue
                    }

                    $stableKey = Get-XdrCloudAppsActivityStableKey -Activity $activity -Sha256 $sha256

                    if ($seenKeys.Add($stableKey)) {
                        $activity.PSObject.TypeNames.Insert(0, 'XdrCloudAppsActivity')
                        $eventRows.Add([PSCustomObject]@{
                            Event        = $activity
                            TimestampKey = $eventUtc.ToString('o')
                            StableKey    = $stableKey
                        })
                    }
                }
            }
            $sha256.Dispose()

            $sortedEvents = $eventRows |
                Sort-Object -Property @{ Expression = 'TimestampKey'; Descending = $true }, @{ Expression = 'StableKey'; Descending = $false } |
                ForEach-Object { $_.Event }

            if ($IncludeThreatScores -and $sortedEvents.Count -gt 0) {
                if ($FromDate -lt $regularBoundaryUtc) {
                    Write-Warning 'Threat scores are only requested for recent Cloud Apps activities; archived events will not have scores.'
                }
                $recordIds = @($sortedEvents | ForEach-Object { Get-XdrCloudAppsObjectValue -InputObject $_ -Name '_id' } | Where-Object { $_ })
                for ($i = 0; $i -lt $recordIds.Count; $i += 500) {
                    $batchEnd = [math]::Min($i + 499, $recordIds.Count - 1)
                    $batchIds = $recordIds[$i..$batchEnd]
                    try {
                        $scores = Get-XdrCloudAppsActivityThreatScore -RecordIds $batchIds -StartDate $FromDate -EndDate $ToDate
                        $scoreMap = @{}
                        foreach ($score in @($scores.data)) {
                            if ($score.recordId) { $scoreMap[$score.recordId] = $score }
                        }
                        foreach ($activity in $sortedEvents) {
                            $activityId = Get-XdrCloudAppsObjectValue -InputObject $activity -Name '_id'
                            if ($activityId -and $scoreMap.ContainsKey($activityId)) {
                                if ($activity -is [System.Collections.IDictionary]) {
                                    $activity['ThreatScore'] = $scoreMap[$activityId]
                                }
                                else {
                                    $activity | Add-Member -NotePropertyName ThreatScore -NotePropertyValue $scoreMap[$activityId] -Force
                                }
                            }
                        }
                    }
                    catch {
                        Write-Warning "Failed to enrich Cloud Apps activity threat scores: $($_.Exception.Message)"
                    }
                }
            }

            $operationStart.Stop()
            $successCount = @($results | Where-Object { $_.Success }).Count
            $eventCount = @($sortedEvents).Count
            Write-Information "Retrieved $eventCount Cloud Apps activities from $successCount chunk(s) in $([math]::Round($operationStart.Elapsed.TotalSeconds, 1)) seconds." -InformationAction Continue

            if ($ExportPath) {
                $parent = Split-Path -Path $ExportPath -Parent
                if ($parent -and -not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
                if ($ExportFormat -eq 'Ndjson') {
                    $writer = [System.IO.StreamWriter]::new($ExportPath, $false, [System.Text.Encoding]::UTF8)
                    try {
                        foreach ($activity in $sortedEvents) {
                            $writer.WriteLine(($activity | ConvertTo-Json -Depth 20 -Compress))
                        }
                    }
                    finally {
                        $writer.Dispose()
                    }
                }
                elseif ($Compress) {
                    $sortedEvents | ConvertTo-Json -Depth 20 -Compress | Set-Content -Path $ExportPath -Encoding UTF8
                }
                else {
                    $sortedEvents | ConvertTo-Json -Depth 20 | Set-Content -Path $ExportPath -Encoding UTF8
                }
                if (-not $PassThru) {
                    return [PSCustomObject]@{
                        PSTypeName       = 'XdrCloudAppsActivityTimelineExport'
                        ExportPath       = $ExportPath
                        ExportFormat     = $ExportFormat
                        TotalEvents      = $eventCount
                        TotalChunks      = $dateChunks.Count
                        FailedChunks     = @($failures).Count
                        WallClockSeconds = [math]::Round($operationStart.Elapsed.TotalSeconds, 2)
                        FromDate         = $FromDate
                        ToDate           = $ToDate
                    }
                }
            }

            return $sortedEvents
        }
        finally {
            Get-ChildItem -Path $runTempPath -Filter 'progress_*.txt' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            if (-not $KeepTempFiles -and (Test-Path $runTempPath)) {
                Remove-Item -Path $runTempPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            elseif ($KeepTempFiles) {
                Write-Information "Temporary Cloud Apps timeline files preserved in: $runTempPath" -InformationAction Continue
            }
        }
    }
}
