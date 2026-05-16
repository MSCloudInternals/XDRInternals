function Get-XdrStringHash {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-XdrFileSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Get-XdrTimelineObjectValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject[$Name]
    }

    if ($InputObject.PSObject.Properties[$Name]) {
        return $InputObject.$Name
    }

    return $null
}

function Set-XdrTimelineObjectValue {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Updates an in-memory object only')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($InputObject -is [System.Collections.IDictionary]) {
        $InputObject[$Name] = $Value
        return
    }

    if ($InputObject.PSObject.Properties[$Name]) {
        $InputObject.$Name = $Value
        return
    }

    $InputObject | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}

function Write-XdrAtomicTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Content
    )

    $parentPath = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -LiteralPath $parentPath)) {
        New-Item -Path $parentPath -ItemType Directory -Force | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($parentPath)) {
        $parentPath = (Get-Location).Path
    }

    $tempPath = Join-Path $parentPath ('.' + [System.IO.Path]::GetFileName($Path) + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    [System.IO.File]::WriteAllText($tempPath, $Content, [System.Text.Encoding]::UTF8)
    Move-Item -LiteralPath $tempPath -Destination $Path -Force
}

function ConvertTo-XdrSanitizedRequestContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$RequestContext
    )

    $cookieNames = @(
        foreach ($cookie in @($RequestContext.CookieData)) {
            if ($cookie.PSObject.Properties['Name']) { [string]$cookie.Name }
        }
    ) | Sort-Object -Unique

    $headerNames = @(
        foreach ($key in @($RequestContext.HeadersData.Keys)) {
            [string]$key
        }
    ) | Sort-Object -Unique

    [PSCustomObject]@{
        BaseUrlHash  = Get-XdrStringHash -Value ([string]$RequestContext.BaseUrl)
        CookieNames  = @($cookieNames)
        HeaderNames  = @($headerNames)
        CookieCount  = @($RequestContext.CookieData).Count
        HeaderCount  = @($headerNames).Count
    }
}

function Get-XdrHttpFailureClass {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$ErrorRecord,

        [Parameter()]
        [AllowNull()]
        [Nullable[int]]$StatusCode,

        [Parameter()]
        [AllowNull()]
        [string]$Message
    )

    if ($ErrorRecord) {
        if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Response) {
            try { $StatusCode = [int]$ErrorRecord.Exception.Response.StatusCode } catch { Write-Verbose "Could not read HTTP status from failure response: $($_.Exception.Message)" }
        }
        if ([string]::IsNullOrWhiteSpace($Message)) {
            $Message = $ErrorRecord.ToString()
        }
    }

    $text = [string]$Message
    if ($text -match '(?i)(interactive sign.?in|sign in to your account|ConvergedSignIn|login\.microsoftonline\.com)') {
        return 'AuthExpired'
    }

    if ($StatusCode -in @(401, 419, 440)) {
        return 'AuthExpired'
    }

    if ($StatusCode -eq 403) {
        if ($text -match '(?i)(xsrf|csrf|session|token|expired|sign.?in|login)') {
            return 'AuthExpired'
        }
        return 'Authz'
    }

    if ($StatusCode -eq 429) {
        return 'RateLimited'
    }

    if ($StatusCode -ge 500 -and $StatusCode -lt 600) {
        return 'Transient'
    }

    if ($text -match '(?i)(exceeded MaxPagesPerChunk|duplicate continuation URI|no-progress|DensePageThreshold|EarlyDensityThreshold)') {
        return 'Fatal'
    }

    if ($text -match '(?i)(timeout|timed out|operation has timed out|task was canceled)') {
        return 'Timeout'
    }

    if ($text -match '(?i)(disk|space|quota|path too long|access.*path)') {
        return 'Disk'
    }

    if ($null -eq $StatusCode -and -not [string]::IsNullOrWhiteSpace($text)) {
        return 'Transient'
    }

    return 'Fatal'
}

function New-XdrEndpointTimelineManifestState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory manifest object only')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Compatibility,

        [Parameter(Mandatory)]
        [object[]]$Chunks,

        [Parameter()]
        [object]$RequestContextSummary
    )

    [ordered]@{
        SchemaVersion         = 3
        PlannerVersion        = 'EndpointTimelineAdaptiveManifestV3'
        Provider              = 'EndpointDeviceTimeline'
        GeneratedAtUtc        = (Get-Date).ToUniversalTime().ToString('o')
        LastUpdatedUtc        = (Get-Date).ToUniversalTime().ToString('o')
        Compatibility         = $Compatibility
        RequestContextSummary = $RequestContextSummary
        Partial               = $false
        Jobs                  = @(
            foreach ($chunk in @($Chunks)) {
                New-XdrEndpointTimelineManifestJob -Chunk $chunk
            }
        )
        Summary               = [ordered]@{}
    }
}

function New-XdrEndpointTimelineManifestJob {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory manifest job object only')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Chunk,

        [Parameter()]
        [AllowNull()]
        [string]$ParentJobId,

        [Parameter()]
        [int]$Generation = 0,

        [Parameter()]
        [string]$Status = 'Pending'
    )

    $chunkIndex = [int](Get-XdrTimelineObjectValue -InputObject $Chunk -Name 'Index')
    $chunkOwnerFrom = ([datetime](Get-XdrTimelineObjectValue -InputObject $Chunk -Name 'OwnerFromDate')).ToUniversalTime()
    $chunkOwnerTo = ([datetime](Get-XdrTimelineObjectValue -InputObject $Chunk -Name 'OwnerToDate')).ToUniversalTime()
    $chunkFrom = ([datetime](Get-XdrTimelineObjectValue -InputObject $Chunk -Name 'FromDate')).ToUniversalTime()
    $chunkTo = ([datetime](Get-XdrTimelineObjectValue -InputObject $Chunk -Name 'ToDate')).ToUniversalTime()
    $chunkHours = Get-XdrTimelineObjectValue -InputObject $Chunk -Name 'ChunkHours'
    $chunkMinutes = Get-XdrTimelineObjectValue -InputObject $Chunk -Name 'ChunkMinutes'
    $chunkStrategy = Get-XdrTimelineObjectValue -InputObject $Chunk -Name 'Strategy'
    [ordered]@{
        JobId                 = "job-$chunkIndex"
        ParentJobId           = $ParentJobId
        Generation            = $Generation
        ChunkIndex            = $chunkIndex
        OwnerFrom             = $chunkOwnerFrom.ToString('o')
        OwnerTo               = $chunkOwnerTo.ToString('o')
        RequestFrom           = $chunkFrom.ToString('o')
        RequestTo             = $chunkTo.ToString('o')
        ChunkHours            = if ($null -ne $chunkHours) { [double]$chunkHours } else { [math]::Round(($chunkOwnerTo - $chunkOwnerFrom).TotalHours, 4) }
        ChunkMinutes          = if ($null -ne $chunkMinutes) { [int]$chunkMinutes } else { [int][math]::Ceiling(($chunkOwnerTo - $chunkOwnerFrom).TotalMinutes) }
        Strategy              = if ($chunkStrategy) { [string]$chunkStrategy } else { 'Adaptive' }
        Status                = $Status
        SplitReason           = $null
        SplitStrategy         = $null
        SplitMetadata         = [ordered]@{}
        ChildJobIds           = @()
        Attempts              = 0
        FilePath              = $null
        FileSha256            = $null
        EventCount            = 0
        UniqueKeyCount        = 0
        KeySetHash            = $null
        FirstTimestamp        = $null
        LastTimestamp         = $null
        MissingTimestampCount = 0
        FailureClass          = $null
        Error                 = $null
        PagesRetrieved        = $null
    }
}

function Get-XdrEndpointTimelineManifestJob {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object]$Manifest,

        [Parameter()]
        [switch]$LeafOnly,

        [Parameter()]
        [switch]$SucceededOnly
    )

    $jobs = if ($Manifest -is [System.Collections.IDictionary]) {
        @($Manifest['Jobs'])
    }
    elseif ($Manifest.PSObject.Properties['Jobs']) {
        @($Manifest.Jobs)
    }
    else {
        @()
    }

    foreach ($job in $jobs) {
        $status = [string](Get-XdrTimelineObjectValue -InputObject $job -Name 'Status')
        $childJobIds = @(Get-XdrTimelineObjectValue -InputObject $job -Name 'ChildJobIds' | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($LeafOnly -and ($status -eq 'Superseded' -or $childJobIds.Count -gt 0)) { continue }
        if ($SucceededOnly -and $status -ne 'Succeeded') { continue }
        $job
    }
}

function ConvertTo-XdrEndpointTimelineChunk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Job
    )

    [PSCustomObject]@{
        Index         = [int](Get-XdrTimelineObjectValue -InputObject $Job -Name 'ChunkIndex')
        FromDate      = ([datetime](Get-XdrTimelineObjectValue -InputObject $Job -Name 'RequestFrom')).ToUniversalTime()
        ToDate        = ([datetime](Get-XdrTimelineObjectValue -InputObject $Job -Name 'RequestTo')).ToUniversalTime()
        OwnerFromDate = ([datetime](Get-XdrTimelineObjectValue -InputObject $Job -Name 'OwnerFrom')).ToUniversalTime()
        OwnerToDate   = ([datetime](Get-XdrTimelineObjectValue -InputObject $Job -Name 'OwnerTo')).ToUniversalTime()
        ChunkHours    = [double](Get-XdrTimelineObjectValue -InputObject $Job -Name 'ChunkHours')
        ChunkMinutes  = [int](Get-XdrTimelineObjectValue -InputObject $Job -Name 'ChunkMinutes')
        Strategy      = [string](Get-XdrTimelineObjectValue -InputObject $Job -Name 'Strategy')
    }
}

function Test-XdrEndpointTimelineManifestJobComplete {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [object]$Job
    )

    $jobStatus = Get-XdrTimelineObjectValue -InputObject $Job -Name 'Status'
    $jobFilePath = Get-XdrTimelineObjectValue -InputObject $Job -Name 'FilePath'
    $jobFileSha256 = Get-XdrTimelineObjectValue -InputObject $Job -Name 'FileSha256'
    if ($jobStatus -ne 'Succeeded' -or -not $jobFilePath -or -not $jobFileSha256 -or -not (Test-Path -LiteralPath $jobFilePath)) {
        return $false
    }

    return ((Get-XdrFileSha256 -Path ([string]$jobFilePath)) -eq [string]$jobFileSha256)
}

function Read-XdrTimelineManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 32 -ErrorAction Stop
}

function Test-XdrTimelineManifestCompatibility {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Manifest,

        [Parameter(Mandatory)]
        [hashtable]$Compatibility
    )

    if ($null -eq $Manifest -or -not $Manifest.PSObject.Properties['Compatibility']) {
        return $false
    }

    $existing = $Manifest.Compatibility
    foreach ($key in $Compatibility.Keys) {
        if (-not $existing.PSObject.Properties[$key]) {
            return $false
        }

        $left = $existing.$key | ConvertTo-Json -Depth 20 -Compress
        $right = $Compatibility[$key] | ConvertTo-Json -Depth 20 -Compress
        if ($left -ne $right) {
            return $false
        }
    }

    return $true
}

function Write-XdrTimelineManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Manifest
    )

    $Manifest['LastUpdatedUtc'] = (Get-Date).ToUniversalTime().ToString('o')
    Write-XdrAtomicTextFile -Path $Path -Content ($Manifest | ConvertTo-Json -Depth 32)
}

function Update-XdrEndpointTimelineManifestJob {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Updates an in-memory manifest object only')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Manifest,

        [Parameter(Mandatory)]
        [object]$Result
    )

    $jobs = @(Get-XdrEndpointTimelineManifestJob -Manifest $Manifest)
    $job = $jobs | Where-Object { [int](Get-XdrTimelineObjectValue -InputObject $_ -Name 'ChunkIndex') -eq [int]$Result.ChunkIndex } | Select-Object -First 1
    if (-not $job) {
        return
    }

    $status = if ($Result.Success) { 'Succeeded' } else { 'Failed' }
    Set-XdrTimelineObjectValue -InputObject $job -Name 'Status' -Value $status
    Set-XdrTimelineObjectValue -InputObject $job -Name 'Attempts' -Value ([int]([int](Get-XdrTimelineObjectValue -InputObject $job -Name 'Attempts') + 1))
    Set-XdrTimelineObjectValue -InputObject $job -Name 'FilePath' -Value $(if ($Result.FilePath) { [string]$Result.FilePath } else { $null })
    Set-XdrTimelineObjectValue -InputObject $job -Name 'FileSha256' -Value $(if ($Result.FileSha256) { [string]$Result.FileSha256 } elseif ($Result.FilePath) { Get-XdrFileSha256 -Path ([string]$Result.FilePath) } else { $null })
    Set-XdrTimelineObjectValue -InputObject $job -Name 'EventCount' -Value ([int]$Result.EventCount)
    Set-XdrTimelineObjectValue -InputObject $job -Name 'UniqueKeyCount' -Value $(if ($Result.PSObject.Properties['UniqueKeyCount']) { [int]$Result.UniqueKeyCount } else { [int]$Result.EventCount })
    Set-XdrTimelineObjectValue -InputObject $job -Name 'KeySetHash' -Value $(if ($Result.PSObject.Properties['KeySetHash']) { $Result.KeySetHash } else { $null })
    Set-XdrTimelineObjectValue -InputObject $job -Name 'FirstTimestamp' -Value $(if ($Result.PSObject.Properties['FirstTimestamp']) { $Result.FirstTimestamp } else { $null })
    Set-XdrTimelineObjectValue -InputObject $job -Name 'LastTimestamp' -Value $(if ($Result.PSObject.Properties['LastTimestamp']) { $Result.LastTimestamp } else { $null })
    Set-XdrTimelineObjectValue -InputObject $job -Name 'MissingTimestampCount' -Value $(if ($Result.PSObject.Properties['MissingTimestampCount']) { [int]$Result.MissingTimestampCount } else { 0 })
    Set-XdrTimelineObjectValue -InputObject $job -Name 'FailureClass' -Value $(if ($Result.PSObject.Properties['FailureClass']) { $Result.FailureClass } else { $null })
    Set-XdrTimelineObjectValue -InputObject $job -Name 'Error' -Value $(if ($Result.Success) { $null } else { $Result.Error })
    Set-XdrTimelineObjectValue -InputObject $job -Name 'PagesRetrieved' -Value $(if ($Result.PSObject.Properties['PagesRetrieved']) { [int]$Result.PagesRetrieved } else { $null })
}

function Get-XdrEndpointTimelinePendingChunk {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [object[]]$Chunks = @(),

        [Parameter()]
        [AllowNull()]
        [object]$Manifest
    )

    if ($null -eq $Manifest) {
        return @($Chunks)
    }

    $jobs = @(Get-XdrEndpointTimelineManifestJob -Manifest $Manifest -LeafOnly)

    if ($jobs.Count -eq 0) {
        return @($Chunks)
    }

    $pending = [System.Collections.Generic.List[object]]::new()
    $chunkByIndex = @{}
    foreach ($chunk in @($Chunks)) {
        if ($null -eq $chunk) { continue }
        $chunkIndex = Get-XdrTimelineObjectValue -InputObject $chunk -Name 'Index'
        if ($null -eq $chunkIndex) { $chunkIndex = Get-XdrTimelineObjectValue -InputObject $chunk -Name 'ChunkIndex' }
        if ($null -ne $chunkIndex) { $chunkByIndex[[int]$chunkIndex] = $chunk }
    }
    foreach ($job in $jobs) {
        $jobChunkIndex = [int](Get-XdrTimelineObjectValue -InputObject $job -Name 'ChunkIndex')
        $jobStatus = [string](Get-XdrTimelineObjectValue -InputObject $job -Name 'Status')
        $failureClass = [string](Get-XdrTimelineObjectValue -InputObject $job -Name 'FailureClass')
        if ($jobStatus -eq 'Succeeded') {
            if (Test-XdrEndpointTimelineManifestJobComplete -Job $job) {
                continue
            }
            [void]$pending.Add($(if ($chunkByIndex.ContainsKey($jobChunkIndex)) { $chunkByIndex[$jobChunkIndex] } else { ConvertTo-XdrEndpointTimelineChunk -Job $job }))
            continue
        }

        $isRetryableFailedJob = ($jobStatus -eq 'Failed' -and $failureClass -in @('RateLimited', 'Transient', 'Timeout', 'AuthExpired'))
        $isPendingJob = ($jobStatus -eq 'Pending' -or $isRetryableFailedJob)
        if (-not $isPendingJob) {
            continue
        }

        [void]$pending.Add($(if ($chunkByIndex.ContainsKey($jobChunkIndex)) { $chunkByIndex[$jobChunkIndex] } else { ConvertTo-XdrEndpointTimelineChunk -Job $job }))
    }

    $pendingChunks = @($pending.ToArray())
    if ($pendingChunks.Count -gt 0 -and @($pendingChunks | Where-Object { [string](Get-XdrTimelineObjectValue -InputObject $_ -Name 'Strategy') -eq 'AdaptiveSplit' }).Count -gt 0) {
        return @($pendingChunks | Sort-Object `
            @{ Expression = { if ([string](Get-XdrTimelineObjectValue -InputObject $_ -Name 'Strategy') -eq 'AdaptiveSplit') { 0 } else { 1 } } }, `
            @{ Expression = { ([datetime](Get-XdrTimelineObjectValue -InputObject $_ -Name 'OwnerFromDate')).ToUniversalTime() }; Descending = $true })
    }

    return $pendingChunks
}

function New-XdrEndpointTimelineResultFromJob {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory result object only')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Job
    )

    $jobFilePath = [string](Get-XdrTimelineObjectValue -InputObject $Job -Name 'FilePath')
    [PSCustomObject]@{
        ChunkIndex            = [int](Get-XdrTimelineObjectValue -InputObject $Job -Name 'ChunkIndex')
        RequestShapeHash      = $null
        RequestShape          = 'ResumedManifestJob'
        FilePath              = $jobFilePath
        FileSha256            = [string](Get-XdrTimelineObjectValue -InputObject $Job -Name 'FileSha256')
        EventCount            = [int](Get-XdrTimelineObjectValue -InputObject $Job -Name 'EventCount')
        UniqueKeyCount        = [int](Get-XdrTimelineObjectValue -InputObject $Job -Name 'UniqueKeyCount')
        KeySetHash            = Get-XdrTimelineObjectValue -InputObject $Job -Name 'KeySetHash'
        FirstTimestamp        = Get-XdrTimelineObjectValue -InputObject $Job -Name 'FirstTimestamp'
        LastTimestamp         = Get-XdrTimelineObjectValue -InputObject $Job -Name 'LastTimestamp'
        MissingTimestampCount = [int](Get-XdrTimelineObjectValue -InputObject $Job -Name 'MissingTimestampCount')
        FromDate              = [datetime](Get-XdrTimelineObjectValue -InputObject $Job -Name 'RequestFrom')
        ToDate                = [datetime](Get-XdrTimelineObjectValue -InputObject $Job -Name 'RequestTo')
        OwnerFromDate         = [datetime](Get-XdrTimelineObjectValue -InputObject $Job -Name 'OwnerFrom')
        OwnerToDate           = [datetime](Get-XdrTimelineObjectValue -InputObject $Job -Name 'OwnerTo')
        Success               = $true
        FailureClass          = $null
        ElapsedSeconds        = 0
        PagesRetrieved        = 0
        ContinuationPageCount = 0
        NextLinkCount         = 0
        PrevLinkCount         = 0
        RetryCount            = 0
        Pages                 = @()
        FileSizeKB            = if ($jobFilePath -and (Test-Path -LiteralPath $jobFilePath)) { [math]::Round((Get-Item -LiteralPath $jobFilePath).Length / 1KB, 2) } else { 0 }
    }
}

function Test-XdrEndpointTimelineResultNeedsSplit {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [object]$Result,

        [Parameter()]
        [int]$DensePageThreshold = 32
    )

    if ($Result.Success) {
        return $false
    }

    $message = [string]$Result.Error
    if ($message -match '(?i)(exceeded MaxPagesPerChunk|duplicate continuation URI|no-progress|DensePageThreshold|EarlyDensityThreshold)') {
        return $true
    }

    if ($Result.PSObject.Properties['PagesRetrieved'] -and [int]$Result.PagesRetrieved -ge $DensePageThreshold) {
        return $true
    }

    return $false
}

function ConvertTo-XdrEndpointTimelineUtcDateTime {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        if ($Value -is [datetime]) {
            return ([datetime]$Value).ToUniversalTime()
        }

        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) {
            return $null
        }

        return ([datetimeoffset]::Parse(
            $text,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal
        )).UtcDateTime
    }
    catch {
        return $null
    }
}

function Get-XdrEndpointTimelineObservedPageTimes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Returns multiple page timestamp observations for split planning')]
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Pages,

        [Parameter(Mandatory)]
        [datetime]$OwnerFrom,

        [Parameter(Mandatory)]
        [datetime]$OwnerTo
    )

    $observed = [System.Collections.Generic.List[object]]::new()

    foreach ($page in @($Pages)) {
        if ($null -eq $page) {
            continue
        }

        $first = ConvertTo-XdrEndpointTimelineUtcDateTime -Value (Get-XdrTimelineObjectValue -InputObject $page -Name 'FirstEventTimestamp')
        $last = ConvertTo-XdrEndpointTimelineUtcDateTime -Value (Get-XdrTimelineObjectValue -InputObject $page -Name 'LastEventTimestamp')
        $valid = @($first, $last) | Where-Object { $null -ne $_ }
        if ($valid.Count -eq 0) {
            continue
        }

        $pageMin = $valid | Sort-Object | Select-Object -First 1
        $pageMax = $valid | Sort-Object | Select-Object -Last 1
        if ($pageMin -lt $OwnerFrom -or $pageMax -gt $OwnerTo) {
            continue
        }

        $centerTicks = [int64](($pageMin.Ticks + $pageMax.Ticks) / 2)
        $observed.Add([pscustomobject]@{
            PageNumber    = Get-XdrTimelineObjectValue -InputObject $page -Name 'PageNumber'
            First         = $first
            Last          = $last
            Min           = $pageMin
            Max           = $pageMax
            Center        = [datetime]::new($centerTicks, [DateTimeKind]::Utc)
            RawItemCount  = Get-XdrTimelineObjectValue -InputObject $page -Name 'RawItemCount'
        })
    }

    return $observed.ToArray()
}

function New-XdrEndpointTimelineSplitPlan {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory split plan only')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Job,

        [Parameter(Mandatory)]
        [object]$Result,

        [Parameter(Mandatory)]
        [int]$MinimumChunkMinutes,

        [Parameter()]
        [int]$DensePageThreshold = 32
    )

    $ownerFrom = ([datetime](Get-XdrTimelineObjectValue -InputObject $Job -Name 'OwnerFrom')).ToUniversalTime()
    $ownerTo = ([datetime](Get-XdrTimelineObjectValue -InputObject $Job -Name 'OwnerTo')).ToUniversalTime()
    $duration = $ownerTo - $ownerFrom
    $metadata = [ordered]@{
        ObservedTimestampStart       = $null
        ObservedTimestampEnd         = $null
        ObservedTimestampSpanSeconds = $null
        SampledPageCount             = 0
        PagesAvoidedEstimate         = 0
        SplitBoundaries              = @()
        RequestedPartCount           = 0
        ActualPartCount              = 0
        FallbackReason               = $null
    }

    if ($duration.TotalMinutes -le $MinimumChunkMinutes) {
        return [pscustomobject]@{
            Strategy   = 'MinimumChunkSizeReached'
            Parts      = 0
            Boundaries = @()
            Metadata   = $metadata
        }
    }

    $pagesRetrieved = if ($Result.PSObject.Properties['PagesRetrieved']) { [int]$Result.PagesRetrieved } else { 0 }
    $eventCount = if ($Result.PSObject.Properties['EventCount']) { [int]$Result.EventCount } else { 0 }
    $parts = if (($pagesRetrieved -ge 64) -or ($eventCount -ge 50000)) { 4 } else { 2 }
    $durationSeconds = $duration.TotalSeconds
    if (($durationSeconds / $parts) -lt ($MinimumChunkMinutes * 60)) {
        $parts = [math]::Max(2, [math]::Floor($durationSeconds / ($MinimumChunkMinutes * 60)))
    }

    if ($parts -lt 2) {
        return [pscustomobject]@{
            Strategy   = 'MinimumChunkSizeReached'
            Parts      = 0
            Boundaries = @()
            Metadata   = $metadata
        }
    }

    $metadata.RequestedPartCount = $parts
    if ($pagesRetrieved -gt 0 -and $pagesRetrieved -lt $DensePageThreshold) {
        $metadata.PagesAvoidedEstimate = [math]::Max(0, $DensePageThreshold - $pagesRetrieved)
    }

    $pages = if ($Result.PSObject.Properties['Pages']) { @($Result.Pages) } else { @() }
    $observed = @(Get-XdrEndpointTimelineObservedPageTimes -Pages $pages -OwnerFrom $ownerFrom -OwnerTo $ownerTo)
    $metadata.SampledPageCount = $observed.Count

    if ($observed.Count -gt 0) {
        $observedMin = $observed.Min | Sort-Object | Select-Object -First 1
        $observedMax = $observed.Max | Sort-Object | Select-Object -Last 1
        $metadata.ObservedTimestampStart = $observedMin.ToString('o')
        $metadata.ObservedTimestampEnd = $observedMax.ToString('o')
        $metadata.ObservedTimestampSpanSeconds = [math]::Round(($observedMax - $observedMin).TotalSeconds, 3)
    }

    $strategy = if ([string]$Result.Error -match 'EarlyDensityThreshold') { 'EarlyDensity' } else { 'TimestampGuided' }
    $minSegment = [timespan]::FromMinutes($MinimumChunkMinutes)
    $candidateBoundaries = [System.Collections.Generic.List[datetime]]::new()

    if ($observed.Count -ge ($parts - 1) -and $metadata.ObservedTimestampSpanSeconds -gt 0) {
        $centers = @($observed.Center | Sort-Object)
        for ($i = 1; $i -lt $parts; $i++) {
            $rawIndex = [math]::Floor(($centers.Count - 1) * ($i / [double]$parts))
            $candidateBoundaries.Add($centers[[int]$rawIndex])
        }
    }
    else {
        $metadata.FallbackReason = 'InsufficientValidPageTimestamps'
    }

    $validBoundaries = [System.Collections.Generic.List[datetime]]::new()
    $previous = $ownerFrom
    foreach ($candidate in @($candidateBoundaries.ToArray() | Sort-Object -Unique)) {
        $clamped = $candidate
        if ($clamped -lt $ownerFrom.Add($minSegment)) {
            $clamped = $ownerFrom.Add($minSegment)
        }
        if ($clamped -gt $ownerTo.Subtract($minSegment)) {
            $clamped = $ownerTo.Subtract($minSegment)
        }

        if (($clamped - $previous) -lt $minSegment) {
            $metadata.FallbackReason = 'TimestampBoundariesTooClose'
            $validBoundaries.Clear()
            break
        }

        $validBoundaries.Add($clamped)
        $previous = $clamped
    }

    if ($validBoundaries.Count -gt 0 -and ($ownerTo - $previous) -lt $minSegment) {
        $metadata.FallbackReason = 'TimestampTailTooSmall'
        $validBoundaries.Clear()
    }

    if ($validBoundaries.Count -eq 0) {
        $strategy = 'EqualTime'
        $metadata.ActualPartCount = $parts
        return [pscustomobject]@{
            Strategy   = $strategy
            Parts      = $parts
            Boundaries = @()
            Metadata   = $metadata
        }
    }

    $metadata.SplitBoundaries = @($validBoundaries.ToArray() | ForEach-Object { $_.ToString('o') })
    $metadata.ActualPartCount = $validBoundaries.Count + 1

    return [pscustomobject]@{
        Strategy   = $strategy
        Parts      = ($validBoundaries.Count + 1)
        Boundaries = $validBoundaries.ToArray()
        Metadata   = $metadata
    }
}

function Split-XdrEndpointTimelineManifestJob {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Updates an in-memory manifest object only')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Manifest,

        [Parameter(Mandatory)]
        [object]$Result,

        [Parameter(Mandatory)]
        [datetime]$GlobalFromDate,

        [Parameter(Mandatory)]
        [datetime]$GlobalToDate,

        [Parameter()]
        [int]$OverlapSeconds = 10,

        [Parameter()]
        [int]$MinimumChunkMinutes = 15,

        [Parameter()]
        [int]$DensePageThreshold = 32
    )

    if (-not (Test-XdrEndpointTimelineResultNeedsSplit -Result $Result -DensePageThreshold $DensePageThreshold)) {
        return @()
    }

    $jobs = @(Get-XdrEndpointTimelineManifestJob -Manifest $Manifest)
    $parentJob = $jobs | Where-Object { [int](Get-XdrTimelineObjectValue -InputObject $_ -Name 'ChunkIndex') -eq [int]$Result.ChunkIndex } | Select-Object -First 1
    if (-not $parentJob) {
        return @()
    }

    $ownerFrom = ([datetime](Get-XdrTimelineObjectValue -InputObject $parentJob -Name 'OwnerFrom')).ToUniversalTime()
    $ownerTo = ([datetime](Get-XdrTimelineObjectValue -InputObject $parentJob -Name 'OwnerTo')).ToUniversalTime()
    $splitPlan = New-XdrEndpointTimelineSplitPlan -Job $parentJob -Result $Result -MinimumChunkMinutes $MinimumChunkMinutes -DensePageThreshold $DensePageThreshold
    if ($splitPlan.Strategy -eq 'MinimumChunkSizeReached' -or [int]$splitPlan.Parts -lt 2) {
        Set-XdrTimelineObjectValue -InputObject $parentJob -Name 'SplitReason' -Value 'MinimumChunkSizeReached'
        Set-XdrTimelineObjectValue -InputObject $parentJob -Name 'SplitStrategy' -Value 'MinimumChunkSizeReached'
        Set-XdrTimelineObjectValue -InputObject $parentJob -Name 'SplitMetadata' -Value $splitPlan.Metadata
        return @()
    }

    $nextIndex = if ($jobs.Count -eq 0) { 0 } else { [int](($jobs | ForEach-Object { [int](Get-XdrTimelineObjectValue -InputObject $_ -Name 'ChunkIndex') } | Measure-Object -Maximum).Maximum) + 1 }
    $parentJobId = [string](Get-XdrTimelineObjectValue -InputObject $parentJob -Name 'JobId')
    $generation = [int](Get-XdrTimelineObjectValue -InputObject $parentJob -Name 'Generation') + 1
    $childJobs = [System.Collections.Generic.List[object]]::new()
    $boundaries = @($splitPlan.Boundaries)
    if ($boundaries.Count -eq 0) {
        $durationSeconds = ($ownerTo - $ownerFrom).TotalSeconds
        for ($i = 1; $i -lt [int]$splitPlan.Parts; $i++) {
            $boundaries += $ownerFrom.AddSeconds(($durationSeconds / [int]$splitPlan.Parts) * $i)
        }
        $splitPlan.Metadata.SplitBoundaries = @($boundaries | ForEach-Object { $_.ToString('o') })
    }
    $windowStarts = @($ownerFrom) + $boundaries
    $windowEnds = $boundaries + @($ownerTo)

    for ($i = 0; $i -lt $windowStarts.Count; $i++) {
        $childOwnerFrom = ([datetime]$windowStarts[$i]).ToUniversalTime()
        $childOwnerTo = ([datetime]$windowEnds[$i]).ToUniversalTime()
        $requestFrom = $childOwnerFrom.AddSeconds(-$OverlapSeconds)
        if ($requestFrom -lt $GlobalFromDate) { $requestFrom = $GlobalFromDate }
        $requestTo = $childOwnerTo.AddSeconds($OverlapSeconds)
        if ($requestTo -gt $GlobalToDate) { $requestTo = $GlobalToDate }

        $childChunk = [pscustomobject]@{
            Index         = $nextIndex + $i
            FromDate      = $requestFrom
            ToDate        = $requestTo
            OwnerFromDate = $childOwnerFrom
            OwnerToDate   = $childOwnerTo
            ChunkHours    = [math]::Round(($childOwnerTo - $childOwnerFrom).TotalHours, 4)
            ChunkMinutes  = [int][math]::Ceiling(($childOwnerTo - $childOwnerFrom).TotalMinutes)
            Strategy      = 'AdaptiveSplit'
        }
        $childJob = New-XdrEndpointTimelineManifestJob -Chunk $childChunk -ParentJobId $parentJobId -Generation $generation
        Set-XdrTimelineObjectValue -InputObject $childJob -Name 'SplitStrategy' -Value $splitPlan.Strategy
        Set-XdrTimelineObjectValue -InputObject $childJob -Name 'SplitMetadata' -Value $splitPlan.Metadata
        [void]$childJobs.Add($childJob)
    }

    Set-XdrTimelineObjectValue -InputObject $parentJob -Name 'Status' -Value 'Superseded'
    Set-XdrTimelineObjectValue -InputObject $parentJob -Name 'SplitReason' -Value ([string]$Result.Error)
    Set-XdrTimelineObjectValue -InputObject $parentJob -Name 'SplitStrategy' -Value $splitPlan.Strategy
    Set-XdrTimelineObjectValue -InputObject $parentJob -Name 'SplitMetadata' -Value $splitPlan.Metadata
    Set-XdrTimelineObjectValue -InputObject $parentJob -Name 'ChildJobIds' -Value @($childJobs | ForEach-Object { [string](Get-XdrTimelineObjectValue -InputObject $_ -Name 'JobId') })
    $Manifest['Jobs'] = @($Manifest['Jobs']) + @($childJobs.ToArray())

    return $childJobs.ToArray()
}

function Test-XdrTimelineDiskSpace {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$Path,

        [Parameter()]
        [int64]$EstimatedBytes = 1073741824
    )

    foreach ($itemPath in @($Path | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        try {
            $parent = Split-Path -Path $itemPath -Parent
            if ([string]::IsNullOrWhiteSpace($parent)) { $parent = (Get-Location).Path }
            $resolvedParent = Resolve-Path -LiteralPath $parent -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path -First 1
            $root = if ($resolvedParent) { [System.IO.Path]::GetPathRoot($resolvedParent) } else { [System.IO.Path]::GetPathRoot($itemPath) }
            if ([string]::IsNullOrWhiteSpace($root)) {
                continue
            }

            $drive = [System.IO.DriveInfo]::new($root)
            $required = [int64]($EstimatedBytes * 1.2)
            if ($drive.AvailableFreeSpace -lt $required) {
                $message = "Available space on '$root' may be insufficient for timeline export. Required estimate: $([math]::Round($required / 1GB, 2)) GB; available: $([math]::Round($drive.AvailableFreeSpace / 1GB, 2)) GB."
                $canPrompt = (
                    $Host -and
                    $Host.UI -and
                    $Host.Name -eq 'ConsoleHost' -and
                    [Environment]::UserInteractive -and
                    -not [Console]::IsInputRedirected -and
                    -not [Console]::IsOutputRedirected
                )
                if ($canPrompt) {
                    $choice = $Host.UI.PromptForChoice('Low disk space', $message, @('&Continue', '&Stop'), 1)
                    if ($choice -ne 0) {
                        throw $message
                    }
                }
                else {
                    throw $message
                }
            }
        }
        catch {
            if ($_.Exception.Message -match 'Available space') { throw }
            Write-Verbose "Could not determine free space for '$itemPath': $($_.Exception.Message)"
        }
    }
}
