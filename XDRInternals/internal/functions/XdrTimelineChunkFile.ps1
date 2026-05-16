function Read-XdrTimelineChunkFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,

        [Parameter()]
        [switch]$AllowPartial
    )

    try {
        return Get-Content -Path $File.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        if ($AllowPartial) {
            Write-Warning "Skipping unreadable timeline chunk file '$($File.Name)': $($_.Exception.Message)"
            return $null
        }
        throw
    }
}

function Get-XdrTimelineChunkEventsJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,

        [Parameter()]
        [switch]$AllowPartial
    )

    try {
        $rawContent = [System.IO.File]::ReadAllText($File.FullName)
        $eventsStart = $rawContent.IndexOf('"Events":[')
        if ($eventsStart -lt 0) { throw 'Could not locate the Events array.' }

        $eventsStart += 10
        $eventsEnd = $rawContent.LastIndexOf('],"EventCount"')
        if ($eventsEnd -lt 0) { $eventsEnd = $rawContent.LastIndexOf(']}') }
        if ($eventsEnd -lt $eventsStart) { throw 'Could not determine the end of the Events array.' }

        return $rawContent.Substring($eventsStart, $eventsEnd - $eventsStart)
    }
    catch {
        if ($AllowPartial) {
            Write-Warning "Skipping unreadable timeline chunk file '$($File.Name)': $($_.Exception.Message)"
            return $null
        }
        throw
    }
}

function Initialize-XdrTimelineRawMergeAccelerator {
    [CmdletBinding()]
    param()

    if ('XdrTimelineRawMergeAccelerator' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

public sealed class XdrTimelineRawEventRecord
{
    public string RawJson { get; set; }
    public string StableKey { get; set; }
    public DateTime? Timestamp { get; set; }
    public string FilePath { get; set; }
    public bool RequiresStableKeyFallback { get; set; }
}

public static class XdrTimelineRawMergeAccelerator
{
    private static readonly string[] TimestampProperties = new[] { "Timestamp", "timestamp", "EventTime", "eventTime", "ActionTimeIsoString", "TimeGenerated", "date" };
    private static readonly string[] PreferredKeyProperties = new[] { "Id", "id", "_id", "EventId", "eventId", "ReportId", "recordId" };
    private static readonly string[] EventTypeProperties = new[] { "ActionType", "Type", "EventType" };

    public static XdrTimelineRawEventRecord[] ExtractRecords(string[] filePaths, string eventType, bool allowPartial)
    {
        var records = new List<XdrTimelineRawEventRecord>();
        Regex eventTypeRegex = null;
        if (!String.IsNullOrWhiteSpace(eventType))
        {
            eventTypeRegex = new Regex("^" + Regex.Escape(eventType).Replace("\\*", ".*").Replace("\\?", ".") + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        foreach (var filePath in filePaths)
        {
            try
            {
                using (var document = JsonDocument.Parse(File.ReadAllText(filePath, Encoding.UTF8)))
                {
                    JsonElement events;
                    if (!document.RootElement.TryGetProperty("Events", out events) || events.ValueKind != JsonValueKind.Array)
                    {
                        throw new InvalidDataException("Could not locate the Events array.");
                    }

                    foreach (var eventElement in events.EnumerateArray())
                    {
                        if (eventTypeRegex != null)
                        {
                            var eventTypeName = GetStringProperty(eventElement, EventTypeProperties);
                            if (String.IsNullOrWhiteSpace(eventTypeName) || !eventTypeRegex.IsMatch(eventTypeName))
                            {
                                continue;
                            }
                        }

                        var stableKey = GetStringProperty(eventElement, PreferredKeyProperties);
                        records.Add(new XdrTimelineRawEventRecord
                        {
                            RawJson = eventElement.GetRawText(),
                            StableKey = stableKey,
                            Timestamp = GetTimestamp(eventElement),
                            FilePath = filePath,
                            RequiresStableKeyFallback = String.IsNullOrWhiteSpace(stableKey)
                        });
                    }
                }
            }
            catch
            {
                if (!allowPartial)
                {
                    throw;
                }
            }
        }

        return records.ToArray();
    }

    private static DateTime? GetTimestamp(JsonElement element)
    {
        var value = GetStringProperty(element, TimestampProperties);
        if (String.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        DateTimeOffset parsed;
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out parsed))
        {
            return parsed.UtcDateTime;
        }

        return null;
    }

    private static string GetStringProperty(JsonElement element, string[] propertyNames)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        foreach (var propertyName in propertyNames)
        {
            JsonElement property;
            if (!element.TryGetProperty(propertyName, out property))
            {
                continue;
            }

            string value = null;
            switch (property.ValueKind)
            {
                case JsonValueKind.String:
                    value = property.GetString();
                    break;
                case JsonValueKind.Number:
                case JsonValueKind.True:
                case JsonValueKind.False:
                    value = property.GetRawText();
                    break;
            }

            if (!String.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }
}
'@
}

function Get-XdrTimelineChunkRawEventRecord {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,

        [Parameter()]
        [scriptblock]$FilterScript = { $true },

        [Parameter()]
        [scriptblock]$GetStableEventKeyScript = { param($TimelineEvent) Get-XdrTimelineStableEventKey -TimelineEvent $TimelineEvent },

        [Parameter()]
        [switch]$AllowPartial
    )

    $document = $null
    try {
        $rawContent = [System.IO.File]::ReadAllText($File.FullName)
        $document = [System.Text.Json.JsonDocument]::Parse($rawContent)
        $eventsProperty = $document.RootElement.GetProperty('Events')
        $records = [System.Collections.Generic.List[object]]::new()

        foreach ($eventElement in $eventsProperty.EnumerateArray()) {
            $rawEventJson = $eventElement.GetRawText()
            $eventItem = $rawEventJson | ConvertFrom-Json -Depth 100
            if (-not (& $FilterScript $eventItem)) {
                continue
            }

            $timestamp = Get-XdrTimelineEventTimestamp -TimelineEvent $eventItem
            [void]$records.Add([PSCustomObject]@{
                    Event     = $eventItem
                    RawJson   = $rawEventJson
                    StableKey = [string](& $GetStableEventKeyScript $eventItem $rawEventJson)
                    Timestamp = $timestamp
                    FilePath  = $File.FullName
                })
        }

        return $records.ToArray()
    }
    catch {
        if ($AllowPartial) {
            Write-Warning "Skipping unreadable timeline chunk file '$($File.Name)': $($_.Exception.Message)"
            return @()
        }
        throw
    }
    finally {
        if ($document) { $document.Dispose() }
    }
}

function Write-XdrTimelineChunkFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [int]$ChunkIndex,

        [Parameter(Mandatory)]
        [datetime]$FromDate,

        [Parameter(Mandatory)]
        [datetime]$ToDate,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Events = @()
    )

    $parentPath = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -Path $parentPath)) {
        New-Item -Path $parentPath -ItemType Directory -Force | Out-Null
    }

    [PSCustomObject]@{
        ChunkIndex = $ChunkIndex
        FromDate   = $FromDate.ToUniversalTime().ToString('o')
        ToDate     = $ToDate.ToUniversalTime().ToString('o')
        Events     = @($Events)
        EventCount = @($Events).Count
    } | ConvertTo-Json -Depth 20 | Set-Content -Path $Path -Encoding UTF8
}

function Get-XdrTimelineEventTimestamp {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory)]
        [object]$TimelineEvent,

        [Parameter()]
        [string[]]$PropertyNames = @('Timestamp', 'timestamp', 'EventTime', 'eventTime', 'ActionTimeIsoString', 'TimeGenerated', 'date')
    )

    foreach ($propertyName in $PropertyNames) {
        if (-not $TimelineEvent.PSObject.Properties[$propertyName]) { continue }
        $value = $TimelineEvent.$propertyName
        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { continue }
        try { return ([datetime]$value).ToUniversalTime() } catch { continue }
    }

    return $null
}

function Get-XdrTimelineStableEventKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$TimelineEvent,

        [Parameter()]
        [string[]]$PreferredProperties = @('Id', 'id', '_id', 'EventId', 'eventId', 'ReportId', 'recordId'),

        [Parameter()]
        [string[]]$UnstableProperties = @('RowNumber')
    )

    foreach ($propertyName in $PreferredProperties) {
        if ($TimelineEvent.PSObject.Properties[$propertyName] -and -not [string]::IsNullOrWhiteSpace([string]$TimelineEvent.$propertyName)) {
            return [string]$TimelineEvent.$propertyName
        }
    }

    $stablePayload = [ordered]@{}
    foreach ($property in ($TimelineEvent.PSObject.Properties | Sort-Object Name)) {
        if ($UnstableProperties -notcontains $property.Name) {
            $stablePayload[$property.Name] = $property.Value
        }
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stableJson = $stablePayload | ConvertTo-Json -Depth 20 -Compress
        return [System.BitConverter]::ToString($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stableJson))).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-XdrTimelineSortedEvent {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Events = @()
    )

    if ($Events.Count -le 1) {
        return $Events
    }

    return @(
        $Events | Sort-Object -Property @{
            Expression = {
                $timestamp = Get-XdrTimelineEventTimestamp -TimelineEvent $_
                if ($null -eq $timestamp) { [datetime]::MinValue } else { $timestamp }
            }
            Descending = $true
        }, @{
            Expression = { Get-XdrTimelineStableEventKey -TimelineEvent $_ }
            Descending = $false
        }
    )
}

function Merge-XdrTimelineChunkFile {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo[]]$File,

        [Parameter()]
        [scriptblock]$SelectEventsScript = { param($ChunkData) @($ChunkData.Events) },

        [Parameter()]
        [scriptblock]$GetStableEventKeyScript = { param($TimelineEvent) Get-XdrTimelineStableEventKey -TimelineEvent $TimelineEvent },

        [Parameter()]
        [switch]$AllowPartial,

        [Parameter()]
        [switch]$Sort
    )

    $events = [System.Collections.Generic.List[object]]::new()
    $seenKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    foreach ($chunkFile in $File) {
        $chunkData = Read-XdrTimelineChunkFile -File $chunkFile -AllowPartial:$AllowPartial
        if ($null -eq $chunkData) { continue }

        foreach ($eventItem in @(& $SelectEventsScript $chunkData)) {
            $stableKey = [string](& $GetStableEventKeyScript $eventItem)
            if ($seenKeys.Add($stableKey)) {
                [void]$events.Add($eventItem)
            }
        }
    }

    if ($Sort) {
        return @(Get-XdrTimelineSortedEvent -Events $events.ToArray())
    }

    return $events.ToArray()
}

function Merge-XdrTimelineChunkRawEvent {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo[]]$File,

        [Parameter()]
        [scriptblock]$FilterScript = { $true },

        [Parameter()]
        [scriptblock]$GetStableEventKeyScript = { param($TimelineEvent) Get-XdrTimelineStableEventKey -TimelineEvent $TimelineEvent },

        [Parameter()]
        [string]$EventType,

        [Parameter()]
        [switch]$UseFastJsonMetadata,

        [Parameter()]
        [switch]$AllowPartial
    )

    $records = [System.Collections.Generic.List[object]]::new()
    $seenKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

    if ($UseFastJsonMetadata) {
        Initialize-XdrTimelineRawMergeAccelerator
        $filePaths = @($File | ForEach-Object { $_.FullName })
        $candidateRecords = [XdrTimelineRawMergeAccelerator]::ExtractRecords($filePaths, $EventType, [bool]$AllowPartial)

        foreach ($record in @($candidateRecords)) {
            if ($record.RequiresStableKeyFallback) {
                $eventItem = $record.RawJson | ConvertFrom-Json -Depth 100
                if (-not (& $FilterScript $eventItem)) {
                    continue
                }
                $record.StableKey = [string](& $GetStableEventKeyScript $eventItem $record.RawJson)
            }

            if ($seenKeys.Add($record.StableKey)) {
                [void]$records.Add($record)
            }
        }
    }
    else {
        foreach ($chunkFile in $File) {
            foreach ($record in @(Get-XdrTimelineChunkRawEventRecord -File $chunkFile -FilterScript $FilterScript -GetStableEventKeyScript $GetStableEventKeyScript -AllowPartial:$AllowPartial)) {
                if ($seenKeys.Add($record.StableKey)) {
                    [void]$records.Add($record)
                }
            }
        }
    }

    return @(
        $records.ToArray() | Sort-Object -Property @{
            Expression = {
                if ($null -eq $_.Timestamp) { [datetime]::MinValue } else { $_.Timestamp }
            }
            Descending = $true
        }, @{
            Expression = { $_.StableKey }
            Descending = $false
        }
    )
}

function Write-XdrTimelineRawEventExport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Record = @(),

        [Parameter()]
        [ValidateSet('Json', 'Ndjson')]
        [string]$Format = 'Json'
    )

    $parentPath = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -LiteralPath $parentPath)) {
        New-Item -Path $parentPath -ItemType Directory -Force | Out-Null
    }
    if ([string]::IsNullOrWhiteSpace($parentPath)) {
        $parentPath = (Get-Location).Path
    }

    $tempPath = Join-Path $parentPath ('.' + [System.IO.Path]::GetFileName($Path) + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $writer = [System.IO.StreamWriter]::new($tempPath, $false, [System.Text.Encoding]::UTF8)
    try {
        if ($Format -eq 'Ndjson') {
            foreach ($item in @($Record)) {
                $writer.WriteLine([string]$item.RawJson)
            }
        }
        else {
            $writer.Write('[')
            $isFirst = $true
            foreach ($item in @($Record)) {
                if (-not $isFirst) { $writer.Write(',') }
                $writer.Write([string]$item.RawJson)
                $isFirst = $false
            }
            $writer.Write(']')
        }
    }
    finally {
        $writer.Dispose()
    }

    Move-Item -LiteralPath $tempPath -Destination $Path -Force
}

function Write-XdrTimelineDiagnosticFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Diagnostics
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    $parentPath = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -Path $parentPath)) {
        New-Item -Path $parentPath -ItemType Directory -Force | Out-Null
    }

    $Diagnostics | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
}
