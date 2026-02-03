function Get-XdrCloudAppsDiscoveredApp {
    <#
    .SYNOPSIS
        Retrieves discovered cloud apps or metadata from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the list of discovered cloud applications from Microsoft Defender for Cloud Apps
        Cloud Discovery. This includes apps detected through traffic analysis from log collectors,
        endpoint integration, or other discovery sources. Results can be filtered, sorted, and paginated.
        This function includes caching support to reduce API calls.

        When no StreamId or StreamName is specified, queries ALL available discovery streams and
        includes StreamId/StreamName properties on each result for context.

        Use -Metadata to retrieve field definitions, filter options, and other metadata
        used when querying discovered apps.

        Use -ListStreams to see available discovery streams without querying apps.

    .PARAMETER Metadata
        When specified, retrieves metadata for discovered apps queries including field
        definitions and filter options instead of the apps themselves.

    .PARAMETER ListStreams
        When specified, lists all available discovery streams. Useful for discovering
        stream IDs and names before querying apps.

    .PARAMETER StreamId
        The ID of the discovery stream to query. This identifies the data source
        (e.g., log collector, endpoint integration) from which apps were discovered.
        If not specified, queries all available streams.
        Accepts pipeline input from Get-XdrCloudAppsConfigurationDiscoveryStream via the _id property.

    .PARAMETER StreamName
        The name of the discovery stream to query. Supports wildcards (e.g., "Defender*").
        If not specified along with StreamId, queries all available streams.

    .PARAMETER Timeframe
        The number of days to include in the results. Default is 30 days.

    .PARAMETER Limit
        The maximum number of results to return per request per stream. Default is 20.

    .PARAMETER Skip
        The number of results to skip for pagination. Default is 0.

    .PARAMETER SortField
        The field to sort results by. Default is "traffic".
        Common values include: name, score, traffic, upload, transactions, users, ips, machines, lastSeen.

    .PARAMETER SortDirection
        The sort direction. Valid values are "asc" (ascending) or "desc" (descending).
        Default is "desc".

    .PARAMETER Filters
        A hashtable of filters to apply to the query. Filter structure depends on the
        metadata available via -Metadata parameter.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsDiscoveredApp -ListStreams
        Lists all available discovery streams.

    .EXAMPLE
        Get-XdrCloudAppsDiscoveredApp
        Retrieves discovered apps from ALL streams (includes StreamId/StreamName on each result).

    .EXAMPLE
        Get-XdrCloudAppsDiscoveredApp -Metadata
        Retrieves discovered apps metadata including filter options.

    .EXAMPLE
        Get-XdrCloudAppsDiscoveredApp -StreamId "64a75731967076e7d6bd00ea"
        Retrieves discovered apps from the specified stream.

    .EXAMPLE
        Get-XdrCloudAppsDiscoveredApp -StreamName "Defender*"
        Retrieves discovered apps from streams matching the wildcard pattern.

    .EXAMPLE
        Get-XdrCloudAppsDiscoveredApp -StreamName "Defender-managed endpoints" -Timeframe 7
        Retrieves discovered apps from the last 7 days from a specific stream.

    .EXAMPLE
        Get-XdrCloudAppsDiscoveredApp -Limit 100 -SortField "users" -SortDirection "desc"
        Retrieves top 100 discovered apps from all streams sorted by number of users.

    .EXAMPLE
        Get-XdrCloudAppsConfigurationDiscoveryStream | Get-XdrCloudAppsDiscoveredApp
        Retrieves discovered apps from all streams via pipeline.

    .OUTPUTS
        XdrCloudAppsDiscoveredApp[]
        Returns an array of discovered app objects containing app details including
        name, category, risk score, traffic data, user counts, and more.
        When querying multiple streams, includes StreamId and StreamName properties.

        XdrCloudAppsDiscoveredAppMetadata
        When -Metadata is specified, returns metadata for discovered apps queries.

        XdrCloudAppsConfigurationDiscoveryStream[]
        When -ListStreams is specified, returns available discovery streams.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Metadata is a common term in the API naming convention')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'ListStreams', Justification = 'Parameter used for parameter set selection')]
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(ParameterSetName = 'Metadata', Mandatory = $true)]
        [switch]$Metadata,

        [Parameter(ParameterSetName = 'ListStreams', Mandatory = $true)]
        [switch]$ListStreams,

        [Parameter(ParameterSetName = 'Default', ValueFromPipelineByPropertyName = $true)]
        [Alias('_id')]
        [string]$StreamId,

        [Parameter(ParameterSetName = 'Default')]
        [SupportsWildcards()]
        [string]$StreamName,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 365)]
        [int]$Timeframe = 30,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 1000)]
        [int]$Limit = 20,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Skip = 0,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("name", "score", "traffic", "upload", "transactions", "users", "ips", "machines", "lastSeen")]
        [string]$SortField = "traffic",

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("asc", "desc")]
        [string]$SortDirection = "desc",

        [Parameter(ParameterSetName = 'Default')]
        [hashtable]$Filters = @{},

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Handle ListStreams parameter set
        if ($PSCmdlet.ParameterSetName -eq 'ListStreams') {
            return Get-XdrCloudAppsConfigurationDiscoveryStream -Force:$Force
        }

        if ($Metadata) {
            $CacheKey = "XdrCloudAppsDiscoveredAppMetadata"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps discovered app metadata"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps discovered app metadata cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/discovered_apps/metadata/"

            Write-Verbose "Retrieving Cloud Apps discovered app metadata"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = if ($null -ne $response.data) { $response.data } else { $response }
                if ($null -ne $result) {
                    $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsDiscoveredAppMetadata')
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps discovered app metadata: $_"
            }
        } else {
            # Resolve streams to query
            $resolveParams = @{ Force = $Force }
            if ($PSBoundParameters.ContainsKey('StreamId')) { $resolveParams.StreamId = $StreamId }
            if ($PSBoundParameters.ContainsKey('StreamName')) { $resolveParams.StreamName = $StreamName }

            $streamsToQuery = Get-XdrCloudAppsDiscoveryStream @resolveParams

            if (-not $streamsToQuery -or $streamsToQuery.Count -eq 0) {
                Write-Warning "No streams to query. Use -ListStreams to see available streams."
                return
            }

            $multipleStreams = $streamsToQuery.Count -gt 1

            foreach ($stream in $streamsToQuery) {
                $currentStreamId = $stream._id
                $currentStreamName = $stream.displayName

                $CacheKey = "XdrCloudAppsDiscoveredApp-$currentStreamId-$Timeframe-$Limit-$Skip-$SortField-$SortDirection"
                $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if (-not $Force -and ($null -eq $Filters -or $Filters.Count -eq 0)) {
                    if ($currentCacheValue.NotValidAfter -gt (Get-Date)) {
                        Write-Verbose "Using cached Cloud Apps discovered apps for stream '$currentStreamName'"
                        $cachedResult = $currentCacheValue.Value
                        # Add stream context if querying multiple streams
                        if ($multipleStreams) {
                            foreach ($item in $cachedResult) {
                                if (-not $item.PSObject.Properties['SourceStreamId']) {
                                    $item | Add-Member -NotePropertyName 'SourceStreamId' -NotePropertyValue $currentStreamId -Force
                                    $item | Add-Member -NotePropertyName 'SourceStreamName' -NotePropertyValue $currentStreamName -Force
                                }
                            }
                        }
                        $cachedResult
                        continue
                    }
                }
                if ($Force) {
                    Write-Verbose "Force parameter specified, bypassing cache for stream '$currentStreamName'"
                    Clear-XdrCache -CacheKey $CacheKey
                } else {
                    Write-Verbose "Cloud Apps discovered apps cache is missing or expired for stream '$currentStreamName'"
                }

                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/discovered_apps/"

                $Body = @{
                    filters           = $Filters
                    limit             = $Limit
                    streamId          = $currentStreamId
                    timeframe         = $Timeframe.ToString()
                    performAsyncTotal = $false
                    skip              = $Skip
                    sortDirection     = $SortDirection
                    sortField         = $SortField
                } | ConvertTo-Json -Compress -Depth 10

                Write-Verbose "Retrieving Cloud Apps discovered apps for stream '$currentStreamName' ($currentStreamId) (Timeframe: $Timeframe days, Limit: $Limit, Skip: $Skip)"

                try {
                    $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                    $result = if ($null -ne $response.data) { $response.data } else { $response }
                    if ($null -ne $result -and $result -is [array]) {
                        foreach ($item in $result) {
                            $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsDiscoveredApp')
                            # Add stream context if querying multiple streams
                            if ($multipleStreams) {
                                $item | Add-Member -NotePropertyName 'SourceStreamId' -NotePropertyValue $currentStreamId -Force
                                $item | Add-Member -NotePropertyName 'SourceStreamName' -NotePropertyValue $currentStreamName -Force
                            }
                        }
                        # Only cache if no filters applied
                        if ($null -eq $Filters -or $Filters.Count -eq 0) {
                            Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                        }
                    }

                    # Output results (streaming to pipeline)
                    $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps discovered apps for stream '$currentStreamName' ($currentStreamId): $_"
                }
            }
        }
    }

    end {
    }
}
