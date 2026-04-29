function Get-XdrCloudAppsDiscovery {
    <#
    .SYNOPSIS
        Retrieves Cloud Discovery data from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets Cloud Discovery data from Microsoft Defender for Cloud Apps. This consolidated
        cmdlet provides access to discovery data types including categories, entities,
        top rankings, locations, constants, unsanctioned apps, and user deanonymization
        through a single interface. This function includes caching support to reduce API calls.

        When no StreamId or StreamName is specified for types that require streams, queries
        ALL available discovery streams and includes StreamId/StreamName properties on each result.

    .PARAMETER Type
        The type of discovery data to retrieve. Valid values are:
        - Category: App category definitions (no StreamId required)
        - CategoryStat: Category statistics with traffic/user data
        - Constant: Discovery constants and enumerations (no StreamId required)
        - Entity: Entities (IP, Machine, User, Resource) - use with -EntityType
        - Location: Discovery service locations (no StreamId required)
        - Top: Top apps, categories, or entities - use with -TopType
        - UnsanctionedApp: Apps marked as unsanctioned/blocked

    .PARAMETER ListStreams
        When specified, lists all available discovery streams. Useful for discovering
        stream IDs and names before querying data.

    .PARAMETER DeanonymizeUser
        When specified, deanonymizes Cloud Discovery usernames using the provided
        justification text.

    .PARAMETER Usernames
        One or more anonymized Cloud Discovery usernames to deanonymize.

    .PARAMETER Justification
        Required justification for deanonymizing Cloud Discovery usernames.

    .PARAMETER StreamId
        The ID of the discovery stream to query. If not specified for types that require it,
        queries all available streams.
        Accepts pipeline input from Get-XdrCloudAppsConfiguration -Type DiscoveryStream via the _id property.

    .PARAMETER StreamName
        The name of the discovery stream to query. Supports wildcards (e.g., "Defender*").
        If not specified along with StreamId, queries all available streams for types that require it.

    .PARAMETER EntityType
        Required when Type is Entity. Specifies the entity type to retrieve.
        Valid values are: IP, Machine, User, Resource

    .PARAMETER TopType
        Required when Type is Top. Specifies what top data to retrieve.
        Valid values are: App, Category, Entity (use with -TopEntityField)

    .PARAMETER TopEntityField
        Required when Type is Top and TopType is Entity. Specifies the entity field.
        Valid values are: users, machines, ipAddresses

    .PARAMETER Timeframe
        The number of days to include in the results. Default is 30 days.
        Applies to CategoryStat, Entity, Top, and UnsanctionedApp types.

    .PARAMETER AppId
        Optional app ID to filter entities by a specific application.
        Only applies to Entity type (not Resource EntityType).

    .PARAMETER Limit
        Maximum number of results to return. Applies to Entity and Top types.

    .PARAMETER Skip
        Number of results to skip for pagination. Applies to Entity type.

    .PARAMETER Offset
        Number of results to skip for pagination. Applies to Top type.

    .PARAMETER SortField
        The field to sort results by. Applies to Entity type. Default is "lastSeen".

    .PARAMETER SortDirection
        The sort direction. Valid values are "asc" or "desc". Default is "desc".

    .PARAMETER Filters
        A hashtable of filters to apply to the query. Applies to Entity type.

    .PARAMETER CategoryFilter
        Filter top apps to a specific category. Only applies to Top type with TopType App.

    .PARAMETER Metric
        The metric used to rank results. Valid values are traffic, users, transactions, upload.
        Applies to Top type with TopType App or Category. Default is traffic.

    .PARAMETER LocationType
        The type of location to retrieve. Valid values are "hq", "branch", or "".
        Only applies to Location type. Default is "hq".

    .PARAMETER Search
        A search string to filter locations. Only applies to Location type.

    .PARAMETER LocationId
        A specific location ID to retrieve. Only applies to Location type.

    .PARAMETER ExcludeSanctioned
        Excludes sanctioned apps. Only applies to Top type with TopType Category.

    .PARAMETER ExcludeUnsanctioned
        Excludes unsanctioned apps. Only applies to Top type with TopType Category.

    .PARAMETER ExcludeOther
        Excludes apps with no sanction status. Only applies to Top type with TopType Category.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -ListStreams
        Lists all available discovery streams.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -DeanonymizeUser -Usernames "User_aaaaaabbbbb=" -Justification "Incident response investigation"
        Deanonymizes a Cloud Discovery username.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -Type Category
        Retrieves all app category definitions.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -Type Constant
        Retrieves discovery constants and enumerations.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -Type Location -LocationType branch
        Retrieves branch office locations.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -Type CategoryStat
        Retrieves category statistics from ALL streams (includes stream context on results).

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -Type CategoryStat -StreamName "Defender*"
        Retrieves category statistics from streams matching the wildcard pattern.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -Type Entity -EntityType IP
        Retrieves discovered IP addresses from ALL streams.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -Type Entity -StreamId "64a75731967076e7d6bd00ea" -EntityType User -Limit 50
        Retrieves up to 50 discovered users from a specific stream.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -Type Top -TopType App
        Retrieves top discovered apps from ALL streams.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -Type Top -StreamName "Defender-managed endpoints" -TopType Entity -TopEntityField users
        Retrieves top users by app usage from a specific stream.

    .EXAMPLE
        Get-XdrCloudAppsDiscovery -Type UnsanctionedApp
        Retrieves apps marked as unsanctioned from ALL streams.

    .EXAMPLE
        Get-XdrCloudAppsConfiguration -Type DiscoveryStream | Get-XdrCloudAppsDiscovery -Type Entity -EntityType Machine
        Retrieves discovered machines from all streams via pipeline.

    .OUTPUTS
        Returns discovery data objects based on the Type parameter. Each type returns
        appropriately typed objects (XdrCloudAppsDiscoveryCategory, XdrCloudAppsDiscoveryEntity, etc.)
        When querying multiple streams, includes SourceStreamId and SourceStreamName properties.

        XdrCloudAppsConfigurationDiscoveryStream[]
        When -ListStreams is specified, returns available discovery streams.

        XdrCloudAppsDiscoveryDeanonymizedUser[]
        When -DeanonymizeUser is specified, returns deanonymized Cloud Discovery usernames.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'ListStreams', Justification = 'Parameter used for parameter set selection')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'DeanonymizeUser', Justification = 'Parameter used for parameter set selection')]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(ParameterSetName = 'Default', Mandatory = $true)]
        [ValidateSet("Category", "CategoryStat", "Constant", "Entity", "Location", "Top", "UnsanctionedApp")]
        [string]$Type,

        [Parameter(ParameterSetName = 'ListStreams', Mandatory = $true)]
        [switch]$ListStreams,

        [Parameter(ParameterSetName = 'DeanonymizeUser', Mandatory = $true)]
        [switch]$DeanonymizeUser,

        [Parameter(ParameterSetName = 'DeanonymizeUser', Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Username')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Usernames,

        [Parameter(ParameterSetName = 'DeanonymizeUser', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Justification,

        [Parameter(ParameterSetName = 'Default', ValueFromPipelineByPropertyName = $true)]
        [Alias('_id')]
        [string]$StreamId,

        [Parameter(ParameterSetName = 'Default')]
        [SupportsWildcards()]
        [string]$StreamName,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("IP", "Machine", "User", "Resource")]
        [string]$EntityType,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("App", "Category", "Entity")]
        [string]$TopType,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("users", "machines", "ipAddresses")]
        [string]$TopEntityField,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 365)]
        [int]$Timeframe = 30,

        [Parameter(ParameterSetName = 'Default')]
        [int]$AppId,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 1000)]
        [int]$Limit,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Skip = 0,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Offset = 0,

        [Parameter(ParameterSetName = 'Default')]
        [string]$SortField = "lastSeen",

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("asc", "desc")]
        [string]$SortDirection = "desc",

        [Parameter(ParameterSetName = 'Default')]
        [hashtable]$Filters = @{},

        [Parameter(ParameterSetName = 'Default')]
        [string]$CategoryFilter = "all",

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("traffic", "users", "transactions", "upload")]
        [string]$Metric = "traffic",

        [Parameter(ParameterSetName = 'Default')]
        [ValidateSet("hq", "branch", "")]
        [string]$LocationType = "hq",

        [Parameter(ParameterSetName = 'Default')]
        [string]$Search = "",

        [Parameter(ParameterSetName = 'Default')]
        [string]$LocationId = "",

        [Parameter(ParameterSetName = 'Default')]
        [switch]$ExcludeSanctioned,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$ExcludeUnsanctioned,

        [Parameter(ParameterSetName = 'Default')]
        [switch]$ExcludeOther,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
        $usernamesToDeanonymize = [System.Collections.Generic.List[string]]::new()

        if ($PSCmdlet.ParameterSetName -eq 'Default') {
            # Validate EntityType is provided when Type is Entity
            if ($Type -eq "Entity" -and -not $PSBoundParameters.ContainsKey('EntityType')) {
                throw "The -EntityType parameter is required when -Type is 'Entity'. Valid values are: IP, Machine, User, Resource"
            }

            # Validate TopType is provided when Type is Top
            if ($Type -eq "Top" -and -not $PSBoundParameters.ContainsKey('TopType')) {
                throw "The -TopType parameter is required when -Type is 'Top'. Valid values are: App, Category, Entity"
            }

            # Validate TopEntityField is provided when TopType is Entity
            if ($Type -eq "Top" -and $TopType -eq "Entity" -and -not $PSBoundParameters.ContainsKey('TopEntityField')) {
                throw "The -TopEntityField parameter is required when -TopType is 'Entity'. Valid values are: users, machines, ipAddresses"
            }
        }
    }

    process {
        # Handle ListStreams
        if ($PSCmdlet.ParameterSetName -eq 'ListStreams') {
            return Get-XdrCloudAppsDiscoveryStream -Force:$Force
        }

        if ($PSCmdlet.ParameterSetName -eq 'DeanonymizeUser') {
            foreach ($username in $Usernames) {
                $usernamesToDeanonymize.Add($username)
            }
            return
        }

        # Helper function to add stream context to results
        function Add-StreamContext {
            param ($Items, $StreamIdValue, $StreamNameValue, $AddContext)
            if ($AddContext -and $Items) {
                foreach ($item in $Items) {
                    $item | Add-Member -NotePropertyName 'SourceStreamId' -NotePropertyValue $StreamIdValue -Force
                    $item | Add-Member -NotePropertyName 'SourceStreamName' -NotePropertyValue $StreamNameValue -Force
                }
            }
            return $Items
        }

        switch ($Type) {
            "Category" {
                $CacheKey = "XdrCloudAppsDiscoveryCategory"
                $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps discovery categories"
                    return $currentCacheValue.Value
                } elseif ($Force) {
                    Write-Verbose "Force parameter specified, bypassing cache"
                    Clear-XdrCache -CacheKey $CacheKey
                } else {
                    Write-Verbose "Cloud Apps discovery categories cache is missing or expired"
                }

                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/categories/"
                Write-Verbose "Retrieving Cloud Apps discovery categories"

                try {
                    $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $result = if ($null -ne $response.data) { $response.data } else { $response }
                    if ($null -ne $result) {
                        foreach ($item in $result) {
                            $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsDiscoveryCategory')
                        }
                        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                    }
                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps discovery categories: $_"
                }
            }

            "CategoryStat" {
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

                    $CacheKey = "XdrCloudAppsDiscoveryCategoryStat_${currentStreamId}_${Timeframe}"
                    $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                    if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                        Write-Verbose "Using cached Cloud Apps discovery category statistics for stream '$currentStreamName'"
                        $cachedResult = $currentCacheValue.Value
                        Add-StreamContext -Items $cachedResult -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                        $cachedResult
                        continue
                    } elseif ($Force) {
                        Write-Verbose "Force parameter specified, bypassing cache for stream '$currentStreamName'"
                        Clear-XdrCache -CacheKey $CacheKey
                    } else {
                        Write-Verbose "Cloud Apps discovery category statistics cache is missing or expired for stream '$currentStreamName'"
                    }

                    $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/category_stats/?streamId=$currentStreamId&timeframe=$Timeframe"
                    Write-Verbose "Retrieving Cloud Apps discovery category statistics for stream '$currentStreamName' ($currentStreamId)"

                    try {
                        $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                        $result = if ($null -ne $response.data) { $response.data } else { $response }
                        if ($null -ne $result) {
                            foreach ($item in $result) {
                                $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsDiscoveryCategoryStat')
                            }
                            Add-StreamContext -Items $result -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                            Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                        }
                        $result
                    } catch {
                        Write-Error "Failed to retrieve Cloud Apps discovery category statistics for stream '$currentStreamName': $_"
                    }
                }
            }

            "Constant" {
                $CacheKey = "XdrCloudAppsDiscoveryConstant"
                $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps discovery constants"
                    return $currentCacheValue.Value
                } elseif ($Force) {
                    Write-Verbose "Force parameter specified, bypassing cache"
                    Clear-XdrCache -CacheKey $CacheKey
                } else {
                    Write-Verbose "Cloud Apps discovery constants cache is missing or expired"
                }

                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/constants/"
                Write-Verbose "Retrieving Cloud Apps discovery constants"

                try {
                    $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $result = if ($null -ne $response.data) { $response.data } else { $response }
                    if ($null -ne $result) {
                        $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsDiscoveryConstant')
                        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                    }
                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps discovery constants: $_"
                }
            }

            "Entity" {
                $entityEndpoints = @{
                    "IP"       = "ips"
                    "Machine"  = "machines"
                    "User"     = "users"
                    "Resource" = "resources"
                }
                $endpoint = $entityEndpoints[$EntityType]

                # Set default Timeframe for Entity if needed
                if (-not $PSBoundParameters.ContainsKey('Timeframe')) {
                    $Timeframe = if ($EntityType -eq "Resource") { 30 } else { 90 }
                }

                # Set default Limit if not specified
                if (-not $PSBoundParameters.ContainsKey('Limit')) {
                    $Limit = if ($EntityType -eq "Resource") { 20 } else { 100 }
                }

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

                    $CacheKey = "XdrCloudAppsDiscovery${EntityType}-$currentStreamId-$Timeframe-$AppId-$Limit-$Skip-$SortField-$SortDirection"
                    $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                    if (-not $Force -and ($null -eq $Filters -or $Filters.Count -eq 0)) {
                        if ($currentCacheValue.NotValidAfter -gt (Get-Date)) {
                            Write-Verbose "Using cached Cloud Apps discovery $EntityType entities for stream '$currentStreamName'"
                            $cachedResult = $currentCacheValue.Value
                            Add-StreamContext -Items $cachedResult -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                            $cachedResult
                            continue
                        }
                    }
                    if ($Force) {
                        Write-Verbose "Force parameter specified, bypassing cache for stream '$currentStreamName'"
                        Clear-XdrCache -CacheKey $CacheKey
                    } else {
                        Write-Verbose "Cloud Apps discovery $EntityType cache is missing or expired for stream '$currentStreamName'"
                    }

                    $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/$endpoint/"

                    $bodyObj = @{
                        filters           = $Filters
                        limit             = $Limit
                        performAsyncTotal = if ($EntityType -eq "Resource") { $true } else { $false }
                        skip              = $Skip
                        sortDirection     = $SortDirection
                        sortField         = $SortField
                        streamId          = $currentStreamId
                        timeframe         = $Timeframe.ToString()
                    }

                    if ($EntityType -ne "Resource") {
                        if ($PSBoundParameters.ContainsKey('AppId')) {
                            $bodyObj.appId = $AppId
                        } else {
                            $bodyObj.appId = $null
                        }
                    }

                    $Body = $bodyObj | ConvertTo-Json -Compress -Depth 10
                    Write-Verbose "Retrieving Cloud Apps discovery ${EntityType}s for stream '$currentStreamName' ($currentStreamId)"

                    try {
                        $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                        $result = if ($null -ne $response.data) { $response.data } else { $response }
                        if ($null -ne $result) {
                            foreach ($item in $result) {
                                $item.PSObject.TypeNames.Insert(0, "XdrCloudAppsDiscovery$EntityType")
                            }
                            Add-StreamContext -Items $result -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                            if ($null -eq $Filters -or $Filters.Count -eq 0) {
                                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                            }
                        }
                        $result
                    } catch {
                        Write-Error "Failed to retrieve Cloud Apps discovery ${EntityType}s for stream '$currentStreamName': $_"
                    }
                }
            }

            "Location" {
                $CacheKey = "XdrCloudAppsDiscoveryLocation_${LocationType}_${Search}"
                $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps discovery locations"
                    return $currentCacheValue.Value
                } elseif ($Force) {
                    Write-Verbose "Force parameter specified, bypassing cache"
                    Clear-XdrCache -CacheKey $CacheKey
                } else {
                    Write-Verbose "Cloud Apps discovery locations cache is missing or expired"
                }

                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/get_locations/?locationId=$LocationId&locationType=$LocationType&search=$Search"
                Write-Verbose "Retrieving Cloud Apps discovery locations"

                try {
                    $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    $result = if ($null -ne $response.data) { $response.data } else { $response }
                    if ($null -ne $result) {
                        foreach ($item in $result) {
                            $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsDiscoveryLocation')
                        }
                        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                    }
                    return $result
                } catch {
                    Write-Error "Failed to retrieve Cloud Apps discovery locations: $_"
                }
            }

            "Top" {
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

                switch ($TopType) {
                    "App" {
                        if (-not $PSBoundParameters.ContainsKey('Limit')) { $Limit = 15 }

                        foreach ($stream in $streamsToQuery) {
                            $currentStreamId = $stream._id
                            $currentStreamName = $stream.displayName

                            $CacheKey = "XdrCloudAppsDiscoveryTopApp_${currentStreamId}_${Timeframe}_${CategoryFilter}_${Metric}_${Limit}_${Offset}"
                            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                                Write-Verbose "Using cached Cloud Apps discovery top apps for stream '$currentStreamName'"
                                $cachedResult = $currentCacheValue.Value
                                Add-StreamContext -Items $cachedResult -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                                $cachedResult
                                continue
                            } elseif ($Force) {
                                Write-Verbose "Force parameter specified, bypassing cache for stream '$currentStreamName'"
                                Clear-XdrCache -CacheKey $CacheKey
                            } else {
                                Write-Verbose "Cloud Apps discovery top apps cache is missing or expired for stream '$currentStreamName'"
                            }

                            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/top_apps/?streamId=$currentStreamId&timeframe=$Timeframe&category=$CategoryFilter&metric=$Metric&limit=$Limit&offset=$Offset"
                            Write-Verbose "Retrieving Cloud Apps discovery top apps for stream '$currentStreamName' ($currentStreamId)"

                            try {
                                $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                                $result = if ($null -ne $response.data) { $response.data } else { $response }
                                if ($null -ne $result) {
                                    foreach ($item in $result) {
                                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsDiscoveryTopApp')
                                    }
                                    Add-StreamContext -Items $result -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                                }
                                $result
                            } catch {
                                Write-Error "Failed to retrieve Cloud Apps discovery top apps for stream '$currentStreamName': $_"
                            }
                        }
                    }

                    "Category" {
                        if (-not $PSBoundParameters.ContainsKey('Limit')) { $Limit = 10 }

                        $sanctioned = if ($ExcludeSanctioned) { "false" } else { "true" }
                        $unsanctioned = if ($ExcludeUnsanctioned) { "false" } else { "true" }
                        $other = if ($ExcludeOther) { "false" } else { "true" }

                        foreach ($stream in $streamsToQuery) {
                            $currentStreamId = $stream._id
                            $currentStreamName = $stream.displayName

                            $CacheKey = "XdrCloudAppsDiscoveryTopCategory_${currentStreamId}_${Timeframe}_${Metric}_${Limit}_${Offset}"
                            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                                Write-Verbose "Using cached Cloud Apps discovery top categories for stream '$currentStreamName'"
                                $cachedResult = $currentCacheValue.Value
                                Add-StreamContext -Items $cachedResult -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                                $cachedResult
                                continue
                            } elseif ($Force) {
                                Write-Verbose "Force parameter specified, bypassing cache for stream '$currentStreamName'"
                                Clear-XdrCache -CacheKey $CacheKey
                            } else {
                                Write-Verbose "Cloud Apps discovery top categories cache is missing or expired for stream '$currentStreamName'"
                            }

                            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/top_categories/?streamId=$currentStreamId&timeframe=$Timeframe&metric=$Metric&limit=$Limit&offset=$Offset&sanctioned=$sanctioned&unsanctioned=$unsanctioned&other=$other"
                            Write-Verbose "Retrieving Cloud Apps discovery top categories for stream '$currentStreamName' ($currentStreamId)"

                            try {
                                $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                                $result = if ($null -ne $response.data) { $response.data } else { $response }
                                if ($null -ne $result) {
                                    foreach ($item in $result) {
                                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsDiscoveryTopCategory')
                                    }
                                    Add-StreamContext -Items $result -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                                }
                                $result
                            } catch {
                                Write-Error "Failed to retrieve Cloud Apps discovery top categories for stream '$currentStreamName': $_"
                            }
                        }
                    }

                    "Entity" {
                        foreach ($stream in $streamsToQuery) {
                            $currentStreamId = $stream._id
                            $currentStreamName = $stream.displayName

                            $CacheKey = "XdrCloudAppsDiscoveryTopEntity_${currentStreamId}_${TopEntityField}_${Timeframe}"
                            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                                Write-Verbose "Using cached Cloud Apps discovery top entities ($TopEntityField) for stream '$currentStreamName'"
                                $cachedResult = $currentCacheValue.Value
                                Add-StreamContext -Items $cachedResult -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                                $cachedResult
                                continue
                            } elseif ($Force) {
                                Write-Verbose "Force parameter specified, bypassing cache for stream '$currentStreamName'"
                                Clear-XdrCache -CacheKey $CacheKey
                            } else {
                                Write-Verbose "Cloud Apps discovery top entities cache is missing or expired for stream '$currentStreamName'"
                            }

                            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/top_entities/?field=$TopEntityField&streamId=$currentStreamId&timeframe=$Timeframe"
                            Write-Verbose "Retrieving Cloud Apps discovery top entities ($TopEntityField) for stream '$currentStreamName' ($currentStreamId)"

                            try {
                                $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                                $result = if ($null -ne $response.data) { $response.data } else { $response }
                                if ($null -ne $result) {
                                    foreach ($item in $result) {
                                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsDiscoveryTopEntity')
                                    }
                                    Add-StreamContext -Items $result -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                                }
                                $result
                            } catch {
                                Write-Error "Failed to retrieve Cloud Apps discovery top entities for stream '$currentStreamName': $_"
                            }
                        }
                    }
                }
            }

            "UnsanctionedApp" {
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

                    $CacheKey = "XdrCloudAppsDiscoveryUnsanctionedApp_${currentStreamId}_${Timeframe}"
                    $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                    if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                        Write-Verbose "Using cached Cloud Apps discovery unsanctioned apps for stream '$currentStreamName'"
                        $cachedResult = $currentCacheValue.Value
                        Add-StreamContext -Items $cachedResult -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                        $cachedResult
                        continue
                    } elseif ($Force) {
                        Write-Verbose "Force parameter specified, bypassing cache for stream '$currentStreamName'"
                        Clear-XdrCache -CacheKey $CacheKey
                    } else {
                        Write-Verbose "Cloud Apps discovery unsanctioned apps cache is missing or expired for stream '$currentStreamName'"
                    }

                    $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/discovery/get_unsanctioned_apps/?streamId=$currentStreamId&timeframe=$Timeframe"
                    Write-Verbose "Retrieving Cloud Apps discovery unsanctioned apps for stream '$currentStreamName' ($currentStreamId)"

                    try {
                        $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                        $result = if ($null -ne $response.data) { $response.data } else { $response }
                        if ($null -ne $result) {
                            foreach ($item in $result) {
                                $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsDiscoveryUnsanctionedApp')
                            }
                            Add-StreamContext -Items $result -StreamIdValue $currentStreamId -StreamNameValue $currentStreamName -AddContext $multipleStreams
                            Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                        }
                        $result
                    } catch {
                        Write-Error "Failed to retrieve Cloud Apps discovery unsanctioned apps for stream '$currentStreamName': $_"
                    }
                }
            }
        }
    }

    end {
        if ($PSCmdlet.ParameterSetName -eq 'DeanonymizeUser') {
            if ($usernamesToDeanonymize.Count -eq 0) {
                return
            }

            # Observed Cloud Apps deanonymization API value for user identities.
            # The current public cmdlet surface intentionally supports users only.
            $userEntityType = 1

            $body = @{
                usernames     = @($usernamesToDeanonymize)
                justification = $Justification
                entityType    = $userEntityType
            }

            return Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/deanonymize_entity_names/' -Method Post -Body $body -TypeName 'XdrCloudAppsDiscoveryDeanonymizedUser' -Force:$Force
        }
    }
}

