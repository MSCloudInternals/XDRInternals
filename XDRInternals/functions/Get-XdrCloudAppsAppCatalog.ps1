function Get-XdrCloudAppsAppCatalog {
    <#
    .SYNOPSIS
        Retrieves cloud apps from the app catalog in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the list of cloud applications from the Microsoft Defender for Cloud Apps
        app catalog. This catalog contains thousands of cloud apps with their risk scores,
        compliance certifications, security features, and other metadata. Results can be
        filtered, sorted, and paginated.
        Use -Metadata to retrieve filter and sorting field definitions.
        Use -CountOnly to retrieve just the app count without full data.
        Use -Category to retrieve app catalog categories.
        This function includes caching support with a 5-minute TTL to reduce API calls.

    .PARAMETER Metadata
        Returns metadata about available filters and sorting options instead of apps.

    .PARAMETER CountOnly
        Returns only the count of matching apps without the full app data.

    .PARAMETER Category
        Returns app catalog categories instead of apps.

    .PARAMETER Limit
        The maximum number of results to return per request. Default is 20.

    .PARAMETER Skip
        The number of results to skip for pagination. Default is 0.

    .PARAMETER SortField
        The field to sort results by. Default is "score".
        Common values include: score, name, category, users.

    .PARAMETER SortDirection
        The sort direction. Valid values are "asc" (ascending) or "desc" (descending).
        Default is "desc".

    .PARAMETER Filters
        A hashtable of filters to apply to the query. Filter structure depends on the
        metadata available from -Metadata switch.
        Example filters:
        - @{ "category" = @{ "eq" = @(15) } } - Filter by category ID
        - @{ "score" = @{ "gte" = 8 } } - Filter apps with score >= 8

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAppCatalog
        Retrieves the first 20 cloud apps from the catalog with default sorting.

    .EXAMPLE
        Get-XdrCloudAppsAppCatalog -Metadata
        Retrieves metadata about available filters and sorting options.

    .EXAMPLE
        Get-XdrCloudAppsAppCatalog -CountOnly
        Retrieves only the total count of cloud apps in the catalog.

    .EXAMPLE
        Get-XdrCloudAppsAppCatalog -Category
        Retrieves all app catalog categories.

    .EXAMPLE
        Get-XdrCloudAppsAppCatalog -Category -SortField "name" -SortDirection "asc"
        Retrieves categories sorted alphabetically by name.

    .EXAMPLE
        Get-XdrCloudAppsAppCatalog -Limit 100 -SortField "score" -SortDirection "desc"
        Retrieves top 100 cloud apps sorted by risk score descending.

    .EXAMPLE
        Get-XdrCloudAppsAppCatalog -Skip 20 -Limit 20
        Retrieves the second page of 20 cloud apps.

    .EXAMPLE
        Get-XdrCloudAppsAppCatalog -Filters @{ "category" = @{ "eq" = @(15) } }
        Retrieves cloud apps filtered by a specific category.

    .EXAMPLE
        Get-XdrCloudAppsAppCatalog -CountOnly -Filters @{ "score" = @{ "gte" = 8 } }
        Retrieves the count of cloud apps with score >= 8.

    .EXAMPLE
        Get-XdrCloudAppsAppCatalog -Force
        Forces a fresh retrieval of cloud apps, bypassing the cache.

    .OUTPUTS
        XdrCloudAppsAppCatalog[]
        Returns an array of cloud app objects, metadata, categories, or count depending on switches.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Metadata is a common term in the API naming convention')]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(ParameterSetName = 'Metadata')]
        [switch]$Metadata,

        [Parameter(ParameterSetName = 'CountOnly')]
        [switch]$CountOnly,

        [Parameter(ParameterSetName = 'Category')]
        [switch]$Category,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(1, 1000)]
        [int]$Limit = 20,

        [Parameter(ParameterSetName = 'Default')]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Skip = 0,

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Category')]
        [string]$SortField = "score",

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Category')]
        [ValidateSet("asc", "desc")]
        [string]$SortDirection = "desc",

        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'CountOnly')]
        [Parameter(ParameterSetName = 'Category')]
        [hashtable]$Filters = @{},

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($Metadata) {
            $CacheKey = "XdrCloudAppsAppCatalogMetadata"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps app catalog metadata"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps app catalog metadata cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/app_catalog/metadata/"
            Write-Verbose "Retrieving Cloud Apps app catalog metadata"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                $result = if ($null -ne $response.data) { $response.data } else { $response }
                if ($null -ne $result) {
                    $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppCatalogMetadata')
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                }
                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps app catalog metadata: $_"
            }
        } elseif ($CountOnly) {
            $CacheKey = "XdrCloudAppsAppCatalogCount"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and ($null -eq $Filters -or $Filters.Count -eq 0)) {
                if ($currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps app catalog count"
                    return $currentCacheValue.Value
                }
            }
            if ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps app catalog count cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/app_catalog/count/"
            $Body = @{
                filters       = $Filters
                limit         = 20
                skip          = 20
                sortDirection = "desc"
                sortField     = "score"
            } | ConvertTo-Json -Compress -Depth 10

            Write-Verbose "Retrieving Cloud Apps app catalog count"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                $result = if ($null -ne $response.total) { $response.total } elseif ($null -ne $response.data) { $response.data } else { $response }
                if ($null -ne $result -and ($null -eq $Filters -or $Filters.Count -eq 0)) {
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                }
                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps app catalog count: $_"
            }
        } elseif ($Category) {
            $CacheKey = "XdrCloudAppsAppCatalogCategory-$SortField-$SortDirection"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and ($null -eq $Filters -or $Filters.Count -eq 0)) {
                if ($currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps app catalog categories"
                    return $currentCacheValue.Value
                }
            }
            if ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps app catalog categories cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/app_catalog/categories/"

            $Body = @{
                filters       = $Filters
                sortDirection = $SortDirection
                sortField     = $SortField
            } | ConvertTo-Json -Compress -Depth 10

            Write-Verbose "Retrieving Cloud Apps app catalog categories (SortField: $SortField, SortDirection: $SortDirection)"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = if ($null -ne $response.data) { $response.data } else { $response }
                if ($null -ne $result) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppCatalogCategory')
                    }
                    if ($null -eq $Filters -or $Filters.Count -eq 0) {
                        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                    }
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps app catalog categories: $_"
            }
        } else {
            $CacheKey = "XdrCloudAppsAppCatalog-$Limit-$Skip-$SortField-$SortDirection"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and ($null -eq $Filters -or $Filters.Count -eq 0)) {
                if ($currentCacheValue.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached Cloud Apps app catalog"
                    return $currentCacheValue.Value
                }
            }
            if ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Cloud Apps app catalog cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/app_catalog/"

            $Body = @{
                filters           = $Filters
                limit             = $Limit
                performAsyncTotal = $true
                skip              = $Skip
                sortDirection     = $SortDirection
                sortField         = $SortField
            } | ConvertTo-Json -Compress -Depth 10

            Write-Verbose "Retrieving Cloud Apps app catalog (Limit: $Limit, Skip: $Skip, SortField: $SortField, SortDirection: $SortDirection)"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = if ($null -ne $response.data) { $response.data } else { $response }
                if ($null -ne $result) {
                    foreach ($item in $result) {
                        $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppCatalog')
                    }
                    if ($null -eq $Filters -or $Filters.Count -eq 0) {
                        Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                    }
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve Cloud Apps app catalog: $_"
            }
        }
    }

    end {
    }
}
