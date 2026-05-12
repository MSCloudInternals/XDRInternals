function Get-XdrCloudAppsApp {
    <#
    .SYNOPSIS
        Retrieves app-focused Microsoft Defender for Cloud Apps data.

    .DESCRIPTION
        Retrieves app catalog, discovered app, OAuth app permission, file, service,
        and tag data through one grouped command.

    .PARAMETER Type
        App data surface to retrieve. Defaults to Discovered.

    .PARAMETER Metadata
        Retrieves metadata for surfaces that expose filter or table metadata.

    .PARAMETER CountOnly
        Retrieves only a count for surfaces that expose count endpoints.

    .PARAMETER Raw
        Returns the API response shape instead of typed admin-friendly objects.

    .PARAMETER AppId
        App identifier used by app-specific data types.

    .PARAMETER StreamId
        Discovery stream identifier for discovered app queries.

    .PARAMETER StreamName
        Discovery stream display name pattern for discovered app queries.

    .PARAMETER Timeframe
        Discovery timeframe in days.

    .PARAMETER Limit
        Maximum number of records to request.

    .PARAMETER Skip
        Number of records to skip.

    .PARAMETER SortField
        Field used to sort grid results.

    .PARAMETER SortDirection
        Sort direction for grid results.

    .PARAMETER Filters
        Cloud Apps filters to include in the query body.

    .PARAMETER Force
        Bypasses cache-backed requests.

    .EXAMPLE
        Get-XdrCloudAppsApp -Type Discovered -Limit 50

        Retrieves discovered cloud apps.

    .EXAMPLE
        Get-XdrCloudAppsApp -Type OAuth -Metadata

        Retrieves OAuth app permission metadata.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter()]
        [ValidateSet('Discovered', 'Catalog', 'CatalogCategory', 'OAuth', 'File', 'Service', 'Tag')]
        [string]$Type = 'Discovered',

        [Parameter()]
        [switch]$Metadata,

        [Parameter()]
        [switch]$CountOnly,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('_id', 'Id')]
        [string]$AppId,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('Stream')]
        [string]$StreamId,

        [Parameter()]
        [SupportsWildcards()]
        [string]$StreamName,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$Timeframe = 30,

        [Parameter()]
        [ValidateRange(1, 5000)]
        [int]$Limit = 100,

        [Parameter()]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Skip = 0,

        [Parameter()]
        [string]$SortField = 'score',

        [Parameter()]
        [ValidateSet('asc', 'desc')]
        [string]$SortDirection = 'desc',

        [Parameter()]
        [hashtable]$Filters = @{},

        [Parameter()]
        [switch]$Raw,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $body = @{
            filters           = $Filters
            limit             = $Limit
            performAsyncTotal = $true
            skip              = $Skip
            sortDirection     = $SortDirection
            sortField         = $SortField
        }

        switch ($Type) {
            'Service' {
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/services/' -TypeName 'XdrCloudAppsService' -CacheKey 'XdrCloudAppsService' -TTLMinutes 30 -Raw:$Raw -Force:$Force
            }
            'Tag' {
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/tags/' -TypeName 'XdrCloudAppsTag' -CacheKey 'XdrCloudAppsTag' -TTLMinutes 30 -Raw:$Raw -Force:$Force
            }
            'OAuth' {
                if ($Metadata) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/app_permissions/metadata/' -TypeName 'XdrCloudAppsOAuthAppMetadata' -CacheKey 'XdrCloudAppsOAuthAppMetadata' -TTLMinutes 15 -Raw:$Raw -Force:$Force
                    return
                }
                if ($CountOnly) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/app_permissions/count/' -Method Post -Body @{ filters = $Filters } -Raw -Force:$Force
                    return
                }
                $body.sortField = if ($PSBoundParameters.ContainsKey('SortField')) { $SortField } else { 'userCount' }
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/app_permissions/' -Method Post -Body $body -TypeName 'XdrCloudAppsOAuthApp' -CacheKey "XdrCloudAppsOAuthApp-$Limit-$Skip-$($body.sortField)-$SortDirection-$(($Filters | ConvertTo-Json -Compress))" -Raw:$Raw -Force:$Force
            }
            'Catalog' {
                if ($Metadata) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/app_catalog/metadata/' -TypeName 'XdrCloudAppsAppCatalogMetadata' -CacheKey 'XdrCloudAppsAppCatalogMetadata' -TTLMinutes 15 -Raw:$Raw -Force:$Force
                    return
                }
                if ($CountOnly) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/app_catalog/count/' -Method Post -Body $body -Raw -Force:$Force
                    return
                }
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/app_catalog/' -Method Post -Body $body -TypeName 'XdrCloudAppsAppCatalog' -CacheKey "XdrCloudAppsAppCatalog-$Limit-$Skip-$SortField-$SortDirection-$(($Filters | ConvertTo-Json -Compress))" -Raw:$Raw -Force:$Force
            }
            'CatalogCategory' {
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/app_catalog/categories/' -Method Post -Body @{ filters = $Filters; sortDirection = $SortDirection; sortField = $SortField } -TypeName 'XdrCloudAppsAppCatalogCategory' -CacheKey "XdrCloudAppsAppCatalogCategory-$SortField-$SortDirection-$(($Filters | ConvertTo-Json -Compress))" -Raw:$Raw -Force:$Force
            }
            'Discovered' {
                if ($Metadata) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/discovered_apps/metadata/' -TypeName 'XdrCloudAppsDiscoveredAppMetadata' -CacheKey 'XdrCloudAppsDiscoveredAppMetadata' -TTLMinutes 15 -Raw:$Raw -Force:$Force
                    return
                }
                if ($CountOnly) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/discovered_apps/count/' -Method Post -Body $body -Raw -Force:$Force
                    return
                }

                $resolveParams = @{ Force = $Force }
                if ($StreamId) { $resolveParams.StreamId = $StreamId }
                if ($StreamName) { $resolveParams.StreamName = $StreamName }
                $streamsToQuery = Get-XdrCloudAppsDiscoveryStream @resolveParams
                if (-not $streamsToQuery) {
                    Write-Warning 'No discovery streams were found for this query.'
                    return
                }

                foreach ($stream in $streamsToQuery) {
                    $queryBody = $body.Clone()
                    $queryBody.streamId = $stream._id
                    $queryBody.timeframe = [string]$Timeframe
                    $result = Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/discovery/discovered_apps/' -Method Post -Body $queryBody -TypeName 'XdrCloudAppsDiscoveredApp' -Raw:$Raw -Force:$Force
                    if (-not $Raw) {
                        foreach ($item in @($result)) {
                            if ($streamsToQuery.Count -gt 1) {
                                $item | Add-Member -NotePropertyName SourceStreamId -NotePropertyValue $stream._id -Force
                                $item | Add-Member -NotePropertyName SourceStreamName -NotePropertyValue $stream.displayName -Force
                            }
                            $item
                        }
                    }
                    else {
                        $result
                    }
                }
            }
            'File' {
                if ($Metadata) {
                    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/files/metadata/' -TypeName 'XdrCloudAppsFileMetadata' -CacheKey 'XdrCloudAppsFileMetadata' -TTLMinutes 15 -Raw:$Raw -Force:$Force
                    return
                }
                $fileBody = $body.Clone()
                if (-not $PSBoundParameters.ContainsKey('SortField')) {
                    $fileBody.sortField = 'modifiedDate'
                }
                if ($AppId) {
                    $fileBody.filters = $Filters.Clone()
                    $fileBody.filters.appId = @{ eq = @($AppId) }
                }
                Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/files/' -Method Post -Body $fileBody -TypeName 'XdrCloudAppsFile' -Raw:$Raw -Force:$Force
            }
        }
    }
}
