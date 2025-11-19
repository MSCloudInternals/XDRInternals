function Get-XdrIdentityIdentity {
    <#
    .SYNOPSIS
        Retrieves identities from Microsoft Defender for Identity.

    .DESCRIPTION
        Gets identities from Microsoft Defender for Identity with support for pagination,
        sorting, and search filtering.
        This function includes caching support with a 10-minute TTL to reduce API calls.

    .PARAMETER SortByField
        The field to sort results by. Valid values are "RepresentableName", "AccountDomain", and "CreatedDateTime".
        Default is "RepresentableName".

    .PARAMETER SortDirection
        The sort direction. Valid values are "Asc" (ascending) and "Dsc" (descending).
        Default is "Asc".

    .PARAMETER PageSize
        The number of identities to retrieve per page. Default is 20. Maximum is 100.

    .PARAMETER Skip
        The number of identities to skip. Used for pagination. Default is 0.

    .PARAMETER SearchText
        Text to search for in identities. Only non-special characters are allowed.

    .PARAMETER IdentityProvider
        Filters identities by identity provider. Valid values are "ActiveDirectory", "EntraID", and "Hybrid".
        Multiple values can be specified.

    .PARAMETER IdentityEnvironment
        Filters identities by primary identity provider. Valid values are "ActiveDirectory", "EntraID", and "Hybrid".
        Multiple values can be specified.

    .PARAMETER All
        Retrieves all identities by automatically paging through all results.
        When specified, PageSize and Skip parameters are ignored.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityIdentity
        Retrieves the first 20 identities sorted by RepresentableName in ascending order.

    .EXAMPLE
        Get-XdrIdentityIdentity -SortByField CreatedDateTime -SortDirection Dsc
        Retrieves identities sorted by creation date in descending order (newest first).

    .EXAMPLE
        Get-XdrIdentityIdentity -PageSize 50 -Skip 100
        Retrieves 50 identities, skipping the first 100 (for pagination).

    .EXAMPLE
        Get-XdrIdentityIdentity -SearchText "admin"
        Retrieves identities matching the search text "admin".

    .EXAMPLE
        Get-XdrIdentityIdentity -SortByField AccountDomain -PageSize 100 -SearchText "contoso"
        Retrieves up to 100 identities containing "contoso", sorted by account domain.

    .EXAMPLE
        Get-XdrIdentityIdentity -IdentityProvider ActiveDirectory
        Retrieves identities from Active Directory only.

    .EXAMPLE
        Get-XdrIdentityIdentity -IdentityProvider ActiveDirectory, EntraID
        Retrieves identities from both Active Directory and Entra ID.

    .EXAMPLE
        Get-XdrIdentityIdentity -IdentityEnvironment ActiveDirectory
        Retrieves identities with Active Directory as primary identity provider.

    .EXAMPLE
        Get-XdrIdentityIdentity -IdentityEnvironment ActiveDirectory, EntraID
        Retrieves identities with Active Directory or Entra ID as primary identity provider.

    .EXAMPLE
        Get-XdrIdentityIdentity -SearchText "bob" -IdentityEnvironment ActiveDirectory
        Retrieves identities matching "bob" from Active Directory only.

    .EXAMPLE
        Get-XdrIdentityIdentity -Force
        Forces a fresh retrieval of identities, bypassing the cache.

    .EXAMPLE
        Get-XdrIdentityIdentity -All
        Retrieves all identities by automatically paging through all results.

    .EXAMPLE
        Get-XdrIdentityIdentity -All -SearchText "admin"
        Retrieves all identities matching "admin" by paging through all results.

    .OUTPUTS
        Object
        Returns the identities data from the API.
    #>
    [OutputType([System.Object[]])]
    [CmdletBinding(DefaultParameterSetName = 'Paged')]
    param (
        [Parameter()]
        [ValidateSet('RepresentableName', 'AccountDomain', 'CreatedDateTime')]
        [string]$SortByField = 'RepresentableName',

        [Parameter()]
        [ValidateSet('Asc', 'Dsc')]
        [string]$SortDirection = 'Asc',

        [Parameter(ParameterSetName = 'Paged')]
        [ValidateRange(1, 500)]
        [int]$PageSize = 20,

        [Parameter(ParameterSetName = 'Paged')]
        [int]$Skip = 0,

        [Parameter()]
        [ValidatePattern('^[a-zA-Z0-9\s]*$')]
        [string]$SearchText = '',

        [Parameter()]
        [ValidateSet('ActiveDirectory', 'EntraID', 'Hybrid')]
        [string[]]$IdentityProvider,

        [Parameter()]
        [ValidateSet('ActiveDirectory', 'EntraID', 'Hybrid')]
        [string[]]$IdentityEnvironment,

        [Parameter(ParameterSetName = 'All', Mandatory)]
        [switch]$All,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Build filters first as they're needed for caching and API calls
        $filters = @{}

        # Add IdentityProvider filter if specified
        if ($PSBoundParameters.ContainsKey('IdentityProvider')) {
            Write-Verbose "Filtering by IdentityProvider: $($IdentityProvider -join ', ')"
            # Translate EntraID to AzureActiveDirectory for API
            $translatedIdentityProvider = $IdentityProvider | ForEach-Object {
                if ($_ -eq 'EntraID') { 'AzureActiveDirectory' } else { $_ }
            }
            $filters['IdentityProviders'] = @{
                has = @($translatedIdentityProvider)
            }
        }

        # Add IdentityEnvironment filter if specified
        if ($PSBoundParameters.ContainsKey('IdentityEnvironment')) {
            Write-Verbose "Filtering by IdentityEnvironment: $($IdentityEnvironment -join ', ')"
            # Translate EntraID to AzureActiveDirectory for API
            $translatedIdentityEnvironment = $IdentityEnvironment | ForEach-Object {
                if ($_ -eq 'EntraID') { 'AzureActiveDirectory' } else { $_ }
            }
            $filters['PrimaryIdentityProvider'] = @{
                eq = @($translatedIdentityEnvironment)
            }
        }

        # If All switch is specified, retrieve all identities through pagination
        if ($All) {
            Write-Verbose "Retrieving all identities with pagination"

            # Create cache key for All parameter
            $identityProviderKey = if ($PSBoundParameters.ContainsKey('IdentityProvider')) {
                ($IdentityProvider | Sort-Object) -join '-'
            } else {
                'All'
            }
            $primaryIdentityProviderKey = if ($PSBoundParameters.ContainsKey('IdentityEnvironment')) {
                ($IdentityEnvironment | Sort-Object) -join '-'
            } else {
                'All'
            }
            $cacheKeySuffix = "All-$SortByField-$SortDirection-$SearchText-$identityProviderKey-$primaryIdentityProviderKey"
            $cacheKey = "XdrIdentityIdentity-$cacheKeySuffix"

            # Check cache first
            $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached XDR identities (All)"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $cacheKey
            } else {
                Write-Verbose "XDR identities cache (All) is missing or expired"
            }

            # Get the total count
            $totalCount = Get-XdrIdentityIdentityCount -Filters $filters -SearchText $SearchText
            Write-Verbose "Total identities to retrieve: $totalCount"

            if ($totalCount -eq 0) {
                Write-Verbose "No identities found matching the criteria"
                $emptyResult = @()
                Set-XdrCache -CacheKey $cacheKey -Value $emptyResult -TTLMinutes 5
                return $emptyResult
            }

            # Use maximum page size for efficiency
            $pageSizeForAll = 500
            $allResults = [System.Collections.Generic.List[object]]::new()
            $currentSkip = 0

            while ($currentSkip -lt $totalCount) {
                Write-Verbose "Retrieving page: Skip=$currentSkip, PageSize=$pageSizeForAll"

                # Build the request body for this page
                $body = @{
                    PageSize   = $pageSizeForAll
                    Skip       = $currentSkip
                    SortBy     = @{
                        Field     = $SortByField
                        Direction = $SortDirection
                    }
                    Filters    = $filters
                    SearchText = $SearchText
                }

                $Uri = "https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/identities"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -WebSession $script:session -Headers $script:headers
                $pageData = $result | Select-Object -ExpandProperty data

                if ($null -ne $pageData -and $pageData.Count -gt 0) {
                    $allResults.AddRange([array]$pageData)
                    Write-Verbose "Retrieved $($pageData.Count) identities (Total so far: $($allResults.Count))"
                }

                $currentSkip += $pageSizeForAll

                # Safety check to prevent infinite loops
                if ($pageData.Count -eq 0) {
                    Write-Verbose "No more data returned, stopping pagination"
                    break
                }
            }

            Write-Verbose "Completed retrieving all identities: $($allResults.Count) total"

            # Add type name for custom formatting
            foreach ($item in $allResults) {
                $item.PSObject.TypeNames.Insert(0, 'XdrIdentityIdentity')
            }

            # Cache the complete result
            $finalResult = $allResults.ToArray()
            Set-XdrCache -CacheKey $cacheKey -Value $finalResult -TTLMinutes 30

            return $finalResult
        }

        # Standard single-page retrieval with caching
        # Create cache key based on parameters
        $identityProviderKey = if ($PSBoundParameters.ContainsKey('IdentityProvider')) {
            ($IdentityProvider | Sort-Object) -join '-'
        } else {
            'All'
        }
        $primaryIdentityProviderKey = if ($PSBoundParameters.ContainsKey('IdentityEnvironment')) {
            ($IdentityEnvironment | Sort-Object) -join '-'
        } else {
            'All'
        }
        $cacheKeySuffix = "$SortByField-$SortDirection-$PageSize-$Skip-$SearchText-$identityProviderKey-$primaryIdentityProviderKey"
        $cacheKey = "XdrIdentityIdentity-$cacheKeySuffix"

        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR identities"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $cacheKey
        } else {
            Write-Verbose "XDR identities cache is missing or expired"
        }

        # Build the request body
        $body = @{
            PageSize   = $PageSize
            Skip       = $Skip
            SortBy     = @{
                Field     = $SortByField
                Direction = $SortDirection
            }
            Filters    = $filters
            SearchText = $SearchText
        }

        $Uri = "https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/identities"
        Write-Verbose "Retrieving XDR identities (SortBy: $SortByField $SortDirection, PageSize: $PageSize, Skip: $Skip, SearchText: '$SearchText', IdentityProvider: '$identityProviderKey', IdentityEnvironment: '$primaryIdentityProviderKey')"
        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -WebSession $script:session -Headers $script:headers
        $result = $result | Select-Object -ExpandProperty data

        if ($null -eq $result) {
            $result = @()
        }

        # Add type name for custom formatting
        foreach ($item in $result) {
            $item.PSObject.TypeNames.Insert(0, 'XdrIdentityIdentity')
        }

        Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 10
        return $result
    }

    end {

    }
}
