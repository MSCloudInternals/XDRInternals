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

    .OUTPUTS
        Object
        Returns the identities data from the API.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('RepresentableName', 'AccountDomain', 'CreatedDateTime')]
        [string]$SortByField = 'RepresentableName',

        [Parameter()]
        [ValidateSet('Asc', 'Dsc')]
        [string]$SortDirection = 'Asc',

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$PageSize = 20,

        [Parameter()]
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

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
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
            Filters    = @{}
            SearchText = $SearchText
        }

        # Add IdentityProvider filter if specified
        if ($PSBoundParameters.ContainsKey('IdentityProvider')) {
            Write-Verbose "Filtering by IdentityProvider: $($IdentityProvider -join ', ')"
            # Translate EntraID to AzureActiveDirectory for API
            $translatedIdentityProvider = $IdentityProvider | ForEach-Object {
                if ($_ -eq 'EntraID') { 'AzureActiveDirectory' } else { $_ }
            }
            $body.Filters['IdentityProviders'] = @{
                has = $translatedIdentityProvider
            }
        }

        # Add IdentityEnvironment filter if specified
        if ($PSBoundParameters.ContainsKey('IdentityEnvironment')) {
            Write-Verbose "Filtering by IdentityEnvironment: $($IdentityEnvironment -join ', ')"
            # Translate EntraID to AzureActiveDirectory for API
            $translatedIdentityEnvironment = $IdentityEnvironment | ForEach-Object {
                if ($_ -eq 'EntraID') { 'AzureActiveDirectory' } else { $_ }
            }
            $body.Filters['PrimaryIdentityProvider'] = @{
                eq = $translatedIdentityEnvironment
            }
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
