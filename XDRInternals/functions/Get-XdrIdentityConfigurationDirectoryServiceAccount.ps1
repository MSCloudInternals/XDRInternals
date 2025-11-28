function Get-XdrIdentityConfigurationDirectoryServiceAccount {
    <#
    .SYNOPSIS
        Retrieves directory service accounts for Microsoft Defender for Identity.

    .DESCRIPTION
        Gets the directory service accounts (gMSA) configured for Microsoft Defender for Identity sensors.
        These accounts are used by MDI sensors to query Active Directory.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER PageSize
        The number of accounts to retrieve per page. Default is 20.

    .PARAMETER Skip
        The number of accounts to skip. Used for pagination. Default is 0.

    .PARAMETER All
        Retrieves all directory service accounts by automatically paging through all results.
        When specified, PageSize and Skip parameters are ignored.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityConfigurationDirectoryServiceAccount
        Retrieves the first 20 directory service accounts using cached data if available.

    .EXAMPLE
        Get-XdrIdentityConfigurationDirectoryServiceAccount -PageSize 50 -Skip 20
        Retrieves 50 accounts, skipping the first 20 (for pagination).

    .EXAMPLE
        Get-XdrIdentityConfigurationDirectoryServiceAccount -All
        Retrieves all directory service accounts by automatically paging through all results.

    .EXAMPLE
        Get-XdrIdentityConfigurationDirectoryServiceAccount -Force
        Forces a fresh retrieval of directory service accounts, bypassing the cache.

    .EXAMPLE
        Get-XdrIdentityConfigurationDirectoryServiceAccount -All |
            Where-Object { $_.IsGroupManagedServiceAccount -eq $true }
        Retrieves all directory service accounts and filters for gMSAs.

    .OUTPUTS
        Object[]
        Returns an array of directory service account objects containing:
        - Id: User Principal Name of the account
        - AccountName: Account name without domain
        - DomainDnsName: Fully qualified domain name
        - AccountPassword: Always null for gMSA accounts
        - IsGroupManagedServiceAccount: Boolean indicating if account is a gMSA
        - IsSingleLabelAccountDomainName: Boolean for single-label domain configuration
    #>
    [OutputType([object[]])]
    [CmdletBinding(DefaultParameterSetName = 'Paged')]
    param (
        [Parameter(ParameterSetName = 'Paged')]
        [ValidateRange(1, 100)]
        [int]$PageSize = 20,

        [Parameter(ParameterSetName = 'Paged')]
        [int]$Skip = 0,

        [Parameter(ParameterSetName = 'All', Mandatory)]
        [switch]$All,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # If All switch is specified, retrieve all accounts through pagination
        if ($All) {
            Write-Verbose "Retrieving all directory service accounts with pagination"

            # Use maximum page size for efficiency
            $pageSizeForAll = 100
            $allResults = [System.Collections.Generic.List[object]]::new()
            $currentSkip = 0
            $totalCount = $null

            do {
                Write-Verbose "Retrieving page: Skip=$currentSkip, PageSize=$pageSizeForAll"

                try {
                    $Uri = "https://security.microsoft.com/apiproxy/aatp/odata/directoryServices?`$count=true&`$top=$pageSizeForAll&`$skip=$currentSkip"
                    $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                } catch {
                    Write-Error "Failed to retrieve directory service accounts: $_"
                    return
                }

                # Get total count from first request
                if ($null -eq $totalCount) {
                    $totalCount = $result.'@odata.count'
                    Write-Verbose "Total directory service accounts to retrieve: $totalCount"

                    if ($totalCount -eq 0) {
                        Write-Verbose "No directory service accounts found"
                        return @()
                    }
                }

                $pageData = $result.value

                if ($null -ne $pageData -and $pageData.Count -gt 0) {
                    $allResults.AddRange([array]$pageData)
                    Write-Verbose "Retrieved $($pageData.Count) directory service accounts (Total so far: $($allResults.Count))"
                }

                $currentSkip += $pageSizeForAll

                # Safety check to prevent infinite loops
                if ($null -eq $pageData -or $pageData.Count -eq 0) {
                    Write-Verbose "No more data returned, stopping pagination"
                    break
                }
            } while ($currentSkip -lt $totalCount)

            Write-Verbose "Completed retrieving all directory service accounts: $($allResults.Count) total"

            return $allResults.ToArray()
        }

        # Standard single-page retrieval with caching
        $cacheKeySuffix = "$PageSize-$Skip"
        $cacheKey = "XdrIdentityConfigurationDirectoryServiceAccount-$cacheKeySuffix"

        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity directory service accounts"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $cacheKey
        } else {
            Write-Verbose "XDR Identity directory service accounts cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/aatp/odata/directoryServices?`$count=true&`$top=$PageSize&`$skip=$Skip"
            Write-Verbose "Retrieving XDR Identity directory service accounts (PageSize: $PageSize, Skip: $Skip)"
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        } catch {
            Write-Error "Failed to retrieve directory service accounts: $_"
            return
        }

        $accounts = $result.value

        if ($null -eq $accounts) {
            $accounts = @()
        }

        Write-Verbose "Retrieved $($accounts.Count) directory service account(s)"

        Set-XdrCache -CacheKey $cacheKey -Value $accounts -TTLMinutes 30
        return $accounts
    }

    end {

    }
}
