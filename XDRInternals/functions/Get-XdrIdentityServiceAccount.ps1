function Get-XdrIdentityServiceAccount {
    <#
    .SYNOPSIS
        Retrieves service accounts from Microsoft Defender for Identity.

    .DESCRIPTION
        Gets service accounts from Microsoft Defender for Identity, including account activity information.
        Supports filtering by service account type (gMSA, sMSA, User).
        This function includes caching support with a 10-minute TTL to reduce API calls.

    .PARAMETER AccountType
        Filters service accounts by type. Valid values are "gMSA", "sMSA", and "User".
        Multiple values can be specified. If not specified, all service account types are returned.

    .PARAMETER PageSize
        The number of service accounts to retrieve per page. Default is 20. Maximum is 100.

    .PARAMETER Skip
        The number of service accounts to skip. Used for pagination. Default is 0.

    .PARAMETER IncludeAccountActivity
        Whether to include account activity information. Default is $true.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityServiceAccount
        Retrieves all service accounts using cached data if available.

    .EXAMPLE
        Get-XdrIdentityServiceAccount -AccountType gMSA
        Retrieves only group Managed Service Accounts (gMSA).

    .EXAMPLE
        Get-XdrIdentityServiceAccount -AccountType sMSA, User
        Retrieves standalone Managed Service Accounts (sMSA) and User accounts.

    .EXAMPLE
        Get-XdrIdentityServiceAccount -PageSize 50 -Skip 20
        Retrieves 50 service accounts, skipping the first 20 (for pagination).

    .EXAMPLE
        Get-XdrIdentityServiceAccount -IncludeAccountActivity $false
        Retrieves service accounts without account activity information.

    .EXAMPLE
        Get-XdrIdentityServiceAccount -Force
        Forces a fresh retrieval of service accounts, bypassing the cache.

    .OUTPUTS
        Array
        Returns the ServiceAccounts array containing service account information.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('gMSA', 'sMSA', 'User')]
        [string[]]$AccountType,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$PageSize = 20,

        [Parameter()]
        [int]$Skip = 0,

        [Parameter()]
        [bool]$IncludeAccountActivity = $true,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Create cache key based on AccountType filter
        $cacheKeySuffix = if ($PSBoundParameters.ContainsKey('AccountType')) {
            ($AccountType | Sort-Object) -join '-'
        } else {
            'All'
        }
        $cacheKey = "XdrIdentityServiceAccount-$cacheKeySuffix-$PageSize-$Skip-$IncludeAccountActivity"

        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR identity service accounts (Filter: $cacheKeySuffix)"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $cacheKey
        } else {
            Write-Verbose "XDR identity service accounts cache is missing or expired (Filter: $cacheKeySuffix)"
        }

        # Build the request body
        $body = @{
            PageSize               = $PageSize
            Skip                   = $Skip
            Filters                = @{}
            IncludeAccountActivity = $IncludeAccountActivity
        }

        # Add AccountType filter if specified
        if ($PSBoundParameters.ContainsKey('AccountType')) {
            Write-Verbose "Filtering by AccountType: $($AccountType -join ', ')"
            $body.Filters = @{
                AdServiceAccountType = @{
                    Eq = $AccountType
                }
            }
        }

        $Uri = "https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/serviceAccounts"
        Write-Verbose "Retrieving XDR identity service accounts"
        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -WebSession $script:session -Headers $script:headers

        # Return only the ServiceAccounts property
        $serviceAccounts = $result.ServiceAccounts

        Set-XdrCache -CacheKey $cacheKey -Value $serviceAccounts -TTLMinutes 10
        return $serviceAccounts
    }

    end {

    }
}
