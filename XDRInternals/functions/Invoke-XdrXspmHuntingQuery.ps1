function Invoke-XdrXspmHuntingQuery {
    <#
    .SYNOPSIS
        Executes a hunting query against the Microsoft Defender XDR XSPM attack surface API.

    .DESCRIPTION
        Executes a custom hunting query against the XSPM (Extended Security Posture Management) attack surface API.
        Supports pagination through top and skip parameters.
        This function is designed to be used as a base for more specific attack surface queries.

    .PARAMETER Query
        The hunting query string to execute. Should follow XSPM query syntax.

    .PARAMETER Top
        The maximum number of records to return. Default is 100.

    .PARAMETER Skip
        The number of records to skip for pagination. Default is 0.

    .PARAMETER ScenarioName
        The scenario name to include in the request header (x-ms-scenario-name).
        This might be used for telemetry or logging purposes on the server side. Be careful out there.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Invoke-XdrXspmHuntingQuery -Query "AttackPathsV2 | take 10"
        Executes a query to retrieve 10 attack paths.

    .EXAMPLE
        Invoke-XdrXspmHuntingQuery -Query "AttackPathsV2" -Top 50 -Skip 100
        Executes a query with pagination, skipping the first 100 records and returning up to 50.

    .EXAMPLE
        Invoke-XdrXspmHuntingQuery -Query "AttackPathsV2 | where RiskLevel == 'High'" -Force
        Executes a filtered query, bypassing the cache.

    .EXAMPLE
        Invoke-XdrXspmHuntingQuery -Query "AttackPathsV2" -ScenarioName "CustomAnalysis"
        Executes a query with a custom scenario name in the request header.

    .OUTPUTS
        Object
        Returns the query results including totalRecords, count, skipToken, and data array.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter()]
        [int]$Top = 0,

        [Parameter()]
        [int]$Skip = 0,

        [Parameter(Mandatory)]
        [string]$ScenarioName,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Create cache key based on query and pagination parameters
        $cacheKeySuffix = "$($Query.GetHashCode())-$Top-$Skip"
        $cacheKey = "XdrXspmHuntingQuery-$cacheKeySuffix"

        try {
            $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "Cache retrieval failed: $_"
        }
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XSPM hunting query results"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $cacheKey
        } else {
            Write-Verbose "XSPM hunting query cache is missing or expired"
        }

        # Build the request body
        $body = @{
            query      = $Query
            options    = @{
                top  = $Top
                skip = $Skip
            }
            apiVersion = "v2"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/xspmatlas/attacksurface/query"
        Write-Verbose "Executing XSPM hunting query (Top: $Top, Skip: $Skip)"
        Write-Verbose "Query: $Query"

        # Get tenant context for X-Tid header
        $XdrTenantId = Get-XdrCache -CacheKey "XdrTenantId" -ErrorAction SilentlyContinue
        $tenantId = $XdrTenantId.Value

        # Build custom headers
        $customHeaders = $script:headers.Clone()
        if ($tenantId) {
            $customHeaders['X-Tid'] = $tenantId
            Write-Verbose "Added X-Tid header: $tenantId"
        }
        $customHeaders['x-ms-scenario-name'] = $ScenarioName
        Write-Verbose "Added x-ms-scenario-name header: $ScenarioName"

        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -WebSession $script:session -Headers $customHeaders

            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to execute XSPM hunting query: $_"
            throw
        }
    }

    end {

    }
}
