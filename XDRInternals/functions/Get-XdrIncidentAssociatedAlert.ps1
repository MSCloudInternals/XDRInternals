function Get-XdrIncidentAssociatedAlert {
    <#
    .SYNOPSIS
        Retrieves alerts associated with a specific incident from Microsoft Defender XDR.

    .DESCRIPTION
        Gets all alerts associated with a specific incident ID from Microsoft Defender XDR.
        By default, this cmdlet automatically handles pagination and caches the result.
        With -PageIndex and -PageSize, it retrieves exactly one page without using the all-pages cache.

    .PARAMETER IncidentId
        The ID of the incident to retrieve associated alerts for.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .PARAMETER PageIndex
        Retrieves exactly one 1-based page (1-10) instead of all pages. Defaults to 1 when
        only PageSize is supplied.

    .PARAMETER PageSize
        Number of associated alerts requested on a single page (1-50). Supplying this
        parameter enables single-page mode even if PageIndex is omitted.

    .EXAMPLE
        Get-XdrIncidentAssociatedAlert -IncidentId 2824
        Retrieves all alerts associated with incident 2824.

    .EXAMPLE
        Get-XdrIncidentAssociatedAlert -IncidentId 2824 -PageIndex 2 -PageSize 25
        Retrieves only the second page of up to 25 associated alerts.

    .OUTPUTS
        Object[]
        Returns an array of alert objects associated with the incident.
    #>
    [OutputType([object[]])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [int]$IncidentId,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$PageIndex = 1,

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$PageSize = 30
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($PSBoundParameters.ContainsKey('PageIndex') -or $PSBoundParameters.ContainsKey('PageSize')) {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/incidents/$IncidentId/AssociatedAlerts?incidentId=$IncidentId"
            $body = @{
                LookBackInDays = 180
                PageSize       = $PageSize
                PageIndex      = $PageIndex
                SortByField    = 'FirstEventTime'
                SortOrder      = 0
                GroupType      = 'GroupHash'
            } | ConvertTo-Json
            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType 'application/json' -Body $body -WebSession $script:session -Headers $script:headers -ErrorAction Stop
                if ($result -isnot [pscustomobject] -or $result.items -isnot [array]) { throw 'invalid_response' }
                if (@($result.items).Count -gt $PageSize) { throw 'invalid_response' }
                foreach ($item in $result.items) {
                    if ($item -isnot [pscustomobject]) { throw 'invalid_response' }
                }
                return @($result.items)
            } catch {
                throw [System.InvalidOperationException]::new("Failed to retrieve associated alerts for incident ${IncidentId}: $_", $_.Exception)
            }
        }

        $cacheKey = "XdrIncidentAssociatedAlert_$IncidentId"
        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue

        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Incident Associated Alerts for IncidentId $IncidentId"
            return $currentCacheValue.Value
        }

        if ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $cacheKey
        } else {
            Write-Verbose "Cache is missing or expired for IncidentId $IncidentId"
        }

        $allAlerts = [System.Collections.Generic.List[object]]::new()
        $pageIndex = 1
        $pageSize = 30
        $hasMorePages = $true

        $Uri = "https://security.microsoft.com/apiproxy/mtp/incidents/$IncidentId/AssociatedAlerts?incidentId=$IncidentId"

        do {
            Write-Verbose "Retrieving associated alerts for incident $IncidentId (Page: $pageIndex)"

            $body = @{
                LookBackInDays = 180
                PageSize       = $pageSize
                PageIndex      = $pageIndex
                SortByField    = "FirstEventTime"
                SortOrder      = 0
                GroupType      = "GroupHash"
            } | ConvertTo-Json

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

                if ($result.items -and $result.items.Count -gt 0) {
                    Write-Verbose "Retrieved $($result.items.Count) alert(s) on page $pageIndex"
                    $allAlerts.AddRange($result.items)
                }

                if ($result.totalPagesAvailable -gt $pageIndex) {
                    $pageIndex++
                } else {
                    $hasMorePages = $false
                }

            } catch {
                Write-Error "Failed to retrieve associated alerts for incident $IncidentId on page $pageIndex : $($_.Exception.Message)"
                $hasMorePages = $false
            }

        } while ($hasMorePages)

        $finalResult = $allAlerts.ToArray()
        
        Set-XdrCache -CacheKey $cacheKey -Value $finalResult -TTLMinutes 10
        
        return $finalResult
    }

    end {
    }
}
