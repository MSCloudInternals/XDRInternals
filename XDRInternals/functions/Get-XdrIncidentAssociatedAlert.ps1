function Get-XdrIncidentAssociatedAlert {
    <#
    .SYNOPSIS
        Retrieves alerts associated with a specific incident from Microsoft Defender XDR.

    .DESCRIPTION
        Gets all alerts associated with a specific incident ID from Microsoft Defender XDR.
        This cmdlet automatically handles pagination to retrieve all associated alerts.
        The results are cached to improve performance.

    .PARAMETER IncidentId
        The ID of the incident to retrieve associated alerts for.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIncidentAssociatedAlert -IncidentId 2824
        Retrieves all alerts associated with incident 2824.

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
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
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
