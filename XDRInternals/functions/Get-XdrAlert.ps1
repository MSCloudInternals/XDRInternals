function Get-XdrAlert {
    <#
    .SYNOPSIS
        Retrieves alerts from Microsoft Defender XDR.

    .DESCRIPTION
        Gets alerts from Microsoft Defender XDR with support for filtering by time range and pagination.
        Alerts can be retrieved with automatic pagination using the -All parameter or with manual page control.

    .PARAMETER DaysAgo
        Number of days to look back for alerts. Default is 7 days.

    .PARAMETER Order
        Sort order for results. Valid values are "desc" (descending, newest first) or "asc" (ascending, oldest first).
        Default is "desc".

    .PARAMETER PageNumber
        Specific page number to retrieve. Cannot be used with -All parameter.
        Default is 1.

    .PARAMETER PageSize
        Number of alerts to retrieve per page. Default is 60.
        Maximum value depends on API limits.

    .PARAMETER Severity
        Filter alerts by severity. Valid values are "Informational", "Low", "Medium", "High".
        Multiple values can be specified as an array.

    .PARAMETER Status
        Filter alerts by status. Valid values are "New", "InProgress", "Resolved".
        Multiple values can be specified as an array.

    .PARAMETER All
        Automatically retrieves all pages of alerts for the specified time range.
        Cannot be used with -PageNumber parameter.

    .EXAMPLE
        Get-XdrAlert
        Retrieves the first page of alerts from the last 7 days, sorted by newest first.

    .EXAMPLE
        Get-XdrAlert -DaysAgo 30
        Retrieves alerts from the last 30 days.

    .EXAMPLE
        Get-XdrAlert -Order asc
        Retrieves alerts sorted by oldest first.

    .EXAMPLE
        Get-XdrAlert -PageNumber 2 -PageSize 100
        Retrieves the second page with 100 alerts per page.

    .EXAMPLE
        Get-XdrAlert -All
        Automatically retrieves all alerts from the last 7 days across all pages.

    .EXAMPLE
        Get-XdrAlert -DaysAgo 14 -All
        Retrieves all alerts from the last 14 days with automatic pagination.

    .EXAMPLE
        Get-XdrAlert -Severity High, Medium
        Retrieves only high and medium severity alerts from the last 7 days.

    .EXAMPLE
        Get-XdrAlert -Status New, InProgress
        Retrieves only new and in-progress alerts.

    .EXAMPLE
        Get-XdrAlert -Severity High -Status New -DaysAgo 30
        Retrieves high severity new alerts from the last 30 days.

    .EXAMPLE
        Get-XdrAlert | Where-Object { $_.severity -eq "High" }
        Retrieves alerts and filters for high severity only.

    .OUTPUTS
        Object[]
        Returns an array of alert objects containing:
        - alertId: Unique identifier for the alert
        - alertDisplayName: Display name of the alert
        - providerName: Source provider (e.g., Microsoft Sentinel, Microsoft Defender)
        - status: Alert status (New, InProgress, Resolved)
        - severity: Alert severity (Informational, Low, Medium, High)
        - classification: Alert classification if set
        - determination: Alert determination if set
        - assignedTo: User assigned to the alert
        - incidentId: Associated incident ID
        - startTimeUtc: Alert start time
        - endTimeUtc: Alert end time
        - timeGenerated: Alert generation time
        - impactedEntities: List of impacted entities
        - mitreAttackCategory: MITRE ATT&CK category
        - mitreAttackTechnique: MITRE ATT&CK technique IDs
        And many other properties depending on the alert type.
    #>
    [OutputType([object[]])]
    [CmdletBinding(DefaultParameterSetName = 'Paged')]
    param (
        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$DaysAgo = 7,

        [Parameter()]
        [ValidateSet('desc', 'asc')]
        [string]$Order = 'desc',

        [Parameter(ParameterSetName = 'Paged')]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$PageNumber = 1,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$PageSize = 60,

        [Parameter()]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string[]]$Severity,

        [Parameter()]
        [ValidateSet('New', 'InProgress', 'Resolved')]
        [string[]]$Status,

        [Parameter(ParameterSetName = 'All')]
        [switch]$All
    )

    begin {
        Update-XdrConnectionSettings
        $Uri = "https://security.microsoft.com/apiproxy/mtp/alertsApiService/alerts"
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'All' -and $All) {
            # Automatic pagination mode
            Write-Verbose "Retrieving all alerts from the last $DaysAgo days with automatic pagination"
            
            $allAlerts = [System.Collections.Generic.List[object]]::new()
            $currentPage = 1
            $hasMorePages = $true

            do {
                Write-Verbose "Retrieving page $currentPage (PageSize: $PageSize)"
                
                $body = @{
                    sortByField                = "LastEventTime"
                    order                      = $Order
                    daysAgo                    = $DaysAgo.ToString()
                    shouldReturnAlertsLinkedBy = $false
                    pageNumber                 = $currentPage
                    pageSize                   = $PageSize
                }

                # Add optional filters
                if ($Severity) {
                    $body.severity = $Severity
                }
                if ($Status) {
                    $body.status = $Status
                }

                $bodyJson = $body | ConvertTo-Json

                try {
                    $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $bodyJson -WebSession $script:session -Headers $script:headers
                    
                    if ($result.entities -and $result.entities.Count -gt 0) {
                        Write-Verbose "Retrieved $($result.entities.Count) alert(s) from page $currentPage"
                        $allAlerts.AddRange($result.entities)
                    } else {
                        Write-Verbose "No more alerts found on page $currentPage"
                        $hasMorePages = $false
                    }

                    # Check if there are more pages
                    if ($result.nextPageParameters -or ($result.entities.Count -eq $PageSize)) {
                        $currentPage++
                    } else {
                        $hasMorePages = $false
                    }
                } catch {
                    Write-Error "Failed to retrieve alerts on page $currentPage : $($_.Exception.Message)"
                    $hasMorePages = $false
                }
            } while ($hasMorePages)

            Write-Verbose "Total alerts retrieved: $($allAlerts.Count)"
            return $allAlerts.ToArray()
        } else {
            # Single page mode
            Write-Verbose "Retrieving alerts from the last $DaysAgo days (Page: $PageNumber, PageSize: $PageSize, Order: $Order)"
            
            $body = @{
                sortByField                = "LastEventTime"
                order                      = $Order
                daysAgo                    = $DaysAgo.ToString()
                shouldReturnAlertsLinkedBy = $false
                pageNumber                 = $PageNumber
                pageSize                   = $PageSize
            }

            # Add optional filters
            if ($Severity) {
                $body.severity = $Severity
            }
            if ($Status) {
                $body.status = $Status
            }

            $bodyJson = $body | ConvertTo-Json

            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $bodyJson -WebSession $script:session -Headers $script:headers
                
                if ($result.entities) {
                    Write-Verbose "Retrieved $($result.entities.Count) of $($result.totalEntities) total alert(s)"
                    return $result.entities
                } else {
                    Write-Verbose "No alerts found"
                    return @()
                }
            } catch {
                Write-Error "Failed to retrieve alerts: $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
