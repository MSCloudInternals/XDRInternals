function Get-XdrIncident {
    <#
    .SYNOPSIS
        Retrieves incidents from Microsoft Defender XDR.

    .DESCRIPTION
        Gets incidents from Microsoft Defender XDR with support for pagination, sorting, and filtering.
        This cmdlet translates severity values and detection source IDs to friendly names.
        Severity translations: 32=Information, 64=Low, 128=Medium, 256=High
        This function includes caching support with a 10-minute TTL to reduce API calls.

    .PARAMETER TitleSearchTerms
        Array of search terms to filter incidents by title.

    .PARAMETER LookBackInDays
        Number of days to look back for incidents. Default is 30.

    .PARAMETER SortByField
        Field to sort by. Valid values are: TopRisk, CreatedDate, LastUpdatedDate, Status, severity, name.
        Default is TopRisk.

    .PARAMETER SortOrder
        Sort order. Valid values are Ascending or Descending. Default is Descending.

    .PARAMETER PageSize
        Number of incidents to retrieve per page. Default is 40.

    .PARAMETER PageIndex
        Page index for pagination. Default is 1.

    .PARAMETER DefenderExpertsLicensed
        Indicates if Microsoft Defender Experts for XDR license is assigned to the tenant. Default is false.

    .PARAMETER All
        Retrieves all incidents by automatically paging through all results.
        When specified, PageSize and PageIndex parameters are used for the page size, but pagination is automatic.

    .PARAMETER IncidentId
        Retrieves a specific incident by its ID. When specified, all other filtering and pagination parameters are ignored.
        Cannot be combined with any other parameters.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIncident
        Retrieves the first 40 incidents from the last 30 days, sorted by TopRisk in descending order.

    .EXAMPLE
        Get-XdrIncident -LookBackInDays 7 -PageSize 100
        Retrieves the first 100 incidents from the last 7 days.

    .EXAMPLE
        Get-XdrIncident -SortByField CreatedDate -SortOrder Ascending
        Retrieves incidents sorted by creation date in ascending order (oldest first).

    .EXAMPLE
        Get-XdrIncident -TitleSearchTerms "ransomware", "phishing"
        Retrieves incidents with titles containing "ransomware" or "phishing".

    .EXAMPLE
        Get-XdrIncident -All
        Retrieves all incidents by automatically paging through all results.

    .EXAMPLE
        Get-XdrIncident -DefenderExpertsLicensed -LookBackInDays 90
        Retrieves incidents from the last 90 days for a tenant with Defender Experts license.

    .EXAMPLE
        Get-XdrIncident -IncidentId 2823
        Retrieves a specific incident by its ID.

    .EXAMPLE
        Get-XdrIncident | Where-Object { $_.SeverityName -eq "High" }
        Retrieves incidents and filters for high severity ones.

    .OUTPUTS
        Object[]
        Returns an array of incident objects with properties including:
        - IncidentId: Unique incident identifier
        - Title: Incident title
        - Severity: Numeric severity value
        - SeverityName: Friendly severity name (Information/Low/Medium/High)
        - DetectionSources: Array of numeric detection source IDs
        - DetectionSourceNames: Array of friendly detection source names
        - Status: Incident status
        - CreatedTime: When the incident was created
        - LastUpdateTime: When the incident was last updated
        - AlertCount: Number of alerts in the incident
        - Classification: Incident classification
        - Determination: Incident determination
        And many other properties from the API response
    #>
    [OutputType([System.Object[]])]
    [CmdletBinding(DefaultParameterSetName = 'List')]
    param (
        [Parameter(ParameterSetName = 'List')]
        [string[]]$TitleSearchTerms,

        [Parameter(ParameterSetName = 'List')]
        [ValidateRange(1, 365)]
        [int]$LookBackInDays = 30,

        [Parameter(ParameterSetName = 'List')]
        [ValidateSet("TopRisk", "CreatedDate", "LastUpdatedDate", "Status", "severity", "name")]
        [string]$SortByField = "TopRisk",

        [Parameter(ParameterSetName = 'List')]
        [ValidateSet("Ascending", "Descending")]
        [string]$SortOrder = "Descending",

        [Parameter(ParameterSetName = 'List')]
        [ValidateRange(1, 1000)]
        [int]$PageSize = 40,

        [Parameter(ParameterSetName = 'List')]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$PageIndex = 1,

        [Parameter(ParameterSetName = 'List')]
        [switch]$DefenderExpertsLicensed,

        [Parameter(ParameterSetName = 'List')]
        [switch]$All,

        [Parameter(ParameterSetName = 'List')]
        [switch]$Force,

        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [int]$IncidentId
    )

    begin {
        Update-XdrConnectionSettings

        # Severity translation map
        $severityMap = @{
            32  = "Information"
            64  = "Low"
            128 = "Medium"
            256 = "High"
        }
    }
    
    process {
        # Handle single incident retrieval by ID
        if ($PSCmdlet.ParameterSetName -eq 'ById') {
            Write-Verbose "Retrieving incident with ID: $IncidentId"
            try {
                $Uri = "https://security.microsoft.com/apiproxy/mtp/incidentQueue/incidents/$IncidentId"
                $incident = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Add severity name
                $IncidentSeverity = [int]$incident.Severity
                if ($severityMap.ContainsKey($IncidentSeverity)) {
                    $incident | Add-Member -NotePropertyName "SeverityName" -NotePropertyValue $severityMap[$IncidentSeverity] -Force
                } else {
                    $incident | Add-Member -NotePropertyName "SeverityName" -NotePropertyValue "Unknown ($($IncidentSeverity))" -Force
                }

                # Add detection source names
                if ($incident.DetectionSources) {
                    $detectionSourceNames = $incident.DetectionSources | ForEach-Object { ConvertFrom-XdrDetectionSourceId -Id $_ }
                    $incident | Add-Member -NotePropertyName "DetectionSourceNames" -NotePropertyValue $detectionSourceNames -Force
                }

                return $incident
            } catch {
                throw "Failed to retrieve incident with ID $IncidentId : $($_.Exception.Message)"
            }
        }

        # Handle list retrieval with pagination
        $allIncidents = @()
        $currentPageIndex = $PageIndex

        do {
            # Build request body
            $body = @{
                isDexLicense                   = $DefenderExpertsLicensed.IsPresent
                isStatusFilterEnable           = $true
                isUSXIncidentAssignmentEnabled = $true
                pageSize                       = $PageSize
                isMultipleIncidents            = $true
                lookBackInDays                 = $LookBackInDays.ToString()
                filterByLastUpdateTime         = $true
                requestType                    = $null
                pageIndex                      = $currentPageIndex
                sortOrder                      = $SortOrder
                sortByField                    = $SortByField
            }

            if ($TitleSearchTerms) {
                $body.titleSearchTerms = $TitleSearchTerms
            }

            # Create cache key from parameters
            $cacheKeyParams = @{
                LookBackInDays          = $LookBackInDays
                SortByField             = $SortByField
                SortOrder               = $SortOrder
                PageSize                = $PageSize
                PageIndex               = $currentPageIndex
                DefenderExpertsLicensed = $DefenderExpertsLicensed.IsPresent
            }
            if ($TitleSearchTerms) {
                $cacheKeyParams.TitleSearchTerms = $TitleSearchTerms -join ","
            }
            $cacheKey = "XdrIncidents_$($cacheKeyParams.GetHashCode())"

            $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached XDR Incidents (Page $currentPageIndex)"
                $incidents = $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $cacheKey
                $incidents = $null
            } else {
                Write-Verbose "XDR Incidents cache is missing or expired (Page $currentPageIndex)"
                $incidents = $null
            }

            if (-not $incidents) {
                Write-Verbose "Retrieving XDR Incidents (Page $currentPageIndex)"
                try {
                    Write-Verbose "Request body: $(($body | ConvertTo-Json -Compress))"
                    $bodyJson = $body | ConvertTo-Json -Compress
                    $incidents = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/incidentQueue/incidents/alerts" -Method Post -ContentType "application/json" -Body $bodyJson -WebSession $script:session -Headers $script:headers
                    Set-XdrCache -CacheKey $cacheKey -Value $incidents -TTLMinutes 10
                    Write-Verbose "Found $($incidents.Count) incidents on page $currentPageIndex"
                } catch {
                    throw "Failed to retrieve XDR Incidents: $($_.Exception.Message)"
                }
            }

            # Process incidents to add friendly names
            foreach ($incident in $incidents) {
                # Add severity name
                $IncidentSeverity = [int]$incident.Severity
                if ($severityMap.ContainsKey($IncidentSeverity)) {
                    $incident | Add-Member -NotePropertyName "SeverityName" -NotePropertyValue $severityMap[$IncidentSeverity] -Force
                } else {
                    $incident | Add-Member -NotePropertyName "SeverityName" -NotePropertyValue "Unknown ($($IncidentSeverity))" -Force
                }

                # Add detection source names
                if ($incident.DetectionSources) {
                    $detectionSourceNames = $incident.DetectionSources | ForEach-Object { ConvertFrom-XdrDetectionSourceId -Id $_ }
                    $incident | Add-Member -NotePropertyName "DetectionSourceNames" -NotePropertyValue $detectionSourceNames -Force
                }
            }

            $allIncidents += $incidents

            if ($All) {
                $currentPageIndex++
                # If we got fewer results than page size, we've reached the end
                if ($incidents.Count -lt $PageSize) {
                    break
                }
            } else {
                break
            }
        } while ($All)

        return $allIncidents
    }
    
    end {
    }
}
