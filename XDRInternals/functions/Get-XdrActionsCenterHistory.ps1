function Get-XdrActionsCenterHistory {
    <#
    .SYNOPSIS
        Retrieves historical actions from the Microsoft Defender XDR Action Center.

    .DESCRIPTION
        Gets a list of historical actions from the Microsoft Defender XDR Action Center with options to filter by date range, sort, and paginate the results.

    .PARAMETER SortByField
        The field to sort actions by. Valid values are: InvestigationId, ApprovalId, ActionType, EntityType, Asset, Decision, DecidedBy, ActionSource, Status, ActionUpdateTime. Defaults to 'ActionUpdateTime'.

    .PARAMETER SortOrder
        The sort order for results. Valid values are 'Ascending' or 'Descending'. Defaults to 'Descending'.

    .PARAMETER PageIndex
        The page index for pagination. Defaults to 1.

    .PARAMETER PageSize
        The number of actions to return per page. Defaults to 100.

    .PARAMETER ToDate
        The end date for the history query. Defaults to current time.

    .PARAMETER FromDate
        The start date for the history query. Defaults to 6 months before ToDate.

    .PARAMETER UseMtpApi
        Whether to use the MTP API. Defaults to $true.

    .PARAMETER Months
        The number of months to look back from the current date. Cannot be used together with FromDate parameter.
        Defaults to 6 months if neither FromDate nor Months is specified.

    .EXAMPLE
        Get-XdrActionsCenterHistory
        Retrieves the last 6 months of action center history with default settings.

    .EXAMPLE
        Get-XdrActionsCenterHistory -PageSize 50 -PageIndex 2
        Retrieves the second page of 50 historical actions.

    .EXAMPLE
        Get-XdrActionsCenterHistory -Months 3
        Retrieves the last 3 months of action center history.

    .EXAMPLE
        Get-XdrActionsCenterHistory -FromDate (Get-Date).AddDays(-30) -ToDate (Get-Date)
        Retrieves the last 30 days of action center history.

    .EXAMPLE
        Get-XdrActionsCenterHistory -SortByField "ActionUpdateTime" -SortOrder "Ascending"
        Retrieves actions sorted by action update time in ascending order.

    .OUTPUTS
        Object
        Returns the historical actions from the Action Center.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Months')]
    param (
        [Parameter()]
        [ValidateSet("InvestigationId", "ApprovalId", "ActionType", "EntityType", "Asset", "Decision", "DecidedBy", "ActionSource", "Status", "ActionUpdateTime")]
        [string]$SortByField = "ActionUpdateTime",

        [Parameter()]
        [ValidateSet("Ascending", "Descending")]
        [string]$SortOrder = "Descending",

        [Parameter()]
        [int]$PageIndex = 1,

        [Parameter()]
        [int]$PageSize = 100,

        [Parameter()]
        [datetime]$ToDate = (Get-Date),

        [Parameter(ParameterSetName = 'FromDate')]
        [datetime]$FromDate,

        [Parameter(ParameterSetName = 'Months')]
        [int]$Months = 6,

        [Parameter()]
        [bool]$UseMtpApi = $true
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Translate friendly SortByField names to internal field names
        $sortFieldMap = @{
            "InvestigationId"  = "investigationId"
            "ApprovalId"       = "bulkId"
            "ActionType"       = "actionType"
            "EntityType"       = "entityType"
            "Asset"            = "computerName"
            "Decision"         = "actionDecision"
            "DecidedBy"        = "decidedBy"
            "ActionSource"     = "actionSource"
            "Status"           = "actionStatus"
            "ActionUpdateTime" = "eventTime"
        }
        $internalSortField = $sortFieldMap[$SortByField]

        # Calculate the actual from date based on parameter set
        if ($PSCmdlet.ParameterSetName -eq 'Months') {
            $calculatedFromDate = $ToDate.AddMonths(-$Months)
        } else {
            $calculatedFromDate = $FromDate
        }

        # Convert dates to ISO 8601 format with milliseconds
        $toDateString = $ToDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $fromDateString = $calculatedFromDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        # Build the URI with query parameters
        $queryParams = @(
            "sortByField=$([System.Uri]::EscapeDataString($internalSortField))"
            "sortOrder=$([System.Uri]::EscapeDataString($SortOrder))"
            "type=history"
            "pageIndex=$PageIndex"
            "pageSize=$PageSize"
            "toDate=$([System.Uri]::EscapeDataString($toDateString))"
            "fromDate=$([System.Uri]::EscapeDataString($fromDateString))"
            "useMtpApi=$($UseMtpApi.ToString().ToLower())"
        )

        $Uri = "https://security.microsoft.com/apiproxy/mtp/actionCenter/actioncenterui/history-actions/?$($queryParams -join '&')"

        Write-Verbose "Retrieving XDR Action Center history (From: $fromDateString, To: $toDateString, Page: $PageIndex, Size: $PageSize)"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers | Select-Object -ExpandProperty Results

        return $result
    }

    end {

    }
}
