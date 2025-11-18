function Get-XdrActionsCenterPending {
    <#
    .SYNOPSIS
        Retrieves pending actions from the Microsoft Defender XDR Action Center.

    .DESCRIPTION
        Gets a list of pending actions from the Microsoft Defender XDR Action Center with options to sort and paginate the results.

    .PARAMETER SortByField
        The field to sort actions by. Valid values are: InvestigationId, ApprovalId, ActionType, EntityType, Asset, Decision, DecidedBy, ActionSource, Status, ActionUpdateTime. Defaults to 'ActionUpdateTime'.

    .PARAMETER SortOrder
        The sort order for results. Valid values are 'Ascending' or 'Descending'. Defaults to 'Descending'.

    .PARAMETER PageIndex
        The page index for pagination. Defaults to 1.

    .PARAMETER PageSize
        The number of actions to return per page. Defaults to 100.

    .PARAMETER UseMtpApi
        Whether to use the MTP API. Defaults to $true.

    .EXAMPLE
        Get-XdrActionsCenterPending
        Retrieves pending actions from the Action Center with default settings.

    .EXAMPLE
        Get-XdrActionsCenterPending -PageSize 50 -PageIndex 2
        Retrieves the second page of 50 pending actions.

    .EXAMPLE
        Get-XdrActionsCenterPending -SortByField "ActionUpdateTime" -SortOrder "Ascending"
        Retrieves pending actions sorted by action update time in ascending order.

    .OUTPUTS
        Object
        Returns the pending actions from the Action Center.
    #>
    [CmdletBinding()]
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

        # Build the URI with query parameters
        $queryParams = @(
            "sortByField=$([System.Uri]::EscapeDataString($internalSortField))"
            "sortOrder=$([System.Uri]::EscapeDataString($SortOrder))"
            "type=pending"
            "pageIndex=$PageIndex"
            "pageSize=$PageSize"
            "useMtpApi=$($UseMtpApi.ToString().ToLower())"
        )

        $Uri = "https://security.microsoft.com/apiproxy/mtp/actionCenter/actioncenterui/pending-actions/?$($queryParams -join '&')"

        Write-Verbose "Retrieving XDR Action Center pending actions (Page: $PageIndex, Size: $PageSize, Sort: $SortByField $SortOrder)"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers | Select-Object -ExpandProperty Results

        return $result
    }

    end {

    }
}
