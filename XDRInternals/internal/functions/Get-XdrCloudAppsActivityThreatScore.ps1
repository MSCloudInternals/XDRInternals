function Get-XdrCloudAppsActivityThreatScore {
    <#
    .SYNOPSIS
        Retrieves Cloud Apps activity threat scores.

    .DESCRIPTION
        Internal helper that retrieves threat score details for activity record identifiers.

    .PARAMETER RecordIds
        Activity record identifiers.

    .PARAMETER StartDate
        Start of the score lookup range.

    .PARAMETER EndDate
        End of the score lookup range.

    .EXAMPLE
        Get-XdrCloudAppsActivityThreatScore -RecordIds @("record-id") -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date)

        Retrieves threat scores for a record.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$RecordIds,

        [Parameter(Mandatory)]
        [datetime]$StartDate,

        [Parameter(Mandatory)]
        [datetime]$EndDate
    )

    $body = @{
        recordIds = $RecordIds
        startDate = [long]($StartDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds
        endDate   = [long]($EndDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds
    }

    Invoke-XdrCloudAppsRequest -Path '/mcas/cas/api/v1/activities/get_activities_threat_scores/' -Method Post -Body $body -Raw
}

