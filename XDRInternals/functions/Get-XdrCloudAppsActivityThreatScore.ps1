function Get-XdrCloudAppsActivityThreatScore {
    <#
    .SYNOPSIS
        Retrieves threat scores for specified activity records from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        The Get-XdrCloudAppsActivityThreatScore cmdlet retrieves threat scores for specific
        activity records identified by their record IDs. You can optionally specify a date
        range to scope the threat score analysis.

    .PARAMETER RecordIds
        An array of activity record IDs to retrieve threat scores for.
        These IDs can be obtained from the Get-XdrCloudAppsActivity cmdlet.

    .PARAMETER StartDate
        The start date for the threat score analysis date range.
        Defaults to 7 days ago if not specified.

    .PARAMETER EndDate
        The end date for the threat score analysis date range.
        Defaults to the current date/time if not specified.

    .EXAMPLE
        Get-XdrCloudAppsActivityThreatScore -RecordIds @("record1", "record2")

        Retrieves threat scores for the specified activity records using the default 7-day date range.

    .EXAMPLE
        $activities = Get-XdrCloudAppsActivity -Limit 10
        $recordIds = $activities.data._id
        Get-XdrCloudAppsActivityThreatScore -RecordIds $recordIds

        Retrieves the 10 most recent activities and gets their threat scores.

    .EXAMPLE
        $startDate = (Get-Date).AddDays(-30)
        $endDate = Get-Date
        Get-XdrCloudAppsActivityThreatScore -RecordIds @("record1") -StartDate $startDate -EndDate $endDate

        Retrieves threat scores for a specific record within a 30-day date range.

    .NOTES
        Requires an active XDR session established via Connect-XdrByEstsCookie.
        This cmdlet does not use caching as it retrieves scores for specific records.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$RecordIds,

        [Parameter()]
        [datetime]$StartDate = (Get-Date).AddDays(-7),

        [Parameter()]
        [datetime]$EndDate = (Get-Date)
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/activities/get_activities_threat_scores/"

        # Convert dates to epoch milliseconds
        $startEpoch = [long]([DateTimeOffset]$StartDate.ToUniversalTime()).ToUnixTimeMilliseconds()
        $endEpoch = [long]([DateTimeOffset]$EndDate.ToUniversalTime()).ToUnixTimeMilliseconds()

        $body = @{
            dateRange = @{
                start = $startEpoch
                end   = $endEpoch
            }
            recordIds = @($RecordIds)
        }

        $jsonBody = $body | ConvertTo-Json -Depth 10

        Write-Verbose "Retrieving activity threat scores from $Uri"
        Write-Verbose "Request body: $jsonBody"

        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $jsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            return $result
        }
        catch {
            Write-Error "Failed to retrieve activity threat scores: $_"
        }
    }
}
