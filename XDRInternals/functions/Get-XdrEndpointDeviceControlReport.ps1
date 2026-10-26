function Get-XdrEndpointDeviceControlReport {
    <#
    .SYNOPSIS
        Retrieves Microsoft Defender for Endpoint Device Control report data.

    .DESCRIPTION
        Retrieves Device Control summary statistics, policy names, or the report update time
        from the Defender portal. Preserves API response fields and caches each report type
        and summary lookback period separately for 30 minutes.

    .PARAMETER ReportType
        Report data to retrieve: SummaryStatistics, Policies, or CookMark (report update time).
        Defaults to SummaryStatistics.

    .PARAMETER LookbackInDays
        Number of days included in summary statistics, from 1 to 180. Defaults to 180 days.
        Applies only to SummaryStatistics.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointDeviceControlReport
        Retrieves the Device Control summary report for the last 180 days.

    .EXAMPLE
        Get-XdrEndpointDeviceControlReport -LookbackInDays 30 -Force
        Retrieves fresh Device Control summary statistics for the last 30 days.

    .EXAMPLE
        Get-XdrEndpointDeviceControlReport -ReportType Policies
        Retrieves the policy names available in the Device Control report.

    .EXAMPLE
        Get-XdrEndpointDeviceControlReport -ReportType CookMark
        Retrieves the time when Device Control report data was last processed.

    .OUTPUTS
        Object
        Returns Device Control report data supplied by the API.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('SummaryStatistics', 'Policies', 'CookMark')]
        [string]$ReportType = 'SummaryStatistics',

        [Parameter()]
        [ValidateRange(1, 180)]
        [int]$LookbackInDays = 180,

        [Parameter()]
        [switch]$Force
    )

    begin {
        if ($ReportType -ne 'SummaryStatistics' -and $PSBoundParameters.ContainsKey('LookbackInDays')) {
            throw 'LookbackInDays applies only to the SummaryStatistics report.'
        }
        Update-XdrConnectionSettings
    }

    process {
        try {
            $Uri = "https://security.microsoft.com/apiproxy/mdepdevicecontrol/m365/devicecontrolservice/$ReportType"
            if ($ReportType -eq 'SummaryStatistics') {
                $Uri += "?lookbackInDays=$LookbackInDays"
            }
            Invoke-XdrReportRequest -Uri $Uri -Force:$Force
        } catch {
            $PSCmdlet.WriteError($_)
        }
    }
}