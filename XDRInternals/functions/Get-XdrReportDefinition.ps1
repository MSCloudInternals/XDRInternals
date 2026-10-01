function Get-XdrReportDefinition {
    <#
    .SYNOPSIS
        Lists supported Microsoft Defender portal report operations.

    .DESCRIPTION
        Returns the report catalog, including report names, families, HTTP methods,
        paths, default query parameters, request bodies, and discovery sources.
        Does not connect to the portal or retrieve tenant data.

    .PARAMETER Name
        Report operation names to select. Supports wildcard patterns.

    .PARAMETER Family
        Report family to select. Supports wildcard patterns.

    .EXAMPLE
        Get-XdrReportDefinition
        Lists all implemented report operations.

    .EXAMPLE
        Get-XdrReportDefinition -Family Firewall
        Lists firewall report data and advanced hunting query operations.

    .OUTPUTS
        Object
        Returns report request definitions.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$Name = @('*'),

        [Parameter()]
        [string]$Family = '*'
    )

    Get-XdrReportCatalog | Where-Object {
        $definition = $_
        $definition.Family -like $Family -and @($Name | Where-Object { $definition.Name -like $_ }).Count -gt 0
    }
}