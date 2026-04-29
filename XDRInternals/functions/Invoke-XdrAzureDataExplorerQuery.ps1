function Invoke-XdrAzureDataExplorerQuery {
    <#
    .SYNOPSIS
        Executes a KQL query or management command against an Azure Data Explorer cluster.
    .DESCRIPTION
        Runs a Kusto Query Language (KQL) query or management command against the configured
        Azure Data Explorer cluster and returns the results as PowerShell objects.

        Regular KQL queries are sent to the v2/rest/query endpoint. Management commands
        (queries starting with '.') are sent to the v1/rest/mgmt endpoint.

        Connection settings must be configured first using Set-XdrAzureDataExplorerConnection.
    .PARAMETER Query
        The KQL query or management command to execute.
    .PARAMETER Database
        Optional database name to override the database from connection settings.
    .PARAMETER ServerTimeout
        Server-side query timeout as a TimeSpan. Default is 4 minutes.
    .PARAMETER RequestTimeout
        Client-side HTTP timeout in seconds. Default is 300 seconds. Currently only
        server-side timeout is enforced via the request body.
    .PARAMETER Raw
        Return the raw API response instead of converting to PSCustomObject output.
    .EXAMPLE
        Invoke-XdrAzureDataExplorerQuery -Query 'XDRAlerts | take 10'

        Runs a KQL query and returns the first 10 alerts as objects.
    .EXAMPLE
        Invoke-XdrAzureDataExplorerQuery -Query '.show tables'

        Runs a management command to list all tables.
    .EXAMPLE
        Invoke-XdrAzureDataExplorerQuery -Query 'StormEvents | count' -Database 'Samples' -ServerTimeout ([timespan]::FromMinutes(10))

        Runs a query against a specific database with a custom server timeout.
    #>
    [OutputType([pscustomobject[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [string]$Database,

        [timespan]$ServerTimeout = [timespan]::FromMinutes(4),

        [int]$RequestTimeout = 300,

        [switch]$Raw
    )

    begin {
        $connection = Get-XdrAzureDataExplorerConnection
        $token = Get-XdrAzureAccessToken -Resource 'https://api.kusto.windows.net' `
            -Scope ("$($connection.ClusterUri.AbsoluteUri.TrimEnd('/'))/.default") `
            -TenantId $connection.TenantId `
            -ManagedIdentityClientId $connection.ManagedIdentityClientId `
            -AccessToken $connection.AccessToken `
            -ResourceDisplayName 'Azure Data Explorer'
    }

    process {
        $db = if ($Database) { $Database } else { $connection.Database }
        $isManagementCommand = $Query.TrimStart().StartsWith('.')

        $body = @{
            db  = $db
            csl = $Query
        }

        if ($isManagementCommand) {
            $path = '/v1/rest/mgmt'
        }
        else {
            $path = '/v2/rest/query'
            $body['properties'] = @{
                Options = @{
                    servertimeout = $ServerTimeout.ToString()
                }
            }
        }

        $response = Invoke-XdrAzureDataExplorerRestRequest `
            -BaseUri $connection.ClusterUri `
            -Path $path `
            -Method POST `
            -Token $token `
            -Body $body `
            -TimeoutSec $RequestTimeout

        if ($Raw) {
            return $response
        }

        if ($isManagementCommand) {
            ConvertFrom-XdrAzureDataExplorerResponseTable -Response $response
        }
        else {
            $primaryResult = $response | Where-Object { $_.FrameType -eq 'DataTable' -and $_.TableKind -eq 'PrimaryResult' }
            if (-not $primaryResult -or -not $primaryResult.Columns -or -not $primaryResult.Rows) {
                return
            }

            foreach ($row in @($primaryResult.Rows)) {
                $values = [ordered]@{}
                for ($i = 0; $i -lt $primaryResult.Columns.Count; $i++) {
                    $values[$primaryResult.Columns[$i].ColumnName] = $row[$i]
                }
                [pscustomobject]$values
            }
        }
    }
}
