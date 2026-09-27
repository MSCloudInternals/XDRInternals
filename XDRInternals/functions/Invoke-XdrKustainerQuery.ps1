function Invoke-XdrKustainerQuery {
    <#
    .SYNOPSIS
        Executes a KQL query or management command against Kustainer.

    .DESCRIPTION
        Runs a Kusto Query Language query or management command against the configured local Kusto
        emulator and returns the result rows as PowerShell objects. Regular queries use
        /v2/rest/query. Commands beginning with a period use /v1/rest/mgmt.

        Configure the default endpoint and database with Set-XdrKustainer, or provide both values
        directly with ClusterUri and Database.

    .PARAMETER Query
        The KQL query or management command to execute.

    .PARAMETER ClusterUri
        Optional HTTP emulator endpoint or HTTPS reverse-proxy endpoint.

    .PARAMETER Database
        Optional database name. When omitted, uses the configured Kustainer database.

    .PARAMETER ServerTimeout
        Server-side timeout for regular KQL queries. Defaults to four minutes.

    .PARAMETER RequestTimeout
        Client-side HTTP timeout in seconds. Defaults to 300 seconds.

    .PARAMETER Raw
        Returns the raw Kusto REST response instead of row objects.
        The caller is responsible for checking the response for partial failures or cancellation.

    .EXAMPLE
        Invoke-XdrKustainerQuery -Query 'XDRAlerts | take 10'

        Returns up to ten rows from the configured Kustainer database.

    .EXAMPLE
        Invoke-XdrKustainerQuery -Query '.show tables'

        Lists tables by using the management endpoint.

    .EXAMPLE
        Invoke-XdrKustainerQuery -ClusterUri 'http://localhost:8080' `
            -Database 'NetDefaultDB' -Query 'XDRCloudAppsActivityTimeline | count'

        Queries Kustainer without first storing a connection.
    #>
    [OutputType([pscustomobject[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Query,

        [uri]$ClusterUri,

        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]{0,127}$')]
        [string]$Database,

        [timespan]$ServerTimeout = [timespan]::FromMinutes(4),

        [ValidateRange(1, 3600)]
        [int]$RequestTimeout = 300,

        [switch]$Raw
    )

    begin {
        if (-not $ClusterUri -or [string]::IsNullOrWhiteSpace($Database)) {
            $connection = Get-XdrKustainerConnection
            if (-not $ClusterUri) {
                $ClusterUri = $connection.ClusterUri
            }
            if ([string]::IsNullOrWhiteSpace($Database)) {
                $Database = $connection.Database
            }
        }

        if ($ClusterUri.Scheme -notin @('http', 'https')) {
            throw 'Kustainer requires an http:// endpoint or an https:// reverse-proxy endpoint.'
        }

        $normalizedClusterUri = [uri]$ClusterUri.GetLeftPart([System.UriPartial]::Authority)
    }

    process {
        $isManagementCommand = $Query.TrimStart().StartsWith('.')
        $body = @{
            db  = $Database
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
            -BaseUri $normalizedClusterUri `
            -Path $path `
            -Method POST `
            -Body $body `
            -TimeoutSec $RequestTimeout `
            -RetryCount $(if ($isManagementCommand) { 1 } else { 10 })

        if ($response -is [string]) {
            if ((Get-Command ConvertFrom-Json -ErrorAction Stop).Parameters.ContainsKey('AsHashtable')) {
                $response = $response | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            }
            else {
                Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
                $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
                $serializer.MaxJsonLength = [int]::MaxValue
                $response = $serializer.DeserializeObject($response)
            }
        }

        if ($Raw) {
            return $response
        }

        if (-not $isManagementCommand) {
            foreach ($completion in @($response | Where-Object { $_.FrameType -eq 'DataSetCompletion' })) {
                if ($completion.HasErrors -or $completion.Cancelled) {
                    $details = @(
                        foreach ($entry in $completion.OneApiErrors) {
                            $message = if ($entry.error.'@message') { $entry.error.'@message' } else { $entry.error.message }
                            if ($message) { $message }
                        }
                    ) -join '; '
                    if ([string]::IsNullOrWhiteSpace($details)) {
                        $details = if ($completion.Cancelled) { 'The query was cancelled.' } else { 'The server reported a partial query failure.' }
                    }

                    throw "Kustainer query failed: $details"
                }
            }
        }

        $tableResponse = if ($isManagementCommand) {
            $response
        }
        else {
            [pscustomobject]@{
                Tables = @(
                    $response |
                        Where-Object { $_.FrameType -eq 'DataTable' -and $_.TableKind -eq 'PrimaryResult' } |
                        Select-Object -First 1
                )
            }
        }

        ConvertFrom-XdrAzureDataExplorerResponseTable -Response $tableResponse
    }
}
