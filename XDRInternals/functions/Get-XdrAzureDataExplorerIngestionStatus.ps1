function Get-XdrAzureDataExplorerIngestionStatus {
    <#
    .SYNOPSIS
        Gets the status of queued Azure Data Explorer ingestion operations.

    .DESCRIPTION
        Queries the Azure Data Explorer queued-ingestion status REST endpoint for one or more
        ingestion operation IDs. Use this cmdlet after Export-XdrAzureDataExplorer -TrackIngestion,
        or use -WaitForCompletion to block until the queued-ingestion operations finish.

        Requires Set-XdrAzureDataExplorerConnection to be called first.

    .PARAMETER TableName
        The target Azure Data Explorer table name that the queued-ingestion operation targeted.

    .PARAMETER OperationId
        One or more queued-ingestion operation IDs returned by Azure Data Explorer.

    .PARAMETER Details
        Includes per-blob details when the service returns them.

    .PARAMETER WaitForCompletion
        Polls the queued-ingestion status endpoint until all specified operations reach a terminal
        state or the timeout is reached.

    .PARAMETER TimeoutMinutes
        Maximum number of minutes to wait when -WaitForCompletion is specified.

    .PARAMETER PollingIntervalSeconds
        Number of seconds between queued-ingestion status polls when -WaitForCompletion is specified.

    .EXAMPLE
        Get-XdrAzureDataExplorerIngestionStatus -TableName "DeviceTimeline" -OperationId "ingest_op_12345"

        Gets the current status of a queued-ingestion operation.

    .EXAMPLE
        Get-XdrAzureDataExplorerIngestionStatus -TableName "DeviceTimeline" -OperationId "ingest_op_12345" -WaitForCompletion -Details

        Waits for the queued-ingestion operation to finish and returns detailed blob status.

    .OUTPUTS
        PSCustomObject[]
        Returns one status object per queued-ingestion operation.
    #>
    [OutputType([pscustomobject[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Alias('Table')]
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]{0,127}$')]
        [string]$TableName,

        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('IngestionOperationId', 'Id')]
        [string[]]$OperationId,

        [switch]$Details,

        [switch]$WaitForCompletion,

        [ValidateRange(1, 1440)]
        [int]$TimeoutMinutes = 30,

        [ValidateRange(1, 300)]
        [int]$PollingIntervalSeconds = 15
    )

    begin {
        $connection = Get-XdrAzureDataExplorerConnection
        $token = Get-XdrAzureAccessToken -Resource 'https://api.kusto.windows.net' `
            -Scope ("$($connection.ClusterUri.AbsoluteUri.TrimEnd('/'))/.default") `
            -TenantId $connection.TenantId `
            -ManagedIdentityClientId $connection.ManagedIdentityClientId `
            -AccessToken $connection.AccessToken `
            -ResourceDisplayName 'Azure Data Explorer'

        $operationIds = [System.Collections.Generic.List[string]]::new()
    }

    process {
        foreach ($currentOperationId in @($OperationId)) {
            if (-not [string]::IsNullOrWhiteSpace($currentOperationId)) {
                $operationIds.Add($currentOperationId.Trim()) | Out-Null
            }
        }
    }

    end {
        if ($operationIds.Count -eq 0) {
            return
        }

        if ($WaitForCompletion) {
            Wait-XdrAzureDataExplorerQueuedIngestion -IngestionUri $connection.IngestionUri `
                -Database $connection.Database `
                -TableName $TableName `
                -OperationId ($operationIds.ToArray()) `
                -Token $token `
                -TimeoutMinutes $TimeoutMinutes `
                -PollingIntervalSeconds $PollingIntervalSeconds `
                -Details:$Details
            return
        }

        foreach ($currentOperationId in $operationIds) {
            Get-XdrAzureDataExplorerQueuedIngestionStatus -IngestionUri $connection.IngestionUri `
                -Database $connection.Database `
                -TableName $TableName `
                -OperationId $currentOperationId `
                -Token $token `
                -Details:$Details
        }
    }
}
