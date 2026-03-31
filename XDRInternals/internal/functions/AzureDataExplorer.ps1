function Get-XdrAzureDataExplorerConnection {
    [CmdletBinding()]
    param()

    process {
        if (-not $script:AzureDataExplorerConnection) {
            throw "Azure Data Explorer connection not configured. Run Set-AzureDataExplorerConnection first."
        }

        return $script:AzureDataExplorerConnection
    }
}

function Resolve-XdrAzureDataExplorerUris {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$ClusterUri,

        [uri]$IngestionUri
    )

    $normalizedClusterUri = [uri]$ClusterUri.GetLeftPart([System.UriPartial]::Authority)
    $clusterHost = $normalizedClusterUri.DnsSafeHost
    $port = if ($normalizedClusterUri.IsDefaultPort) { -1 } else { $normalizedClusterUri.Port }

    if ($clusterHost.StartsWith('ingest-', [System.StringComparison]::OrdinalIgnoreCase)) {
        $engineHost = $clusterHost.Substring(7)
        $ingestionHost = $clusterHost
    }
    else {
        $engineHost = $clusterHost
        $ingestionHost = "ingest-$clusterHost"
    }

    $clusterBuilder = [System.UriBuilder]::new($normalizedClusterUri.Scheme, $engineHost, $port)

    if ($IngestionUri) {
        $normalizedIngestionUri = [uri]$IngestionUri.GetLeftPart([System.UriPartial]::Authority)
    }
    else {
        $normalizedIngestionUri = [uri]([System.UriBuilder]::new($normalizedClusterUri.Scheme, $ingestionHost, $port).Uri.GetLeftPart([System.UriPartial]::Authority))
    }

    [pscustomobject]@{
        ClusterUri   = [uri]$clusterBuilder.Uri.GetLeftPart([System.UriPartial]::Authority)
        IngestionUri = $normalizedIngestionUri
    }
}

function ConvertFrom-XdrAzureDataExplorerResponseTable {
    [OutputType([pscustomobject[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Response
    )

    process {
        if (-not $Response -or -not $Response.Tables) {
            return [pscustomobject[]]@()
        }

        $table = @($Response.Tables)[0]
        if (-not $table -or -not $table.Columns -or -not $table.Rows) {
            return [pscustomobject[]]@()
        }

        $rows = foreach ($row in @($table.Rows)) {
            $values = [ordered]@{}
            for ($i = 0; $i -lt $table.Columns.Count; $i++) {
                $values[$table.Columns[$i].ColumnName] = $row[$i]
            }

            [pscustomobject]$values
        }

        return [pscustomobject[]]$rows
    }
}

function Invoke-XdrAzureDataExplorerRestRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$BaseUri,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Token,

        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',

        $Body
    )

    $requestUri = [uri]::new($BaseUri, $Path)
    $headers = @{
        'Accept'                 = 'application/json'
        'Authorization'          = "Bearer $Token"
        'Connection'             = 'Keep-Alive'
        'x-ms-app'               = 'XDRInternals'
        'x-ms-client-version'    = 'XDRInternals/1.0.12'
        'x-ms-client-request-id' = "XDRInternals.AzureDataExplorer;$([guid]::NewGuid())"
    }

    if ($Method -eq 'GET') {
        return Invoke-RestMethod -Uri $requestUri -Method Get -Headers $headers -ErrorAction Stop -Verbose:$false
    }

    $requestBody = if ($Body -is [string]) {
        $Body
    }
    else {
        $Body | ConvertTo-Json -Depth 20 -Compress
    }

    Invoke-RestMethod -Uri $requestUri -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $requestBody -ErrorAction Stop -Verbose:$false
}

function Invoke-XdrAzureDataExplorerManagementCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$ClusterUri,

        [Parameter(Mandatory)]
        [string]$Database,

        [Parameter(Mandatory)]
        [string]$Command,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $body = @{
        db  = $Database
        csl = $Command
    }

    Invoke-XdrAzureDataExplorerRestRequest -BaseUri $ClusterUri -Path '/v1/rest/mgmt' -Method POST -Token $Token -Body $body
}

function Test-XdrAzureDataExplorerNotFound {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $ErrorRecord
    )

    $response = $ErrorRecord.Exception.Response
    if ($response) {
        try {
            if ([int]$response.StatusCode -eq 404) {
                return $true
            }
        }
        catch {
            Write-Verbose "Could not inspect the Azure Data Explorer response status code while handling a not-found check."
        }
    }

    $messages = @(
        $ErrorRecord.Exception.Message,
        $ErrorRecord.ErrorDetails.Message,
        $(if ($response -and $response.Content) { [string]$response.Content } else { $null })
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    return (@($messages | Where-Object {
                $_ -match '404' -or
                $_ -match 'NotFound' -or
                $_ -match 'BadRequest_EntityNotFound' -or
                $_ -match 'EntityNotFoundException' -or
                $_ -match 'does not exist' -or
                $_ -match 'was not found'
            }).Count -gt 0)
}

function Test-XdrAzureDataExplorerTable {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [uri]$ClusterUri,

        [Parameter(Mandatory)]
        [string]$Database,

        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $escapedTableName = $TableName -replace "'", "''"
    $response = Invoke-XdrAzureDataExplorerManagementCommand `
        -ClusterUri $ClusterUri `
        -Database $Database `
        -Command ".show tables | where TableName == '$escapedTableName'" `
        -Token $Token

    return (@(ConvertFrom-XdrAzureDataExplorerResponseTable -Response $response).Count -gt 0)
}

function Test-XdrAzureDataExplorerMapping {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [uri]$ClusterUri,

        [Parameter(Mandatory)]
        [string]$Database,

        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [string]$MappingName,

        [Parameter(Mandatory)]
        [string]$Token
    )

    try {
        $response = Invoke-XdrAzureDataExplorerManagementCommand -ClusterUri $ClusterUri -Database $Database -Command ".show table $TableName ingestion json mappings | where Name == '$MappingName'" -Token $Token
        return (@(ConvertFrom-XdrAzureDataExplorerResponseTable -Response $response).Count -gt 0)
    }
    catch {
        if (Test-XdrAzureDataExplorerNotFound -ErrorRecord $_) {
            return $false
        }

        throw
    }
}

function Initialize-XdrAzureDataExplorerTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$ClusterUri,

        [Parameter(Mandatory)]
        [string]$Database,

        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [string]$MappingName,

        [Parameter(Mandatory)]
        [string]$Token,

        [hashtable]$TableProfile
    )

    if (-not (Test-XdrAzureDataExplorerTable -ClusterUri $ClusterUri -Database $Database -TableName $TableName -Token $Token)) {
        if ($TableProfile) {
            $columnSpec = ($TableProfile.Columns | ForEach-Object { "$($_.Name):$($_.Type)" }) -join ', '
        }
        else {
            $columnSpec = 'Event:dynamic'
        }

        Write-Verbose "Creating Azure Data Explorer table '$TableName' in database '$Database' with columns ($columnSpec)"
        $null = Invoke-XdrAzureDataExplorerManagementCommand -ClusterUri $ClusterUri -Database $Database -Command ".create table $TableName ($columnSpec)" -Token $Token
    }

    if (-not (Test-XdrAzureDataExplorerMapping -ClusterUri $ClusterUri -Database $Database -TableName $TableName -MappingName $MappingName -Token $Token)) {
        if ($TableProfile) {
            $mappingEntries = $TableProfile.ColumnMappings | ForEach-Object {
                @{ column = $_.Column; Properties = @{ path = $_.Properties.Path } }
            }
            $mapping = ($mappingEntries | ConvertTo-Json -Depth 4 -Compress)
        }
        else {
            $mapping = '[{"column":"Event","Properties":{"path":"$"}}]'
        }

        Write-Verbose "Creating Azure Data Explorer JSON mapping '$MappingName' on table '$TableName'"
        $null = Invoke-XdrAzureDataExplorerManagementCommand -ClusterUri $ClusterUri -Database $Database -Command ".create table $TableName ingestion json mapping '$MappingName' '$mapping'" -Token $Token
    }
}

function Get-XdrAzureDataExplorerIngestionConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$IngestionUri,

        [Parameter(Mandatory)]
        [string]$Token
    )

    Invoke-XdrAzureDataExplorerRestRequest -BaseUri $IngestionUri -Path '/v1/rest/ingestion/configuration' -Method GET -Token $Token
}

function Get-XdrAzureDataExplorerIngestionRuntimeConfiguration {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [uri]$IngestionUri,

        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter(Mandatory)]
        [int]$MaxBlobSizeMB
    )

    $ingestionConfig = Get-XdrAzureDataExplorerIngestionConfiguration -IngestionUri $IngestionUri -Token $Token
    if ($ingestionConfig.containerSettings.preferredUploadMethod -and $ingestionConfig.containerSettings.preferredUploadMethod -ne 'Storage') {
        throw "Azure Data Explorer returned preferred upload method '$($ingestionConfig.containerSettings.preferredUploadMethod)'. This cmdlet currently supports only Storage-based queued ingestion."
    }

    $containerPath = @($ingestionConfig.containerSettings.containers)[0].path
    if ([string]::IsNullOrWhiteSpace($containerPath)) {
        throw "Azure Data Explorer did not return a writable storage container path for queued ingestion."
    }

    $serviceMaxDataSizeBytes = if ($ingestionConfig.ingestionSettings.maxDataSize) {
        [int64]$ingestionConfig.ingestionSettings.maxDataSize
    }
    else {
        6GB
    }

    $maxBlobsPerRequest = if ($ingestionConfig.ingestionSettings.maxBlobsPerBatch) {
        [int]$ingestionConfig.ingestionSettings.maxBlobsPerBatch
    }
    else {
        20
    }

    $refreshInterval = $null
    if (-not [string]::IsNullOrWhiteSpace($ingestionConfig.containerSettings.refreshInterval)) {
        try {
            $refreshInterval = [TimeSpan]::Parse([string]$ingestionConfig.containerSettings.refreshInterval)
        }
        catch {
            Write-Verbose "Could not parse the Azure Data Explorer ingestion configuration refresh interval '$($ingestionConfig.containerSettings.refreshInterval)'."
        }
    }

    [pscustomobject]@{
        ContainerPath            = [string]$containerPath
        ServiceMaxDataSizeBytes  = $serviceMaxDataSizeBytes
        TargetMaxBlobSizeBytes   = [Math]::Min(([int64]$MaxBlobSizeMB * 1MB), $serviceMaxDataSizeBytes)
        MaxBlobsPerRequest       = $maxBlobsPerRequest
        RefreshInterval          = $refreshInterval
        RetrievedAtUtc           = [DateTime]::UtcNow
        PreferredIngestionMethod = [string]$ingestionConfig.ingestionSettings.preferredIngestionMethod
    }
}

function Test-XdrAzureDataExplorerIngestionConfigurationRefreshDue {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $Configuration
    )

    if ($null -eq $Configuration.RefreshInterval) {
        return $false
    }

    if ($Configuration.RefreshInterval.TotalSeconds -le 0) {
        return $true
    }

    return (([DateTime]::UtcNow - $Configuration.RetrievedAtUtc) -ge $Configuration.RefreshInterval)
}

function Get-XdrAzureDataExplorerBlobUri {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$ContainerUri,

        [Parameter(Mandatory)]
        [string]$BlobName
    )

    $container = [uri]$ContainerUri
    $builder = [System.UriBuilder]::new($container)
    $basePath = $builder.Path.TrimEnd('/')
    $builder.Path = "$basePath/$BlobName"
    $builder.Uri.AbsoluteUri
}

function Compress-XdrFileToGzip {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$DestinationPath
    )

    $inputStream = [System.IO.File]::OpenRead($SourcePath)
    try {
        $outputStream = [System.IO.File]::Create($DestinationPath)
        try {
            $gzipStream = [System.IO.Compression.GzipStream]::new($outputStream, [System.IO.Compression.CompressionLevel]::Optimal)
            try {
                $inputStream.CopyTo($gzipStream)
            }
            finally {
                $gzipStream.Dispose()
            }
        }
        finally {
            $outputStream.Dispose()
        }
    }
    finally {
        $inputStream.Dispose()
    }

    return $DestinationPath
}

function Send-XdrAzureDataExplorerBlobUpload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$BlobUri,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [switch]$Compressed
    )

    $headers = @{
        'x-ms-blob-type' = 'BlockBlob'
        'x-ms-version'   = '2023-11-03'
    }

    $contentType = if ($Compressed) { 'application/gzip' } else { 'application/json' }

    $null = Invoke-WebRequest -UseBasicParsing -Uri $BlobUri -Method Put -InFile $FilePath -Headers $headers -ContentType $contentType -ErrorAction Stop -Verbose:$false
}

function Send-XdrAzureDataExplorerQueuedIngestion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$IngestionUri,

        [Parameter(Mandatory)]
        [string]$Database,

        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [string]$MappingName,

        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter(Mandatory)]
        [hashtable[]]$Blobs,

        [switch]$TrackIngestion
    )

    $properties = @{
        format                    = 'json'
        deleteAfterDownload       = $true
        ingestionMappingReference = $MappingName
    }

    if ($TrackIngestion) {
        $properties.enableTracking = $true
    }

    $body = @{
        timestamp  = [DateTime]::UtcNow.ToString('o')
        blobs      = @($Blobs)
        properties = $properties
    }

    Invoke-XdrAzureDataExplorerRestRequest -BaseUri $IngestionUri -Path "/v1/rest/ingestion/queued/$Database/$TableName" -Method POST -Token $Token -Body $body
}

function Submit-XdrAzureDataExplorerQueuedIngestionBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$IngestionUri,

        [Parameter(Mandatory)]
        [string]$Database,

        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [string]$MappingName,

        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter(Mandatory)]
        [System.Collections.Generic.List[hashtable]]$PendingBlobs,

        [Parameter(Mandatory)]
        [ref]$PendingRawSizeBytes,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$QueuedOperationIds,

        [switch]$TrackIngestion
    )

    if ($PendingBlobs.Count -le 0) {
        return $null
    }

    $response = Send-XdrAzureDataExplorerQueuedIngestion -IngestionUri $IngestionUri `
        -Database $Database `
        -TableName $TableName `
        -MappingName $MappingName `
        -Token $Token `
        -Blobs ($PendingBlobs.ToArray()) `
        -TrackIngestion:$TrackIngestion

    if ($response.ingestionOperationId) {
        $QueuedOperationIds.Add([string]$response.ingestionOperationId) | Out-Null
    }

    $PendingBlobs.Clear()
    $PendingRawSizeBytes.Value = 0L

    return $response
}

function Get-XdrAzureDataExplorerQueuedIngestionStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [uri]$IngestionUri,

        [Parameter(Mandatory)]
        [string]$Database,

        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [string]$OperationId,

        [Parameter(Mandatory)]
        [string]$Token,

        [switch]$Details
    )

    $path = "/v1/rest/ingestion/queued/$([uri]::EscapeDataString($Database))/$([uri]::EscapeDataString($TableName))/$([uri]::EscapeDataString($OperationId))"
    if ($Details) {
        $path += '?details=true'
    }

    $response = Invoke-XdrAzureDataExplorerRestRequest -BaseUri $IngestionUri -Path $path -Method GET -Token $Token
    $status = $response.status
    $succeeded = if ($null -ne $status.Succeeded) { [int]$status.Succeeded } else { 0 }
    $failed = if ($null -ne $status.Failed) { [int]$status.Failed } else { 0 }
    $inProgress = if ($null -ne $status.InProgress) { [int]$status.InProgress } else { 0 }
    $canceled = if ($null -ne $status.Canceled) { [int]$status.Canceled } else { 0 }
    $knownCount = $succeeded + $failed + $inProgress + $canceled

    $detailItems = if ($Details -and $response.details) {
        @(
            foreach ($detail in @($response.details)) {
                [pscustomobject]@{
                    SourceId      = $detail.sourceId
                    Url           = $detail.url
                    Status        = $detail.status
                    StartTime     = $detail.startTime
                    LastUpdated   = $detail.lastUpdated
                    ErrorCode     = $detail.errorCode
                    FailureStatus = $detail.failureStatus
                    Details       = $detail.details
                }
            }
        )
    }
    else {
        $null
    }

    [pscustomobject]@{
        OperationId = $OperationId
        Status      = if ($failed -gt 0) {
            'Failed'
        }
        elseif ($canceled -gt 0) {
            'Canceled'
        }
        elseif ($inProgress -gt 0 -or $knownCount -eq 0) {
            'InProgress'
        }
        elseif ($succeeded -gt 0) {
            'Succeeded'
        }
        else {
            'Unknown'
        }
        Succeeded   = $succeeded
        Failed      = $failed
        InProgress  = $inProgress
        Canceled    = $canceled
        StartTime   = $response.startTime
        LastUpdated = $response.lastUpdated
        IsTerminal  = ($knownCount -gt 0 -and $inProgress -eq 0)
        HasFailures = ($failed -gt 0 -or $canceled -gt 0)
        Details     = $detailItems
    }
}

function Wait-XdrAzureDataExplorerQueuedIngestion {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [uri]$IngestionUri,

        [Parameter(Mandatory)]
        [string]$Database,

        [Parameter(Mandatory)]
        [string]$TableName,

        [Parameter(Mandatory)]
        [string[]]$OperationId,

        [Parameter(Mandatory)]
        [string]$Token,

        [ValidateRange(1, 1440)]
        [int]$TimeoutMinutes = 30,

        [ValidateRange(1, 300)]
        [int]$PollingIntervalSeconds = 15,

        [switch]$Details
    )

    $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
    do {
        [pscustomobject[]]$statuses = @(
            foreach ($currentOperationId in $OperationId) {
                Get-XdrAzureDataExplorerQueuedIngestionStatus -IngestionUri $IngestionUri `
                    -Database $Database `
                    -TableName $TableName `
                    -OperationId $currentOperationId `
                    -Token $Token `
                    -Details:$Details
            }
        )

        if (@($statuses | Where-Object { -not $_.IsTerminal }).Count -eq 0) {
            return [pscustomobject[]]$statuses
        }

        if ([DateTime]::UtcNow -ge $deadline) {
            $statusSummary = $statuses | ForEach-Object {
                "$($_.OperationId): $($_.Status) (Succeeded=$($_.Succeeded), InProgress=$($_.InProgress), Failed=$($_.Failed), Canceled=$($_.Canceled))"
            }
            throw "Timed out waiting for Azure Data Explorer queued ingestion to finish. Last status: $($statusSummary -join '; ')"
        }

        Start-Sleep -Seconds $PollingIntervalSeconds
    } while ($true)
}
