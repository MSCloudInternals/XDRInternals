function Get-XdrAzureDataExplorerConnection {
    [CmdletBinding()]
    param()

    process {
        if (-not $script:AzureDataExplorerConnection) {
            throw "Azure Data Explorer connection not configured. Run Set-XdrAzureDataExplorerConnection first."
        }

        return $script:AzureDataExplorerConnection
    }
}

function Test-XdrAzureDataExplorerServiceUri {
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$Uri
    )

    if (-not $Uri.IsAbsoluteUri -or $Uri.Scheme -ne 'https' -or -not $Uri.IsDefaultPort) {
        return $false
    }

    $hostName = $Uri.DnsSafeHost
    foreach ($suffix in @(
            '.kusto.windows.net',
            '.kustodev.windows.net',
            '.kusto.usgovcloudapi.net',
            '.kusto.chinacloudapi.cn',
            '.kusto.cloudapi.de'
        )) {
        if ($hostName.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase) -and $hostName.Length -gt $suffix.Length) {
            return $true
        }
    }

    return $false
}

function Resolve-XdrAzureDataExplorerUris {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri]$ClusterUri,

        [uri]$IngestionUri
    )

    $normalizedClusterUri = [uri]$ClusterUri.GetLeftPart([System.UriPartial]::Authority)
    if (-not (Test-XdrAzureDataExplorerServiceUri -Uri $normalizedClusterUri)) {
        throw "Azure Data Explorer cluster URI must use HTTPS on a trusted Azure Data Explorer service host."
    }
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

    if (-not (Test-XdrAzureDataExplorerServiceUri -Uri $normalizedIngestionUri)) {
        throw "Azure Data Explorer ingestion URI must use HTTPS on a trusted Azure Data Explorer service host."
    }

    [pscustomobject]@{
        ClusterUri   = [uri]$clusterBuilder.Uri.GetLeftPart([System.UriPartial]::Authority)
        IngestionUri = $normalizedIngestionUri
    }
}

function Select-XdrAzureDataExplorerDiscoveredValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Heading,

        [Parameter(Mandatory)]
        [string]$Prompt,

        [Parameter(Mandatory)]
        [object[]]$Items,

        [Parameter(Mandatory)]
        [scriptblock]$DisplayScript,

        [switch]$NonInteractive,

        [string]$AmbiguousSelectionMessage = 'Multiple Azure Data Explorer values matched the requested discovery criteria in non-interactive mode.'
    )

    $resolvedItems = @($Items)
    if ($resolvedItems.Count -eq 0) {
        return $null
    }

    if ($resolvedItems.Count -eq 1) {
        return $resolvedItems[0]
    }

    if ($NonInteractive) {
        throw $AmbiguousSelectionMessage
    }

    Write-Information $Heading -InformationAction Continue
    for ($i = 0; $i -lt $resolvedItems.Count; $i++) {
        $displayValue = & $DisplayScript $resolvedItems[$i]
        Write-Information "  [$($i + 1)] $displayValue" -InformationAction Continue
    }

    while ($true) {
        $selection = Read-Host $Prompt
        $index = 0
        if ([int]::TryParse([string]$selection, [ref]$index) -and $index -ge 1 -and $index -le $resolvedItems.Count) {
            return $resolvedItems[$index - 1]
        }

        Write-Information 'Invalid selection. Try again.' -InformationAction Continue
    }
}

function Resolve-XdrAzureDataExplorerDiscoveredConnection {
    [CmdletBinding()]
    param(
        [string[]]$SubscriptionId,

        [SupportsWildcards()]
        [string]$ClusterName,

        [SupportsWildcards()]
        [string]$DatabaseName,

        [string]$TenantId,

        [string]$ManagedIdentityClientId,

        [switch]$NonInteractive,

        [switch]$AllowPartialDiscovery,

        [ValidateRange(1, 600)]
        [int]$RequestTimeout = 60
    )

    $discoveryParams = @{
        IncludeDatabases        = $true
        TenantId                = $TenantId
        ManagedIdentityClientId = $ManagedIdentityClientId
        RequestTimeout          = $RequestTimeout
    }

    if ($SubscriptionId) {
        $discoveryParams['SubscriptionId'] = $SubscriptionId
    }

    if (-not [string]::IsNullOrWhiteSpace($ClusterName)) {
        $discoveryParams['ClusterName'] = $ClusterName
    }

    if (-not [string]::IsNullOrWhiteSpace($DatabaseName)) {
        $discoveryParams['DatabaseName'] = $DatabaseName
    }

    $clusters = @(Get-XdrAzureDataExplorerCluster @discoveryParams)
    if ($clusters.Count -eq 0) {
        throw 'No Azure Data Explorer clusters matched the requested discovery criteria.'
    }

    $partialDiscoveryFailures = @(
        $clusters | ForEach-Object {
            if ($null -ne $_.DiscoveryStatus -and -not $_.DiscoveryStatus.IsComplete) {
                $_.DiscoveryStatus.Failures
            }
        }
    )
    if ($partialDiscoveryFailures.Count -gt 0 -and -not $AllowPartialDiscovery) {
        $failureSummary = @(
            $partialDiscoveryFailures | ForEach-Object {
                "$($_.Provider) [$($_.Scope)]: $($_.Message)"
            }
        ) | Select-Object -Unique
        throw "Azure Data Explorer connection discovery was incomplete and automatic selection was stopped. $($failureSummary -join ' | ') Re-run with -AllowPartialDiscovery to select from the partial results, or narrow discovery with -SubscriptionId."
    }

    $selectedCluster = Select-XdrAzureDataExplorerDiscoveredValue `
        -Heading 'Available Azure Data Explorer clusters:' `
        -Prompt "Select cluster [1-$($clusters.Count)]" `
        -Items $clusters `
        -NonInteractive:$NonInteractive `
        -AmbiguousSelectionMessage 'Multiple Azure Data Explorer clusters matched the requested discovery criteria in non-interactive mode. Narrow the match with -ClusterName or -SubscriptionId, or specify -ClusterUri and -Database explicitly.' `
        -DisplayScript {
            param($Cluster)

            $subscriptionLabel = if ([string]::IsNullOrWhiteSpace([string]$Cluster.SubscriptionId)) {
                'Free/personal'
            }
            elseif ([string]::IsNullOrWhiteSpace([string]$Cluster.SubscriptionName)) {
                [string]$Cluster.SubscriptionId
            }
            else {
                "$($Cluster.SubscriptionName) [$($Cluster.SubscriptionId)]"
            }

            $databaseCount = @($Cluster.Databases).Count
            $databaseLabel = if ($databaseCount -eq 1) {
                '1 database'
            }
            elseif ($databaseCount -gt 1) {
                "$databaseCount databases"
            }
            else {
                'no databases discovered'
            }

            $stateLabel = if (-not [string]::IsNullOrWhiteSpace([string]$Cluster.ProvisioningState)) {
                [string]$Cluster.ProvisioningState
            }
            elseif (-not [string]::IsNullOrWhiteSpace([string]$Cluster.State)) {
                [string]$Cluster.State
            }
            else {
                'Unknown'
            }

            "$($Cluster.ClusterName) | $subscriptionLabel | $($Cluster.Location) | $($Cluster.SkuTier) | $databaseLabel | state: $stateLabel"
        }

    $databases = @($selectedCluster.Databases)
    if ($databases.Count -eq 0) {
        $stateFragments = [System.Collections.Generic.List[string]]::new()
        if (-not [string]::IsNullOrWhiteSpace([string]$selectedCluster.ProvisioningState)) {
            $stateFragments.Add("ProvisioningState=$($selectedCluster.ProvisioningState)") | Out-Null
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$selectedCluster.State) -and $selectedCluster.State -ne $selectedCluster.ProvisioningState) {
            $stateFragments.Add("State=$($selectedCluster.State)") | Out-Null
        }

        $stateSuffix = if ($stateFragments.Count -gt 0) {
            " ($($stateFragments -join ', '))"
        }
        else {
            ''
        }

        throw "No databases were discovered for cluster '$($selectedCluster.ClusterName)'$stateSuffix. Retry discovery when the cluster is ready, or configure the connection explicitly with -ClusterUri and -Database."
    }

    $selectedDatabase = Select-XdrAzureDataExplorerDiscoveredValue `
        -Heading "Available databases for '$($selectedCluster.ClusterName)':" `
        -Prompt "Select database [1-$($databases.Count)]" `
        -Items $databases `
        -NonInteractive:$NonInteractive `
        -AmbiguousSelectionMessage "Multiple databases were discovered for cluster '$($selectedCluster.ClusterName)' in non-interactive mode. Narrow the match with -DatabaseName, or specify -ClusterUri and -Database explicitly." `
        -DisplayScript {
            param($Database)

            if ([string]::IsNullOrWhiteSpace([string]$Database.Kind)) {
                return [string]$Database.DatabaseName
            }

            return "$($Database.DatabaseName) ($($Database.Kind))"
        }

    return [pscustomobject]@{
        ClusterName  = $selectedCluster.ClusterName
        ClusterUri   = [uri]$selectedCluster.ClusterUri
        IngestionUri = [uri]$selectedCluster.IngestionUri
        TenantId     = $selectedCluster.TenantId
        Database     = [string]$selectedDatabase.DatabaseName
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

function Test-XdrAzureDataExplorerTransientRestError {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        $ErrorRecord
    )

    $messages = [System.Collections.Generic.List[string]]::new()
    if ($ErrorRecord.Exception) {
        $currentException = $ErrorRecord.Exception
        while ($currentException) {
            if (-not [string]::IsNullOrWhiteSpace($currentException.Message)) {
                $messages.Add($currentException.Message) | Out-Null
            }
            $currentException = $currentException.InnerException
        }
    }
    if ($ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        $messages.Add($ErrorRecord.ErrorDetails.Message) | Out-Null
    }
    $messages.Add([string]$ErrorRecord) | Out-Null

    $message = $messages -join "`n"
    return (
        $message -match 'unexpected EOF' -or
        $message -match '0 bytes from the transport stream' -or
        $message -match 'transport stream' -or
        $message -match 'response ended prematurely' -or
        $message -match 'connection.*closed' -or
        $message -match 'connection.*reset'
    )
}

function Invoke-XdrRetryingAzureRestMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$RequestParams,

        [Parameter(Mandatory)]
        [uri]$RequestUri,

        [Parameter(Mandatory)]
        [string]$RequestDescription,

        [ValidateRange(1, 10)]
        [int]$RetryCount = 10
    )

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            return Invoke-RestMethod @RequestParams
        }
        catch {
            if (-not (Test-XdrAzureDataExplorerTransientRestError -ErrorRecord $_) -or $attempt -ge $RetryCount) {
                throw
            }

            $delaySeconds = [math]::Min([math]::Pow(2, $attempt - 1), 8)
            Write-Verbose "$RequestDescription to '$requestUri' failed with a transient transport error on attempt $attempt of $RetryCount. Retrying in $delaySeconds second(s)."
            Start-Sleep -Seconds $delaySeconds
        }
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

        $Body,

        [int]$TimeoutSec,

        [ValidateRange(1, 10)]
        [int]$RetryCount = 10
    )

    if (-not (Test-XdrAzureDataExplorerServiceUri -Uri $BaseUri)) {
        throw "Refusing to send an Azure Data Explorer bearer token to an untrusted endpoint."
    }

    $requestUri = [uri]::new($BaseUri, $Path)
    $headers = @{
        'Accept'                 = 'application/json'
        'Authorization'          = "Bearer $Token"
        'Connection'             = 'Close'
        'x-ms-app'               = 'XDRInternals'
        'x-ms-client-version'    = 'XDRInternals/1.0.12'
        'x-ms-client-request-id' = "XDRInternals.AzureDataExplorer;$([guid]::NewGuid())"
    }

    $requestParams = @{
        Uri         = $requestUri
        Method      = $Method
        Headers     = $headers
        ErrorAction = 'Stop'
        Verbose     = $false
    }

    if ($TimeoutSec -gt 0) {
        $requestParams['TimeoutSec'] = $TimeoutSec
    }

    if ($Method -eq 'POST') {
        $requestBody = if ($Body -is [string]) {
            $Body
        }
        else {
            $Body | ConvertTo-Json -Depth 20 -Compress
        }

        $requestParams['Method'] = 'Post'
        $requestParams['ContentType'] = 'application/json; charset=utf-8'
        $requestParams['Body'] = $requestBody
    }

    Invoke-XdrRetryingAzureRestMethod -RequestParams $requestParams -RequestUri $requestUri -RequestDescription 'Azure Data Explorer REST request' -RetryCount $RetryCount
}

function Invoke-XdrAzureResourceManagerRequest {
    [CmdletBinding()]
    param(
        [uri]$Uri,

        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Token,

        [int]$TimeoutSec,

        [ValidateRange(1, 10)]
        [int]$RetryCount = 10
    )

    if (-not $Uri -and [string]::IsNullOrWhiteSpace($Path)) {
        throw 'Specify either -Uri or -Path.'
    }

    $requestUri = if ($Uri) {
        $Uri
    }
    else {
        [uri]::new([uri]'https://management.azure.com/', $Path)
    }

    if (-not $requestUri.IsAbsoluteUri -or
        $requestUri.Scheme -ne 'https' -or
        -not $requestUri.IsDefaultPort -or
        $requestUri.DnsSafeHost -ne 'management.azure.com') {
        throw "Refusing to send an Azure Resource Manager bearer token to an untrusted endpoint."
    }

    $headers = @{
        'Accept'                 = 'application/json'
        'Authorization'          = "Bearer $Token"
        'Connection'             = 'Close'
        'x-ms-app'               = 'XDRInternals'
        'x-ms-client-version'    = 'XDRInternals/1.0.12'
        'x-ms-client-request-id' = "XDRInternals.AzureResourceManager;$([guid]::NewGuid())"
    }

    $requestParams = @{
        Uri         = $requestUri
        Method      = 'Get'
        Headers     = $headers
        ErrorAction = 'Stop'
        Verbose     = $false
    }

    if ($TimeoutSec -gt 0) {
        $requestParams['TimeoutSec'] = $TimeoutSec
    }

    Invoke-XdrRetryingAzureRestMethod -RequestParams $requestParams -RequestUri $requestUri -RequestDescription 'Azure Resource Manager request' -RetryCount $RetryCount
}

function Get-XdrAzureResourceManagerCollection {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Token,

        [int]$TimeoutSec
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = [uri]::new([uri]'https://management.azure.com/', $Path)
    $initialUri = $nextUri
    $initialQuery = [System.Web.HttpUtility]::ParseQueryString($initialUri.Query)
    $defaultApiVersion = $initialQuery['api-version']

    while ($nextUri) {
        $response = Invoke-XdrAzureResourceManagerRequest -Uri $nextUri -Token $Token -TimeoutSec $TimeoutSec
        foreach ($item in @($response.value)) {
            $items.Add($item) | Out-Null
        }

        if ([string]::IsNullOrWhiteSpace([string]$response.nextLink)) {
            $nextUri = $null
        }
        else {
            $nextUri = [uri]$response.nextLink
            if (-not [string]::IsNullOrWhiteSpace($defaultApiVersion)) {
                $nextQuery = [System.Web.HttpUtility]::ParseQueryString($nextUri.Query)
                if ([string]::IsNullOrWhiteSpace($nextQuery['api-version'])) {
                    $builder = [System.UriBuilder]::new($nextUri)
                    $nextQuery['api-version'] = $defaultApiVersion
                    $builder.Query = $nextQuery.ToString()
                    $nextUri = $builder.Uri
                }
            }
        }
    }

    return [object[]]$items.ToArray()
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

function Get-XdrAzureDataExplorerTableSchema {
    [CmdletBinding()]
    [OutputType([hashtable])]
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

    try {
        $response = Invoke-XdrAzureDataExplorerManagementCommand `
            -ClusterUri $ClusterUri `
            -Database $Database `
            -Command ".show table $TableName schema as json" `
            -Token $Token
        $schemaRow = @(ConvertFrom-XdrAzureDataExplorerResponseTable -Response $response) | Select-Object -First 1
        if (-not $schemaRow -or [string]::IsNullOrWhiteSpace([string]$schemaRow.Schema)) {
            return $null
        }

        $schema = [string]$schemaRow.Schema | ConvertFrom-Json -ErrorAction Stop
        $columns = @{}
        foreach ($column in @($schema.OrderedColumns)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$column.Name)) {
                $columns[[string]$column.Name] = [string]$column.CslType
            }
        }

        return $columns
    }
    catch {
        if (Test-XdrAzureDataExplorerNotFound -ErrorRecord $_) {
            return $null
        }

        throw
    }
}

function Get-XdrAzureDataExplorerMapping {
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
        [string]$Token
    )

    try {
        $escapedMappingName = $MappingName -replace "'", "''"
        $response = Invoke-XdrAzureDataExplorerManagementCommand `
            -ClusterUri $ClusterUri `
            -Database $Database `
            -Command ".show table $TableName ingestion json mappings | where Name == '$escapedMappingName'" `
            -Token $Token
        return @(ConvertFrom-XdrAzureDataExplorerResponseTable -Response $response) | Select-Object -First 1
    }
    catch {
        if (Test-XdrAzureDataExplorerNotFound -ErrorRecord $_) {
            return $null
        }

        throw
    }
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

    return $null -ne (Get-XdrAzureDataExplorerMapping -ClusterUri $ClusterUri -Database $Database -TableName $TableName -MappingName $MappingName -Token $Token)
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

        [hashtable]$TableProfile,

        [switch]$PreserveExistingMapping
    )

    $desiredColumns = if ($TableProfile) {
        @($TableProfile.Columns)
    }
    else {
        @(@{ Name = 'Event'; Type = 'dynamic' })
    }
    $columnSpec = ($desiredColumns | ForEach-Object { "$($_.Name):$($_.Type)" }) -join ', '
    $existingColumns = Get-XdrAzureDataExplorerTableSchema -ClusterUri $ClusterUri -Database $Database -TableName $TableName -Token $Token
    $missingColumns = [System.Collections.Generic.List[string]]::new()
    $incompatibleColumns = [System.Collections.Generic.List[string]]::new()

    if ($null -ne $existingColumns) {
        foreach ($column in $desiredColumns) {
            if (-not $existingColumns.ContainsKey([string]$column.Name)) {
                $missingColumns.Add([string]$column.Name) | Out-Null
                continue
            }

            $actualType = [string]$existingColumns[[string]$column.Name]
            if ($actualType -ine [string]$column.Type) {
                $incompatibleColumns.Add("$($column.Name) (expected $($column.Type), found $actualType)") | Out-Null
            }
        }
    }

    if ($incompatibleColumns.Count -gt 0) {
        throw "Azure Data Explorer table '$TableName' has incompatible column types: $($incompatibleColumns -join '; '). No schema or mapping changes were applied."
    }

    if ($null -eq $existingColumns -or $missingColumns.Count -gt 0) {
        $schemaAction = if ($null -eq $existingColumns) { 'Creating' } else { "Adding missing columns ($($missingColumns -join ', ')) to" }
        Write-Verbose "$schemaAction Azure Data Explorer table '$TableName' in database '$Database' with schema ($columnSpec)"
        $null = Invoke-XdrAzureDataExplorerManagementCommand -ClusterUri $ClusterUri -Database $Database -Command ".create-merge tables $TableName ($columnSpec)" -Token $Token
    }

    $mappingEntries = if ($TableProfile) {
        @($TableProfile.ColumnMappings | ForEach-Object {
                @{ column = $_.Column; Properties = @{ path = $_.Properties.Path } }
            })
    }
    else {
        @(@{ column = 'Event'; Properties = @{ path = '$' } })
    }
    $mapping = ConvertTo-Json -InputObject @($mappingEntries) -Depth 4 -Compress
    $existingMapping = Get-XdrAzureDataExplorerMapping -ClusterUri $ClusterUri -Database $Database -TableName $TableName -MappingName $MappingName -Token $Token

    if ($PreserveExistingMapping -and $existingMapping) {
        Write-Verbose "Preserving existing caller-owned Azure Data Explorer JSON mapping '$MappingName' on table '$TableName'."
        return
    }

    $mappingMatches = $false
    if ($existingMapping -and -not [string]::IsNullOrWhiteSpace([string]$existingMapping.Mapping)) {
        try {
            $existingEntries = @([string]$existingMapping.Mapping | ConvertFrom-Json -ErrorAction Stop)
            $existingSignature = @($existingEntries | ForEach-Object {
                    "$([string]$_.Column)|$([string]$_.DataType)|$([string]$_.Properties.Path)|$([string]$_.Properties.ConstValue)|$([string]$_.Properties.Transform)"
                }) -join "`n"
            $desiredSignature = @($mappingEntries | ForEach-Object {
                    "$([string]$_.column)||$([string]$_.Properties.path)||"
                }) -join "`n"
            $mappingMatches = $existingSignature -ceq $desiredSignature
        }
        catch {
            Write-Verbose "Existing Azure Data Explorer mapping '$MappingName' could not be normalized and will be replaced."
        }
    }

    if (-not $mappingMatches) {
        Write-Verbose "Converging Azure Data Explorer JSON mapping '$MappingName' on table '$TableName'"
        $null = Invoke-XdrAzureDataExplorerManagementCommand -ClusterUri $ClusterUri -Database $Database -Command ".create-or-alter table $TableName ingestion json mapping '$MappingName' '$mapping'" -Token $Token
    }
}

function Clear-XdrAzureDataExplorerExportState {
    [CmdletBinding()]
    param(
        [hashtable]$TableStates,

        [string]$SessionStagingPath,

        [switch]$KeepTempFiles,

        [Parameter(Mandatory)]
        [ref]$CleanupCompleted
    )

    if ($CleanupCompleted.Value) {
        return
    }

    $CleanupCompleted.Value = $true

    foreach ($tableState in @($TableStates.Values)) {
        if (-not $tableState.writer) {
            continue
        }

        try {
            $tableState.writer.Dispose()
        }
        catch {
            Write-Warning "Could not close an Azure Data Explorer staging writer: $($_.Exception.Message)"
        }
        finally {
            $tableState.writer = $null
        }
    }

    if (-not $KeepTempFiles -and
        -not [string]::IsNullOrWhiteSpace($SessionStagingPath) -and
        (Test-Path -LiteralPath $SessionStagingPath)) {
        Remove-Item -LiteralPath $SessionStagingPath -Recurse -Force -ErrorAction SilentlyContinue
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
        try {
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
        }
        catch {
            if (-not (Test-XdrAzureDataExplorerTransientRestError -ErrorRecord $_) -or [DateTime]::UtcNow -ge $deadline) {
                throw
            }

            Write-Verbose "Azure Data Explorer ingestion status polling for table '$TableName' hit a transient transport error. Retrying after $PollingIntervalSeconds second(s)."
            Start-Sleep -Seconds $PollingIntervalSeconds
            continue
        }

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
