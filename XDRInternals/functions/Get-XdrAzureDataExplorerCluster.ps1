function Get-XdrAzureDataExplorerCluster {
    <#
    .SYNOPSIS
        Discovers accessible Azure Data Explorer clusters and databases.

    .DESCRIPTION
        Enumerates Azure Data Explorer (Microsoft.Kusto) clusters visible to the current Azure
        auth context through Azure Resource Manager, and also includes Azure Data Explorer free
        clusters exposed through the web control plane. When requested, it also lists databases for
        each cluster so you can quickly bootstrap Set-XdrAzureDataExplorerConnection without
        hunting for portal details manually.

        Authentication uses the module's standard Azure token flow: explicit token, Az.Accounts,
        Azure CLI, browser-derived ESTS bridge, or managed identity.

        Each returned cluster includes DiscoveryStatus metadata. IsComplete is false when a provider
        or requested database enumeration failed, and Failures identifies the provider, scope, and
        error. Partial results are returned with a warning. Supplying -SubscriptionId intentionally
        scopes discovery to Azure Resource Manager and does not count skipped free-cluster discovery
        as a failure.

    .PARAMETER SubscriptionId
        Optional subscription IDs to query. When omitted, all accessible subscriptions are enumerated.

    .PARAMETER ClusterName
        Optional cluster name filter. Wildcards are supported.

    .PARAMETER DatabaseName
        Optional database name filter. Wildcards are supported and imply -IncludeDatabases.

    .PARAMETER IncludeDatabases
        Includes Azure Data Explorer databases for each returned cluster.

    .PARAMETER TenantId
        Optional tenant ID used during Azure token acquisition.

    .PARAMETER ManagedIdentityClientId
        Optional user-assigned managed identity client ID for token acquisition via IMDS.

    .PARAMETER AccessToken
        Optional explicit Azure Resource Manager bearer token.

    .PARAMETER RequestTimeout
        Optional HTTP timeout for discovery requests. Default is 60 seconds.

    .EXAMPLE
        Get-XdrAzureDataExplorerCluster

        Lists Azure Data Explorer clusters visible to the current Azure auth context, including
        accessible free clusters.

    .EXAMPLE
        Get-XdrAzureDataExplorerCluster -IncludeDatabases

        Lists clusters together with their databases.

    .EXAMPLE
        Get-XdrAzureDataExplorerCluster -ClusterName 'my*' -DatabaseName 'Investigations'

        Finds clusters whose names match "my*" and includes only databases matching "Investigations".
    #>
    [OutputType('XdrAzureDataExplorerCluster')]
    [CmdletBinding()]
    param(
        [string[]]$SubscriptionId,

        [SupportsWildcards()]
        [string]$ClusterName,

        [SupportsWildcards()]
        [string]$DatabaseName,

        [switch]$IncludeDatabases,

        [string]$TenantId,

        [string]$ManagedIdentityClientId,

        [string]$AccessToken,

        [ValidateRange(1, 600)]
        [int]$RequestTimeout = 60
    )

    begin {
        $databaseFilterRequested = -not [string]::IsNullOrWhiteSpace($DatabaseName)
        $includeDatabaseList = $IncludeDatabases -or $databaseFilterRequested
        $subscriptions = @()
        $effectiveTenantId = $TenantId
        $armTokensByTenant = @{}
        $discoveryFailures = [System.Collections.Generic.List[object]]::new()

        $addDiscoveryFailure = {
            param(
                [Parameter(Mandatory)]
                [string]$Provider,

                [Parameter(Mandatory)]
                [string]$Scope,

                [Parameter(Mandatory)]
                $ErrorRecord
            )

            $message = if ($ErrorRecord.Exception) {
                [string]$ErrorRecord.Exception.Message
            }
            else {
                [string]$ErrorRecord
            }
            $discoveryFailures.Add([pscustomobject]@{
                    Provider = $Provider
                    Scope    = $Scope
                    Message  = $message
                }) | Out-Null
        }

        $getArmToken = {
            param(
                [string]$RequestedTenantId
            )

            $tokenCacheKey = if ([string]::IsNullOrWhiteSpace($RequestedTenantId)) {
                '__default__'
            }
            else {
                $RequestedTenantId.Trim()
            }

            if (-not $armTokensByTenant.ContainsKey($tokenCacheKey)) {
                $armTokensByTenant[$tokenCacheKey] = Get-XdrAzureAccessToken -Resource 'https://management.azure.com/' `
                    -Scope 'https://management.azure.com/.default' `
                    -TenantId $RequestedTenantId `
                    -ManagedIdentityClientId $ManagedIdentityClientId `
                    -AccessToken $AccessToken `
                    -ResourceDisplayName 'Azure Resource Manager'
            }

            return [string]$armTokensByTenant[$tokenCacheKey]
        }

        if ([string]::IsNullOrWhiteSpace($effectiveTenantId)) {
            try {
                $cachedTenantId = Get-XdrCache -CacheKey 'XdrTenantId' -ErrorAction SilentlyContinue
                if ($cachedTenantId -and -not [string]::IsNullOrWhiteSpace([string]$cachedTenantId.Value)) {
                    $effectiveTenantId = [string]$cachedTenantId.Value
                }
            }
            catch {
                Write-Verbose "Could not read the cached tenant ID while preparing Azure Data Explorer discovery: $($_.Exception.Message)"
            }
        }

        try {
            $token = & $getArmToken $effectiveTenantId

            if ($SubscriptionId) {
                $subscriptions = foreach ($currentSubscriptionId in $SubscriptionId) {
                    try {
                        $subscriptionMetadata = Invoke-XdrAzureResourceManagerRequest -Path "/subscriptions/$currentSubscriptionId?api-version=2022-12-01" -Token $token -TimeoutSec $RequestTimeout
                        [pscustomobject]@{
                            subscriptionId = $currentSubscriptionId
                            displayName    = $subscriptionMetadata.displayName
                            tenantId       = if ([string]::IsNullOrWhiteSpace([string]$subscriptionMetadata.tenantId)) { $effectiveTenantId } else { [string]$subscriptionMetadata.tenantId }
                            state          = $subscriptionMetadata.state
                        }
                    }
                    catch {
                        & $addDiscoveryFailure 'AzureResourceManager' "Subscription $currentSubscriptionId metadata" $_
                        Write-Verbose "Could not retrieve metadata for subscription '$currentSubscriptionId' before Azure Data Explorer discovery: $($_.Exception.Message)"
                        [pscustomobject]@{
                            subscriptionId = $currentSubscriptionId
                            displayName    = $null
                            tenantId       = $effectiveTenantId
                            state          = $null
                        }
                    }
                }
            }
            else {
                $subscriptions = Get-XdrAzureResourceManagerCollection -Path '/subscriptions?api-version=2022-12-01' -Token $token -TimeoutSec $RequestTimeout
            }
        }
        catch {
            & $addDiscoveryFailure 'AzureResourceManager' 'Subscription discovery' $_
            Write-Verbose "Azure Resource Manager discovery setup failed: $($_.Exception.Message)"
        }
    }

    process {
        $results = [System.Collections.Generic.List[object]]::new()

        foreach ($subscription in @($subscriptions)) {
            $currentSubscriptionId = [string]$subscription.subscriptionId
            if ([string]::IsNullOrWhiteSpace($currentSubscriptionId)) {
                continue
            }

            $currentSubscriptionTenantId = if ([string]::IsNullOrWhiteSpace([string]$subscription.tenantId)) {
                $effectiveTenantId
            }
            else {
                [string]$subscription.tenantId
            }

            try {
                $subscriptionToken = & $getArmToken $currentSubscriptionTenantId
            }
            catch {
                & $addDiscoveryFailure 'AzureResourceManager' "Subscription $currentSubscriptionId token acquisition" $_
                Write-Verbose "Azure Resource Manager token acquisition failed for subscription '$currentSubscriptionId': $($_.Exception.Message)"
                continue
            }

            Write-Verbose "Enumerating Azure Data Explorer clusters in subscription '$currentSubscriptionId'"
            try {
                $clusters = Get-XdrAzureResourceManagerCollection -Path "/subscriptions/$currentSubscriptionId/providers/Microsoft.Kusto/clusters?api-version=2024-04-13" -Token $subscriptionToken -TimeoutSec $RequestTimeout
            }
            catch {
                & $addDiscoveryFailure 'AzureResourceManager' "Subscription $currentSubscriptionId cluster enumeration" $_
                Write-Verbose "Azure Data Explorer cluster enumeration failed for subscription '$currentSubscriptionId': $($_.Exception.Message)"
                continue
            }

            foreach ($cluster in @($clusters)) {
                $clusterResourceId = [string]$cluster.id
                $resourceGroupName = $null
                if ($clusterResourceId -match '/resourceGroups/([^/]+)/providers/Microsoft\.Kusto/clusters/([^/]+)$') {
                    $resourceGroupName = $Matches[1]
                }

                $clusterRecord = [pscustomobject]@{
                    PSTypeName        = 'XdrAzureDataExplorerCluster'
                    SubscriptionId    = $currentSubscriptionId
                    SubscriptionName  = $subscription.displayName
                    TenantId          = $subscription.tenantId
                    ResourceGroupName = $resourceGroupName
                    ClusterName       = $cluster.name
                    ClusterUri        = $cluster.properties.uri
                    IngestionUri      = $cluster.properties.dataIngestionUri
                    Location          = $cluster.location
                    State             = $cluster.properties.state
                    ProvisioningState = $cluster.properties.provisioningState
                    SkuName           = $cluster.sku.name
                    SkuTier           = $cluster.sku.tier
                    ResourceId        = $clusterResourceId
                    Databases         = @()
                }

                if ($PSBoundParameters.ContainsKey('ClusterName') -and ($clusterRecord.ClusterName -notlike $ClusterName)) {
                    continue
                }

                if ($includeDatabaseList) {
                    $databaseEnumerationFailed = $false
                    if ([string]::IsNullOrWhiteSpace($resourceGroupName)) {
                        $resourceIdError = "The resource group could not be parsed from '$clusterResourceId'."
                        & $addDiscoveryFailure 'AzureResourceManager' "Cluster $($clusterRecord.ClusterName) database enumeration" $resourceIdError
                        Write-Warning "Skipping database enumeration for cluster '$($clusterRecord.ClusterName)' because $resourceIdError"
                    }
                    else {
                        Write-Verbose "Enumerating Azure Data Explorer databases for cluster '$($clusterRecord.ClusterName)'"
                        try {
                            $databases = Get-XdrAzureResourceManagerCollection -Path "/subscriptions/$currentSubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Kusto/clusters/$($clusterRecord.ClusterName)/databases?api-version=2024-04-13" -Token $subscriptionToken -TimeoutSec $RequestTimeout

                            $clusterRecord.Databases = @(
                                foreach ($database in @($databases)) {
                                    $databaseNameValue = [string]$database.name
                                    if ($databaseNameValue.Contains('/')) {
                                        $databaseNameValue = $databaseNameValue.Split('/')[-1]
                                    }

                                    if ($databaseFilterRequested -and ($databaseNameValue -notlike $DatabaseName)) {
                                        continue
                                    }

                                    [pscustomobject]@{
                                        PSTypeName        = 'XdrAzureDataExplorerDatabase'
                                        SubscriptionId    = $currentSubscriptionId
                                        ResourceGroupName = $resourceGroupName
                                        ClusterName       = $clusterRecord.ClusterName
                                        DatabaseName      = $databaseNameValue
                                        Kind              = $database.kind
                                        Location          = $database.location
                                        ProvisioningState = $database.properties.provisioningState
                                        SoftDeletePeriod  = $database.properties.softDeletePeriod
                                        HotCachePeriod    = $database.properties.hotCachePeriod
                                        ResourceId        = $database.id
                                    }
                                }
                            )
                        }
                        catch {
                            $databaseEnumerationFailed = $true
                            & $addDiscoveryFailure 'AzureResourceManager' "Cluster $($clusterRecord.ClusterName) database enumeration" $_
                            Write-Verbose "Azure Data Explorer database enumeration failed for cluster '$($clusterRecord.ClusterName)': $($_.Exception.Message)"
                        }
                    }

                    if ($databaseEnumerationFailed -and $databaseFilterRequested) {
                        continue
                    }

                    if ($databaseFilterRequested -and @($clusterRecord.Databases).Count -eq 0) {
                        continue
                    }
                }

                $results.Add($clusterRecord) | Out-Null
            }
        }

        if (-not $PSBoundParameters.ContainsKey('SubscriptionId')) {
            try {
                Write-Verbose 'Enumerating Azure Data Explorer free clusters'
                $freeClusterToken = Get-XdrAzureAccessToken -Resource 'https://help.kusto.windows.net' `
                    -Scope 'https://help.kusto.windows.net/.default' `
                    -TenantId $effectiveTenantId `
                    -ManagedIdentityClientId $ManagedIdentityClientId `
                    -ResourceDisplayName 'Azure Data Explorer Free Cluster Discovery'

                $freeClusters = @(Invoke-XdrAzureDataExplorerRestRequest `
                        -BaseUri 'https://saasrp.kusto.windows.net' `
                        -Path '/v1/rest/SaasRp/clusters' `
                        -Method GET `
                        -Token $freeClusterToken `
                        -TimeoutSec $RequestTimeout `
                        -RetryCount 10)

                $freeClusterDataToken = $null
                if ($includeDatabaseList -and @($freeClusters).Count -gt 0) {
                    $freeClusterDataToken = Get-XdrAzureAccessToken -Resource 'https://kusto.kusto.windows.net' `
                        -Scope 'https://kusto.kusto.windows.net/.default' `
                        -TenantId $effectiveTenantId `
                        -ManagedIdentityClientId $ManagedIdentityClientId `
                        -ResourceDisplayName 'Azure Data Explorer Free Cluster Data'
                }

                foreach ($cluster in @($freeClusters)) {
                    $clusterDisplayName = if ([string]::IsNullOrWhiteSpace([string]$cluster.defaultDisplayName)) {
                        [string]$cluster.id
                    }
                    else {
                        [string]$cluster.defaultDisplayName
                    }

                    $clusterUri = [string]$cluster.engineUrl
                    $clusterHost = $null
                    if (-not [string]::IsNullOrWhiteSpace($clusterUri)) {
                        try {
                            $clusterHost = ([uri]$clusterUri).DnsSafeHost
                        }
                        catch {
                            Write-Verbose "Could not parse free cluster URI '$clusterUri' while applying the cluster filter."
                        }
                    }

                    $clusterMatches = $true
                    if ($PSBoundParameters.ContainsKey('ClusterName')) {
                        $clusterMatches = @(
                            $clusterDisplayName,
                            [string]$cluster.id,
                            $clusterHost
                        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -like $ClusterName } | Select-Object -First 1

                        $clusterMatches = [bool]$clusterMatches
                    }

                    if (-not $clusterMatches) {
                        continue
                    }

                    $clusterRecord = [pscustomobject]@{
                        PSTypeName        = 'XdrAzureDataExplorerCluster'
                        SubscriptionId    = $null
                        SubscriptionName  = $null
                        TenantId          = $effectiveTenantId
                        ResourceGroupName = $null
                        ClusterName       = $clusterDisplayName
                        ClusterUri        = $cluster.engineUrl
                        IngestionUri      = $cluster.dmUrl
                        Location          = $cluster.region
                        State             = $cluster.state
                        ProvisioningState = $cluster.state
                        SkuName           = 'FreeCluster'
                        SkuTier           = 'Free'
                        ResourceId        = $cluster.id
                        Databases         = @()
                    }

                    if ($includeDatabaseList) {
                        Write-Verbose "Enumerating Azure Data Explorer databases for free cluster '$($clusterRecord.ClusterName)'"
                        $databaseEnumerationFailed = $false
                        try {
                            $databaseResponse = Invoke-XdrAzureDataExplorerRestRequest `
                                -BaseUri $clusterRecord.ClusterUri `
                                -Path '/v1/rest/mgmt' `
                                -Method POST `
                                -Token $freeClusterDataToken `
                                -TimeoutSec $RequestTimeout `
                                -Body @{
                                csl        = '.show databases'
                                properties = $null
                            }

                            $clusterRecord.Databases = @(
                                foreach ($database in @(ConvertFrom-XdrAzureDataExplorerResponseTable -Response $databaseResponse)) {
                                    $databaseNameValue = [string]$database.DatabaseName
                                    if ([string]::IsNullOrWhiteSpace($databaseNameValue)) {
                                        continue
                                    }

                                    if ($databaseFilterRequested -and ($databaseNameValue -notlike $DatabaseName)) {
                                        continue
                                    }

                                    [pscustomobject]@{
                                        PSTypeName        = 'XdrAzureDataExplorerDatabase'
                                        SubscriptionId    = $null
                                        ResourceGroupName = $null
                                        ClusterName       = $clusterRecord.ClusterName
                                        DatabaseName      = $databaseNameValue
                                        Kind              = $database.DatabaseAccessMode
                                        Location          = $clusterRecord.Location
                                        ProvisioningState = $null
                                        SoftDeletePeriod  = $null
                                        HotCachePeriod    = $null
                                        ResourceId        = $null
                                    }
                                }
                            )
                        }
                        catch {
                            $databaseEnumerationFailed = $true
                            & $addDiscoveryFailure 'FreeCluster' "Cluster $($clusterRecord.ClusterName) database enumeration" $_
                            Write-Verbose "Azure Data Explorer database enumeration failed for free cluster '$($clusterRecord.ClusterName)': $($_.Exception.Message)"
                        }

                        if ($databaseEnumerationFailed -and $databaseFilterRequested) {
                            continue
                        }

                        if ($databaseFilterRequested -and @($clusterRecord.Databases).Count -eq 0) {
                            continue
                        }
                    }

                    $results.Add($clusterRecord) | Out-Null
                }
            }
            catch {
                & $addDiscoveryFailure 'FreeCluster' 'Cluster discovery' $_
                Write-Verbose "Azure Data Explorer free-cluster discovery failed: $($_.Exception.Message)"
            }
        }

        if ($results.Count -eq 0 -and $discoveryFailures.Count -gt 0) {
            $discoveryMessages = @(
                $discoveryFailures |
                    ForEach-Object { $_.Message } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Select-Object -Unique
            )

            if (@($discoveryMessages).Count -eq 1) {
                throw $discoveryMessages[0]
            }

            throw "Azure Data Explorer discovery failed. $($discoveryMessages -join ' | ')"
        }

        $discoveryStatus = [pscustomobject]@{
            IsComplete = $discoveryFailures.Count -eq 0
            Failures   = @($discoveryFailures.ToArray())
        }

        if (-not $discoveryStatus.IsComplete) {
            $failureSummary = $discoveryStatus.Failures | ForEach-Object {
                "$($_.Provider) [$($_.Scope)]: $($_.Message)"
            }
            Write-Warning "Azure Data Explorer discovery returned partial results. $($failureSummary -join ' | ')"
        }

        foreach ($clusterResult in $results) {
            $clusterResult | Add-Member -NotePropertyName DiscoveryStatus -NotePropertyValue $discoveryStatus -Force
            $clusterResult
        }
    }
}
