function Set-XdrAzureDataExplorerConnection {
    <#
    .SYNOPSIS
        Configures Azure Data Explorer connection settings for export cmdlets.

    .DESCRIPTION
        Stores the Azure Data Explorer cluster, ingestion endpoint, database, and auth settings
        used by Export-XdrAzureDataExplorer and Get-XdrAzureDataExplorerIngestionStatus.

        When ClusterUri and Database are omitted, the cmdlet auto-discovers accessible clusters,
        prompts you to choose a cluster when multiple matches exist, and then prompts you to
        choose a database when the selected cluster has more than one available database.

        If IngestionUri is omitted, the cmdlet derives it from the cluster URI by using the
        standard `ingest-<cluster>` hostname convention.

    .PARAMETER ClusterUri
        The Azure Data Explorer cluster URI. You can supply either the engine endpoint or the
        ingestion endpoint. If omitted, the cmdlet discovers accessible clusters and prompts
        for a selection when needed.

    .PARAMETER Database
        The database name to target for table bootstrap and queued ingestion.

    .PARAMETER SubscriptionId
        Optional subscription IDs used to narrow cluster discovery when ClusterUri is omitted.

    .PARAMETER ClusterName
        Optional cluster name filter used during discovery when ClusterUri is omitted. Wildcards
        are supported.

    .PARAMETER DatabaseName
        Optional database name filter used during discovery when ClusterUri is omitted. Wildcards
        are supported.

    .PARAMETER IngestionUri
        Optional explicit data ingestion URI. If omitted, it is derived from ClusterUri.

    .PARAMETER TenantId
        Optional tenant ID used when obtaining a token through Az.Accounts or Azure CLI.

    .PARAMETER ManagedIdentityClientId
        Optional user-assigned managed identity client ID for IMDS token acquisition.

    .PARAMETER AccessToken
        Optional Azure Data Explorer access token to use directly instead of acquiring a token
        dynamically. This applies only when ClusterUri and Database are supplied explicitly.

    .PARAMETER RequestTimeout
        Optional HTTP timeout for discovery requests when ClusterUri is omitted. Default is 60 seconds.

    .PARAMETER NonInteractive
        Prevents interactive cluster or database prompts during discovery. If discovery is
        ambiguous, the cmdlet throws and asks you to narrow the match or specify the connection
        explicitly.

    .PARAMETER AllowPartialDiscovery
        Allows automatic connection selection when one or more discovery providers or database
        enumeration requests failed. By default, discovery fails closed rather than selecting
        from an incomplete result set.

    .PARAMETER Confirm
        Prompts for confirmation before updating the module's Azure Data Explorer connection settings.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs without updating the module's Azure Data Explorer connection settings.

    .EXAMPLE
        Set-XdrAzureDataExplorerConnection -ClusterUri "https://mycluster.westeurope.kusto.windows.net" -Database "Investigations"

        Configures the connection and derives the ingestion endpoint automatically.

    .EXAMPLE
        Set-XdrAzureDataExplorerConnection

        Discovers accessible clusters, prompts for a cluster if more than one is available,
        and prompts for a database if the chosen cluster has more than one database.

    .EXAMPLE
        Set-XdrAzureDataExplorerConnection -ClusterName 'nm-test-cluster' -DatabaseName 'Investigations' -NonInteractive

        Discovers a single matching cluster and database without prompting. If multiple matches
        remain, the cmdlet throws instead of waiting for user input.

    .EXAMPLE
        $token = az account get-access-token --resource https://api.kusto.windows.net --query accessToken -o tsv
        Set-XdrAzureDataExplorerConnection -ClusterUri "https://mycluster.westeurope.kusto.windows.net" -Database "Investigations" -AccessToken $token

        Configures the connection with an explicit bearer token.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Discover', SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Explicit')]
        [Alias('Cluster')]
        [uri]$ClusterUri,

        [Parameter(Mandatory, ParameterSetName = 'Explicit')]
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]{0,127}$')]
        [string]$Database,

        [Parameter(ParameterSetName = 'Discover')]
        [string[]]$SubscriptionId,

        [Parameter(ParameterSetName = 'Discover')]
        [SupportsWildcards()]
        [string]$ClusterName,

        [Parameter(ParameterSetName = 'Discover')]
        [SupportsWildcards()]
        [string]$DatabaseName,

        [Parameter(ParameterSetName = 'Explicit')]
        [Alias('DataIngestionUri')]
        [uri]$IngestionUri,

        [string]$TenantId,

        [string]$ManagedIdentityClientId,

        [Parameter(ParameterSetName = 'Explicit')]
        [string]$AccessToken,

        [Parameter(ParameterSetName = 'Discover')]
        [ValidateRange(1, 600)]
        [int]$RequestTimeout = 60,

        [Parameter(ParameterSetName = 'Discover')]
        [switch]$NonInteractive,

        [Parameter(ParameterSetName = 'Discover')]
        [switch]$AllowPartialDiscovery
    )

    process {
        $resolvedDatabase = $Database
        $resolvedTenantId = $TenantId
        $shouldProcessFinalConfiguration = $true

        if ($PSCmdlet.ParameterSetName -eq 'Discover') {
            $discoveryTarget = if (-not [string]::IsNullOrWhiteSpace($ClusterName)) {
                $ClusterName
            }
            elseif ($PSBoundParameters.ContainsKey('SubscriptionId') -and @($SubscriptionId).Count -gt 0) {
                ($SubscriptionId -join ', ')
            }
            else {
                'auto-discovered Azure Data Explorer connection'
            }

            if (-not $PSCmdlet.ShouldProcess($discoveryTarget, 'Discover and configure Azure Data Explorer connection settings')) {
                return
            }

            $shouldProcessFinalConfiguration = $false
            $selection = Resolve-XdrAzureDataExplorerDiscoveredConnection `
                -SubscriptionId $SubscriptionId `
                -ClusterName $ClusterName `
                -DatabaseName $DatabaseName `
                -TenantId $TenantId `
                -ManagedIdentityClientId $ManagedIdentityClientId `
                -NonInteractive:$NonInteractive `
                -AllowPartialDiscovery:$AllowPartialDiscovery `
                -RequestTimeout $RequestTimeout

            $ClusterUri = $selection.ClusterUri
            $IngestionUri = $selection.IngestionUri
            $resolvedDatabase = $selection.Database
            if (-not [string]::IsNullOrWhiteSpace([string]$selection.TenantId)) {
                $resolvedTenantId = $selection.TenantId
            }
        }

        $resolvedUris = Resolve-XdrAzureDataExplorerUris -ClusterUri $ClusterUri -IngestionUri $IngestionUri

        if ((-not $shouldProcessFinalConfiguration) -or $PSCmdlet.ShouldProcess($resolvedUris.ClusterUri.AbsoluteUri, 'Configure Azure Data Explorer connection settings')) {
            $script:AzureDataExplorerConnection = [pscustomobject]@{
                ClusterUri              = $resolvedUris.ClusterUri
                IngestionUri            = $resolvedUris.IngestionUri
                Database                = $resolvedDatabase
                TenantId                = $resolvedTenantId
                ManagedIdentityClientId = $ManagedIdentityClientId
                AccessToken             = $AccessToken
            }

            Write-Verbose "Configured Azure Data Explorer connection for database '$resolvedDatabase' using cluster '$($resolvedUris.ClusterUri.AbsoluteUri)'"
            Write-Verbose "Using ingestion endpoint '$($resolvedUris.IngestionUri.AbsoluteUri)'"
        }
    }
}
