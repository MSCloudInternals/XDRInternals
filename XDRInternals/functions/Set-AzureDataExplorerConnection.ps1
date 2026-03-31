function Set-AzureDataExplorerConnection {
    <#
    .SYNOPSIS
        Configures Azure Data Explorer connection settings for export cmdlets.

    .DESCRIPTION
        Stores the Azure Data Explorer cluster, ingestion endpoint, database, and auth settings
        used by Export-AzureDataExplorer and Get-AzureDataExplorerIngestionStatus.

        If IngestionUri is omitted, the cmdlet derives it from the cluster URI by using the
        standard `ingest-<cluster>` hostname convention.

    .PARAMETER ClusterUri
        The Azure Data Explorer cluster URI. You can supply either the engine endpoint or the
        ingestion endpoint.

    .PARAMETER Database
        The database name to target for table bootstrap and queued ingestion.

    .PARAMETER IngestionUri
        Optional explicit data ingestion URI. If omitted, it is derived from ClusterUri.

    .PARAMETER TenantId
        Optional tenant ID used when obtaining a token through Az.Accounts or Azure CLI.

    .PARAMETER ManagedIdentityClientId
        Optional user-assigned managed identity client ID for IMDS token acquisition.

    .PARAMETER AccessToken
        Optional access token to use directly instead of acquiring a token dynamically.

    .PARAMETER Confirm
        Prompts for confirmation before updating the module's Azure Data Explorer connection settings.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs without updating the module's Azure Data Explorer connection settings.

    .EXAMPLE
        Set-AzureDataExplorerConnection -ClusterUri "https://mycluster.westeurope.kusto.windows.net" -Database "Investigations"

        Configures the connection and derives the ingestion endpoint automatically.

    .EXAMPLE
        $token = az account get-access-token --resource https://api.kusto.windows.net --query accessToken -o tsv
        Set-AzureDataExplorerConnection -ClusterUri "https://mycluster.westeurope.kusto.windows.net" -Database "Investigations" -AccessToken $token

        Configures the connection with an explicit bearer token.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [Alias('Cluster')]
        [uri]$ClusterUri,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]{0,127}$')]
        [string]$Database,

        [Alias('DataIngestionUri')]
        [uri]$IngestionUri,

        [string]$TenantId,

        [string]$ManagedIdentityClientId,

        [string]$AccessToken
    )

    process {
        $resolvedUris = Resolve-XdrAzureDataExplorerUris -ClusterUri $ClusterUri -IngestionUri $IngestionUri

        if ($PSCmdlet.ShouldProcess($resolvedUris.ClusterUri.AbsoluteUri, 'Configure Azure Data Explorer connection settings')) {
            $script:AzureDataExplorerConnection = [pscustomobject]@{
                ClusterUri              = $resolvedUris.ClusterUri
                IngestionUri            = $resolvedUris.IngestionUri
                Database                = $Database
                TenantId                = $TenantId
                ManagedIdentityClientId = $ManagedIdentityClientId
                AccessToken             = $AccessToken
            }

            Write-Verbose "Configured Azure Data Explorer connection for database '$Database' using cluster '$($resolvedUris.ClusterUri.AbsoluteUri)'"
            Write-Verbose "Using ingestion endpoint '$($resolvedUris.IngestionUri.AbsoluteUri)'"
        }
    }
}
