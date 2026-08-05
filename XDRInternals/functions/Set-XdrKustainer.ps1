function Set-XdrKustainer {
    <#
    .SYNOPSIS
        Configures the local Kusto emulator connection used by Export-XdrKustainer.

    .DESCRIPTION
        Validates and stores an unauthenticated endpoint and database for a local Kusto emulator
        (Kustainer). Optionally enables the database streaming-ingestion policy.

        Export-XdrKustainer uses .ingest inline, which doesn't require a streaming policy.
        EnableStreamingIngestion configures the separate /v1/rest/ingest endpoint for clients
        that use streaming ingestion.

    .PARAMETER ClusterUri
        The HTTP endpoint exposed by Kustainer, such as http://localhost:8080, or an HTTPS endpoint
        provided by a reverse proxy in front of Kustainer.

    .PARAMETER Database
        The emulator database to use.

    .PARAMETER EnableStreamingIngestion
        Enables the streaming-ingestion policy at database scope. The policy applies to existing
        and future tables in the database. This isn't required for .ingest inline exports.

    .PARAMETER Confirm
        Prompts for confirmation before changing the stored connection or database policy.

    .PARAMETER WhatIf
        Shows what would happen without changing the stored connection or database policy.

    .EXAMPLE
        Set-XdrKustainer -ClusterUri 'http://localhost:8080' -Database 'NetDefaultDB'

        Configures Kustainer for inline exports.

    .EXAMPLE
        Set-XdrKustainer -ClusterUri 'http://localhost:8080' -Database 'NetDefaultDB' -EnableStreamingIngestion

        Configures Kustainer and enables the database policy required by /v1/rest/ingest.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [Alias('Endpoint')]
        [uri]$ClusterUri,

        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]{0,127}$')]
        [string]$Database,

        [Alias('EnableIngestion')]
        [switch]$EnableStreamingIngestion
    )

    process {
        if ($ClusterUri.Scheme -notin @('http', 'https')) {
            throw 'Kustainer requires an http:// endpoint or an https:// reverse-proxy endpoint.'
        }

        $normalizedClusterUri = [uri]$ClusterUri.GetLeftPart([System.UriPartial]::Authority)
        $streamingIngestionEnabled = $false
        if (-not $PSCmdlet.ShouldProcess("$Database at $($normalizedClusterUri.AbsoluteUri)", 'Configure Kustainer connection')) {
            return
        }

        $null = Invoke-XdrAzureDataExplorerManagementCommand `
            -ClusterUri $normalizedClusterUri `
            -Database $Database `
            -Command '.show tables'

        if ($EnableStreamingIngestion -and
            $PSCmdlet.ShouldProcess("database '$Database'", 'Enable the streaming-ingestion policy')) {
            Write-Warning 'Kustainer streaming ingestion is experimental. It works in tested container builds, but Microsoft currently documents streaming ingestion as unsupported by the emulator.'
            $null = Invoke-XdrAzureDataExplorerManagementCommand `
                -ClusterUri $normalizedClusterUri `
                -Database $Database `
                -Command ".alter database $Database policy streamingingestion enable"
            $streamingIngestionEnabled = $true
        }

        $script:KustainerConnection = [pscustomobject]@{
            ClusterUri                = $normalizedClusterUri
            Database                  = $Database
            StreamingIngestionEnabled = $streamingIngestionEnabled
        }

        Write-Verbose "Configured Kustainer connection for database '$Database' using '$($normalizedClusterUri.AbsoluteUri)'."
    }
}
