function Disconnect-Xdr {
    <#
    .SYNOPSIS
        Clears authentication and export credentials held by the current XDRInternals module session.

    .DESCRIPTION
        Removes the Defender web session, authentication headers, cached tenant data, Azure Data
        Explorer connection, Sentinel workspace credentials, and locally tracked Live Response state
        from the current module instance. This does not close a Live Response session in the service;
        close those sessions with Disconnect-XdrEndpointDeviceLiveResponse before disconnecting.

    .PARAMETER WhatIf
        Shows what would happen without clearing the current module session.

    .PARAMETER Confirm
        Prompts for confirmation before clearing the current module session.

    .EXAMPLE
        Disconnect-Xdr

        Clears credentials and cached connection state from the current XDRInternals module instance.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param()

    process {
        if (-not $PSCmdlet.ShouldProcess('current XDRInternals module session', 'Clear authentication and export credentials')) {
            return
        }

        if ((Test-Path variable:script:headers) -and $null -ne $script:headers) {
            $script:headers.Clear()
        }
        if ((Test-Path variable:script:XdrCacheStore) -and $null -ne $script:XdrCacheStore) {
            $script:XdrCacheStore.Clear()
        }
        if ((Test-Path variable:script:AzureDataExplorerConnection) -and
            $null -ne $script:AzureDataExplorerConnection -and
            $script:AzureDataExplorerConnection.PSObject.Properties['AccessToken']) {
            $script:AzureDataExplorerConnection.AccessToken = $null
        }

        $script:session = $null
        $script:headers = $null
        $script:XdrCacheStore = $null
        $script:AzureDataExplorerConnection = $null
        $script:SentinelWorkspaceId = $null
        $script:SentinelSharedKey = $null
        $script:SentinelDceEndpoint = $null
        $script:LiveResponseSession = $null
        $script:XdrBaseUrl = $null
        $script:responseMetadata = $null

        Write-Verbose 'Cleared the current XDRInternals module session.'
    }
}
