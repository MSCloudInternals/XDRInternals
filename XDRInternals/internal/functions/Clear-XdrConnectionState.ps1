function Clear-XdrConnectionState {
    <#
    .SYNOPSIS
        Clears sensitive connection state from the current module instance.

    .DESCRIPTION
        Clears Defender cookies and headers, cached tenant data, Azure Data Explorer tokens,
        Sentinel credentials, and locally tracked connection metadata without contacting a service.

    .EXAMPLE
        Clear-XdrConnectionState

        Clears sensitive state held by the current XDRInternals module instance.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal cleanup invoked after public confirmation or during module removal.')]
    [CmdletBinding()]
    param()

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
}
