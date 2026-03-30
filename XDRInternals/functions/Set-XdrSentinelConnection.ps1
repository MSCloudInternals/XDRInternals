function Set-XdrSentinelConnection {
    <#
    .SYNOPSIS
        Configures the Sentinel (Log Analytics) workspace connection for data export.

    .DESCRIPTION
        Stores the Log Analytics workspace ID and shared key in script-scoped variables
        used by Export-XdrToSentinel and Invoke-XdrDefenderHarvest.

        The shared key can be found in the Azure portal under:
        Log Analytics workspace > Agents > Log Analytics agent instructions > Primary/Secondary key

    .PARAMETER WorkspaceId
        The Log Analytics workspace ID (GUID).

    .PARAMETER SharedKey
        The primary or secondary shared key for the workspace.

    .PARAMETER DceEndpoint
        Optional Data Collection Endpoint URI. When set, uses the DCR/DCE ingestion API
        instead of the legacy HTTP Data Collector API. Not required for most use cases.

    .PARAMETER Confirm
        Prompts for confirmation before updating the module's Sentinel connection settings.

    .PARAMETER WhatIf
        Shows what would happen if the command runs without updating the module's
        Sentinel connection settings.

    .EXAMPLE
        Set-XdrSentinelConnection -WorkspaceId "12345678-abcd-1234-abcd-123456789012" -SharedKey "base64key=="

    .EXAMPLE
        $key = Read-Host -AsSecureString "Shared Key"
        Set-XdrSentinelConnection -WorkspaceId "12345678-abcd-1234-abcd-123456789012" -SharedKey ([System.Net.NetworkCredential]::new('', $key).Password)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory)]
        [string]$WorkspaceId,

        [Parameter(Mandatory)]
        [string]$SharedKey,

        [string]$DceEndpoint
    )

    process {
        if ($PSCmdlet.ShouldProcess($WorkspaceId, 'Configure Sentinel connection settings')) {
            $script:SentinelWorkspaceId = $WorkspaceId
            $script:SentinelSharedKey = $SharedKey
            if ($DceEndpoint) {
                $script:SentinelDceEndpoint = $DceEndpoint
            }

            Write-Verbose "Configured Sentinel connection for workspace: $WorkspaceId"
        }
    }
}
