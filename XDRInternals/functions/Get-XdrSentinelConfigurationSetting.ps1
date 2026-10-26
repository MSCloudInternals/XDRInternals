function Get-XdrSentinelConfigurationSetting {
    <#
    .SYNOPSIS
        Retrieves a Microsoft Sentinel workspace service setting.

    .DESCRIPTION
        Gets raw Anomalies, EntityAnalytics, Ueba, or security event collection settings
        from the Defender portal's Sentinel workspace proxy. Requires access to the
        specified Azure workspace.

    .PARAMETER SubscriptionId
        Azure subscription ID containing the Sentinel workspace.

    .PARAMETER ResourceGroupName
        Resource group containing the Sentinel workspace.

    .PARAMETER WorkspaceName
        Name of the Sentinel Log Analytics workspace.

    .PARAMETER Setting
        The Sentinel setting or security event collection configuration to retrieve.

    .EXAMPLE
        Get-XdrSentinelConfigurationSetting -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroup -WorkspaceName $workspace -Setting Ueba
        Retrieves the UEBA data sources and onboarding state for a Sentinel workspace.

    .OUTPUTS
        Object
        Returns the raw workspace setting response.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$SubscriptionId,

        [Parameter(Mandatory)]
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$WorkspaceName,

        [Parameter(Mandatory)]
        [ValidateSet('Anomalies', 'EntityAnalytics', 'Ueba', 'SecurityInsightsSecurityEventCollectionConfiguration', 'SecurityEventCollectionConfiguration')]
        [string]$Setting
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $subscription = [uri]::EscapeDataString($SubscriptionId)
        $resourceGroup = [uri]::EscapeDataString($ResourceGroupName)
        $workspace = [uri]::EscapeDataString($WorkspaceName)
        $workspacePath = "https://security.microsoft.com/apiproxy/arm/subscriptions/$subscription/resourceGroups/$resourceGroup/providers/Microsoft.OperationalInsights/workspaces/$workspace"
        if ($Setting -like '*CollectionConfiguration') {
            $uri = "$workspacePath/datasources/$Setting`?api-version=2015-11-01-preview"
        } else {
            $apiVersion = if ($Setting -eq 'Anomalies') { '2019-01-01-preview' } else { '2022-04-01-preview' }
            $uri = "$workspacePath/providers/Microsoft.SecurityInsights/settings/$Setting`?api-version=$apiVersion"
        }

        try {
            Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}
