function Get-XdrCloudAppsFeatureFlag {
    <#
    .SYNOPSIS
        Retrieves feature flag values for Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets the current values of specified feature flags from Cloud App Security.
        Feature flags control various behaviors and capabilities within the service.
        This can be useful for understanding available features or troubleshooting.

    .PARAMETER FeatureFlags
        An array of feature flag names to retrieve values for.
        Common flags include:
        - "adallom.console.discovery.risk_score_app_hidden_fields"
        - "adallom.console.top_apps_dashboard.limit"
        - "adallom.console.discovery.enable_custom_apps"

    .EXAMPLE
        Get-XdrCloudAppsFeatureFlag -FeatureFlags "adallom.console.discovery.risk_score_app_hidden_fields"

        Retrieves the value of a single feature flag.

    .EXAMPLE
        Get-XdrCloudAppsFeatureFlag -FeatureFlags @("adallom.console.discovery.risk_score_app_hidden_fields", "adallom.console.top_apps_dashboard.limit")

        Retrieves values for multiple feature flags at once.

    .EXAMPLE
        $flags = @(
            "adallom.console.discovery.enable_custom_apps",
            "adallom.console.discovery.risk_score_app_hidden_fields"
        )
        Get-XdrCloudAppsFeatureFlag -FeatureFlags $flags

        Retrieves multiple feature flag values using a variable.

    .NOTES
        This cmdlet requires an active XDR session. Use Connect-XdrByEstsCookie to authenticate.
        Feature flags may change between service updates and are not officially documented.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$FeatureFlags
    )

    begin {
        Update-XdrConnectionSettings
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/get_feature_values/"
    }

    process {
        Write-Verbose "Retrieving feature flag values for: $($FeatureFlags -join ', ')"

        $Body = @{
            feature_flags = $FeatureFlags
        } | ConvertTo-Json -Depth 10

        Write-Verbose "Request body: $Body"

        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Write-Verbose "Successfully retrieved feature flag values"
            return $result
        }
        catch {
            Write-Error "Failed to retrieve feature flag values: $_"
        }
    }
}
