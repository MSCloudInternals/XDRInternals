function Get-XdrCloudAppsConnectedServiceApp {
    <#
    .SYNOPSIS
        Retrieves connected service apps from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        The Get-XdrCloudAppsConnectedServiceApp cmdlet retrieves the list of connected
        service apps configured in Microsoft Defender for Cloud Apps. This information
        is useful for understanding which apps are connected and can be used for
        activity filtering.

    .PARAMETER Force
        Bypasses the cache and retrieves fresh data from the API.

    .EXAMPLE
        Get-XdrCloudAppsConnectedServiceApp

        Retrieves the list of connected service apps from cache or API.

    .EXAMPLE
        Get-XdrCloudAppsConnectedServiceApp -Force

        Forces a fresh retrieval of connected service apps, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsConnectedServiceApp | Where-Object { $_.enabled -eq $true }

        Retrieves connected service apps and filters for enabled apps only.

    .NOTES
        Requires an active XDR session established via Connect-XdrByEstsCookie.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCloudAppsConnectedServiceApp"

        if (-not $Force) {
            $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Returning cached connected service apps"
                return $cache.Value
            }
        }

        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/connected_services/apps/?getHierarchy=true"

        Write-Verbose "Retrieving connected service apps from $Uri"

        try {
            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            $result = if ($null -ne $response.data) { $response.data } else { $response }
            if ($null -ne $result -and $result -is [array]) {
                foreach ($item in $result) {
                    $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConnectedServiceApp')
                }
            }

            Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15

            return $result
        }
        catch {
            Write-Error "Failed to retrieve connected service apps: $_"
        }
    }
}
