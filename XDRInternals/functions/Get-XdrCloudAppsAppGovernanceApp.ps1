function Get-XdrCloudAppsAppGovernanceApp {
    <#
    .SYNOPSIS
        Retrieves apps governed by App Governance.

    .DESCRIPTION
        Gets the list of applications that are governed by Microsoft Defender
        for Cloud Apps App Governance. This includes OAuth apps, service
        principals, and other applications being monitored.
        Use -DataTraffic with -AppId to get data traffic for a specific app.
        This function includes caching support to reduce API calls.

    .PARAMETER DataTraffic
        Returns data traffic information for a specific app. Requires -AppId parameter.

    .PARAMETER AppId
        The unique identifier of the application to retrieve data traffic for.
        This is typically the Azure AD application (client) ID.
        Required when -DataTraffic is specified.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernanceApp
        Retrieves all governed apps using cached data if available.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernanceApp -Force
        Forces a fresh retrieval of all governed apps, bypassing the cache.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernanceApp | Where-Object { $_.privilegeLevel -eq 'High' }
        Retrieves all governed apps and filters for high privilege apps.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernanceApp | Select-Object appDisplayName, privilegeLevel, certificationStatus
        Retrieves governed apps and displays selected properties.

    .EXAMPLE
        Get-XdrCloudAppsAppGovernanceApp -DataTraffic -AppId "12345678-1234-1234-1234-123456789012"
        Retrieves data traffic for the specified application.

    .EXAMPLE
        $apps = Get-XdrCloudAppsAppGovernanceApp
        $apps | ForEach-Object { Get-XdrCloudAppsAppGovernanceApp -DataTraffic -AppId $_.appId }
        Retrieves data traffic for all governed apps.

    .OUTPUTS
        XdrCloudAppsAppGovernanceApp[]
        Returns an array of governed application objects, or data traffic if -DataTraffic is specified.
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(ParameterSetName = 'DataTraffic', Mandatory = $true)]
        [switch]$DataTraffic,

        [Parameter(ParameterSetName = 'DataTraffic', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AppId,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($DataTraffic) {
            $CacheKey = "XdrCloudAppsAppGovernanceAppDataTraffic_$AppId"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached App Governance app data traffic for AppId: $AppId"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "App Governance app data traffic cache is missing or expired for AppId: $AppId"
            }

            $Uri = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/datatraffic('$AppId')"

            Write-Verbose "Retrieving App Governance app data traffic for AppId: $AppId"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = if ($null -ne $response.data) { $response.data } else { $response }
                if ($null -ne $result) {
                    $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppGovernanceAppDataTraffic')
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve App Governance app data traffic for AppId '$AppId': $_"
            }
        } else {
            $CacheKey = "XdrCloudAppsAppGovernanceApp"
            $currentCacheValue = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached App Governance apps"
                return $currentCacheValue.Value
            } elseif ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "App Governance apps cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/m365appprotection/mapg-glsservice/compliance/apps"

            Write-Verbose "Retrieving App Governance apps"

            try {
                $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $result = if ($null -ne $response.data) { $response.data } else { $response }
                if ($null -ne $result) {
                    foreach ($item in $result) {
                        if ($null -ne $item -and $item.PSObject) {
                            $item.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAppGovernanceApp')
                        }
                    }
                    Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                }

                return $result
            } catch {
                Write-Error "Failed to retrieve App Governance apps: $_"
            }
        }
    }

    end {
    }
}
