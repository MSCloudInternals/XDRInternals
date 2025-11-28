function Get-XdrConfigurationAlertServiceSetting {
    <#
    .SYNOPSIS
        Retrieves alert service settings from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the alert service settings for various workloads from the Microsoft Defender XDR portal,
        showing which services have alerts disabled and the reasons for disablement.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrConfigurationAlertServiceSetting
        Retrieves the alert service settings using cached data if available.

    .EXAMPLE
        Get-XdrConfigurationAlertServiceSetting -Force
        Forces a fresh retrieval of the alert service settings, bypassing the cache.

    .OUTPUTS
        Object
        Returns the alert service settings for each workload with translated names and normalized reasons.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $currentCacheValue = Get-XdrCache -CacheKey "XdrAlertServiceSettings" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR alert service settings"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrAlertServiceSettings"
        } else {
            Write-Verbose "XDR alert service settings cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/alertsApiService/workloads/disabled?includeDetails=true"
        Write-Verbose "Retrieving XDR alert service settings"
        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        } catch {
            Write-Error "Failed to retrieve alert service settings: $_"
            return
        }

        # Process the result to translate names and normalize reasons
        $processedResult = @()

        foreach ($property in $result.PSObject.Properties) {
            $workloadName = $property.Name
            $workloadData = $property.Value

            # Translate workload names
            $translatedName = switch ($workloadName) {
                'Aad' { 'EntraID' }
                'Mdc' { 'DefenderForCloud' }
                default { $workloadName }
            }

            # Normalize reasons - if empty, set to MonitorAllAlerts for Mdc
            $reasons = $workloadData.reasons
            if ($workloadName -eq 'Mdc' -and ($null -eq $reasons -or $reasons.Count -eq 0)) {
                $reasons = @('MonitorAllAlerts')
            }

            # Convert reasons array to AlertSetting string (use first reason or join multiple)
            $alertSetting = if ($reasons -and $reasons.Count -gt 0) {
                if ($reasons.Count -eq 1) {
                    $reasons[0]
                } else {
                    $reasons -join ', '
                }
            } else {
                $null
            }

            # Create processed workload object with Service as a property
            $processedWorkload = [PSCustomObject]@{
                Service         = $translatedName
                AlertSetting    = $alertSetting
                Feedback        = $workloadData.feedback
                DisabledTime    = $workloadData.disabledTime
                DisablementType = $workloadData.disablementType
            }

            # Add to result array
            $processedResult += $processedWorkload
        }

        Set-XdrCache -CacheKey "XdrAlertServiceSettings" -Value $processedResult -TTLMinutes 30
        return $processedResult
    }

    end {

    }
}
