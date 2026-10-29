function Get-XdrEndpointConfigurationAutomatedInvestigation {
    <#
    .SYNOPSIS
        Retrieves advanced automated investigation settings for Defender for Endpoint.

    .DESCRIPTION
        Gets the advanced automated investigation settings, including cloud upload,
        memory content upload, and file extension settings. Results are cached for 30 minutes.

    .PARAMETER Force
        Bypasses the cache and retrieves the current settings.

    .EXAMPLE
        Get-XdrEndpointConfigurationAutomatedInvestigation -Force

    .OUTPUTS
        Object
        Returns the API response with the advanced settings in its data property.
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
        $cacheKey = 'GetXdrEndpointConfigurationAutomatedInvestigation'
        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            return $currentCacheValue.Value
        } elseif ($Force) {
            Clear-XdrCache -CacheKey $cacheKey
        }

        try {
            $uri = 'https://security.microsoft.com/apiproxy/mtp/autoIr/ui/admin/advanced'
            $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve automated investigation advanced settings: $_"
        }
    }
}