function Get-XdrEndpointOnboardingStatus {
    <#
    .SYNOPSIS
        Retrieves Defender for Endpoint onboarding status.

    .DESCRIPTION
        Gets the tenant onboarding status, including the test alert and device status.
        Results are cached for 30 minutes.

    .PARAMETER Force
        Bypasses the cached response.

    .EXAMPLE
        Get-XdrEndpointOnboardingStatus -Force

    .OUTPUTS
        Object
        Returns the onboarding status from the API.
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
        $cacheKey = 'GetXdrEndpointOnboardingStatus'
        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            return $currentCacheValue.Value
        } elseif ($Force) {
            Clear-XdrCache -CacheKey $cacheKey
        }

        try {
            $uri = 'https://security.microsoft.com/apiproxy/mtp/settings/EndpointOnboardingStatus'
            $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve endpoint onboarding status: $_"
        }
    }
}