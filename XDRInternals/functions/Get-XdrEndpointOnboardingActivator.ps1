function Get-XdrEndpointOnboardingActivator {
    <#
    .SYNOPSIS
        Lists Defender for Endpoint Windows onboarding activators.

    .DESCRIPTION
        Gets visible or hidden Windows onboarding activator requests. Each list is
        cached independently for 30 minutes.

    .PARAMETER Hidden
        Retrieves hidden activators instead of visible activators.

    .PARAMETER Force
        Bypasses the cached response for the selected list.

    .EXAMPLE
        Get-XdrEndpointOnboardingActivator -Hidden -Force

    .OUTPUTS
        Object[]
        Returns the activator list from the API.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Hidden,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $list = if ($Hidden) { 'ListHidden' } else { 'List' }
        $cacheKey = "GetXdrEndpointOnboardingActivator$list"
        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            return $currentCacheValue.Value
        } elseif ($Force) {
            Clear-XdrCache -CacheKey $cacheKey
        }

        try {
            $uri = "https://security.microsoft.com/apiproxy/mtp/packages/DownloadOnboardingWindowsActivator/$list"
            $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve $list onboarding activators: $_"
        }
    }
}