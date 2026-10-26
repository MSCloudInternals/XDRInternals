function Get-XdrEndpointWebContentFilteringPolicy {
    <#
    .SYNOPSIS
        Retrieves Defender for Endpoint web content filtering policies.

    .DESCRIPTION
        Gets web content filtering policies, including blocked and audited categories.
        Results are cached for 30 minutes.

    .PARAMETER Force
        Bypasses the cached response.

    .EXAMPLE
        Get-XdrEndpointWebContentFilteringPolicy -Force

    .OUTPUTS
        Object[]
        Returns the policies from the API.
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
        $cacheKey = 'GetXdrEndpointWebContentFilteringPolicy'
        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            return $currentCacheValue.Value
        } elseif ($Force) {
            Clear-XdrCache -CacheKey $cacheKey
        }

        try {
            $uri = 'https://security.microsoft.com/apiproxy/mtp/userRequests/webcategory/policies'
            $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve web content filtering policies: $_"
        }
    }
}