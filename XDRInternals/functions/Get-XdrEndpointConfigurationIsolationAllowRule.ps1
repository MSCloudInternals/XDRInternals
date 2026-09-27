function Get-XdrEndpointConfigurationIsolationAllowRule {
    <#
    .SYNOPSIS
        Retrieves Defender for Endpoint device isolation allow rules.

    .DESCRIPTION
        Gets the isolation allow rules for Windows or macOS from the Defender portal.
        Results are cached for 30 minutes per platform.

    .PARAMETER OsPlatform
        The operating system platform whose rules should be retrieved.

    .PARAMETER Force
        Bypasses the cached response for this platform.

    .EXAMPLE
        Get-XdrEndpointConfigurationIsolationAllowRule -OsPlatform Windows

    .OUTPUTS
        Object[]
        Returns the isolation allow rules for the selected platform.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('Windows', 'MacOs')]
        [string]$OsPlatform,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $cacheKey = "GetXdrEndpointConfigurationIsolationAllowRule$OsPlatform"
        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            return $currentCacheValue.Value
        } elseif ($Force) {
            Clear-XdrCache -CacheKey $cacheKey
        }

        try {
            $uri = "https://security.microsoft.com/apiproxy/mtp/customizationApi/?customizationType=IsolationAllowRules&osPlatform=$OsPlatform"
            $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve $OsPlatform isolation allow rules: $_"
        }
    }
}