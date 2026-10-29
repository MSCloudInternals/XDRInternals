function Get-XdrEndpointConfigurationAttackDisruptionExclusion {
    <#
    .SYNOPSIS
        Retrieves device exclusions from automated attack disruption.

    .DESCRIPTION
        Gets IP, device tag, or default device tag exclusions from the Defender XDR portal.

    .PARAMETER Type
        The type of device exclusion to retrieve.

    .PARAMETER Force
        Bypasses the cached response.

    .EXAMPLE
        Get-XdrEndpointConfigurationAttackDisruptionExclusion -Type DeviceTag

    .OUTPUTS
        Object
        Returns the API response, including ExclusionType and Exclusions or DefaultIdentifiers.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('IP', 'DeviceTag', 'DefaultDeviceTag')]
        [string]$Type,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $canonicalType = switch ($Type) {
            'IP' { 'IP' }
            'DeviceTag' { 'DeviceTag' }
            'DefaultDeviceTag' { 'DefaultDeviceTag' }
        }
        $cacheKey = "GetXdrEndpointConfigurationAttackDisruptionExclusion$canonicalType"
        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            return $currentCacheValue.Value
        } elseif ($Force) {
            Clear-XdrCache -CacheKey $cacheKey
        }

        $path = if ($canonicalType -eq 'DefaultDeviceTag') { 'deviceTag/default' } else { $canonicalType }
        $uri = "https://security.microsoft.com/apiproxy/mtp/disrupt/api/exclusions/$path"
        try {
            $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve endpoint attack disruption $Type exclusions: $_"
        }
    }
}