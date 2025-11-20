function Get-XdrIdentityOnboardingStatus {
    <#
    .SYNOPSIS
        Retrieves the onboarding status of Microsoft Defender for Identity.

    .DESCRIPTION
        Gets the onboarding status of Microsoft Defender for Identity (MDI) for the current tenant.
        Returns a boolean value indicating whether MDI is onboarded or not.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrIdentityOnboardingStatus
        Retrieves the MDI onboarding status using cached data if available.

    .EXAMPLE
        Get-XdrIdentityOnboardingStatus -Force
        Forces a fresh retrieval of the MDI onboarding status, bypassing the cache.

    .EXAMPLE
        if (Get-XdrIdentityOnboardingStatus) {
            Write-Host "Microsoft Defender for Identity is onboarded"
        }
        Checks if MDI is onboarded and displays a message.

    .OUTPUTS
        Boolean
        Returns $true if Microsoft Defender for Identity is onboarded, $false otherwise.
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
        $currentCacheValue = Get-XdrCache -CacheKey "XdrIdentityOnboardingStatus" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Identity onboarding status"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrIdentityOnboardingStatus"
        } else {
            Write-Verbose "XDR Identity onboarding status cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/aatp/api/workspaces/isWorkspaceExists/"
        Write-Verbose "Retrieving XDR Identity onboarding status"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        Set-XdrCache -CacheKey "XdrIdentityOnboardingStatus" -Value $result -TTLMinutes 30
        return $result
    }

    end {

    }
}
