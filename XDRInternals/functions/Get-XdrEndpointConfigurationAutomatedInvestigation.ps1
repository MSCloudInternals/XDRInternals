function Get-XdrEndpointConfigurationAutomatedInvestigation {
    <#
    .SYNOPSIS
        Retrieves advanced automated investigation settings for Defender for Endpoint.

    .DESCRIPTION
        Gets the advanced automated investigation settings, including cloud upload,
        memory content upload, and file extension settings. Results are cached for 30 minutes.
        Legacy route availability varies; HTTP 410 reports an unavailable feature without a cached result.

    .PARAMETER Force
        Bypasses the cache and retrieves the current settings.

    .EXAMPLE
        Get-XdrEndpointConfigurationAutomatedInvestigation -Force

    .NOTES
        HTTP 410 emits XdrEndpointAutomatedInvestigationUnavailable with category
        NotImplemented and constant Route, Type, and StatusCode target metadata.

        Microsoft documents retirement of the separate AIR investigation experience on
        September 1, 2026. This does not establish retirement of these exact portal routes;
        automation upload and folder exclusion settings remain documented separately.

    .LINK
        https://learn.microsoft.com/en-us/defender-endpoint/configure-automated-investigations-remediation

    .LINK
        https://learn.microsoft.com/en-us/defender-endpoint/manage-automation-file-uploads

    .LINK
        https://learn.microsoft.com/en-us/defender-endpoint/automation-folder-exclusions-configure

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
            $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers -ErrorAction Stop
            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            if ($_.Exception -is [Microsoft.PowerShell.Commands.HttpResponseException] -and
                $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::Gone) {
                Write-Error -ErrorId 'XdrEndpointAutomatedInvestigationUnavailable' -Category NotImplemented `
                    -TargetObject ([pscustomobject]@{ Route = '/apiproxy/mtp/autoIr/ui/admin/advanced'; Type = 'Advanced'; StatusCode = 410 }) `
                    -Message 'Legacy automated investigation advanced settings are unavailable (HTTP 410). Verify availability in the Defender portal.'
            } else {
                Write-Error -ErrorRecord $_
            }
        }
    }
}