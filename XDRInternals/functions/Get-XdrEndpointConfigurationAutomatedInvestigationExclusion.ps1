function Get-XdrEndpointConfigurationAutomatedInvestigationExclusion {
    <#
    .SYNOPSIS
        Retrieves automated investigation memory or folder exclusions.

    .DESCRIPTION
        Gets memory-content ACL or folder exclusions from Defender for Endpoint.
        Responses are cached for 30 minutes per exclusion type. Legacy route availability
        varies independently by exclusion type; HTTP 410 reports unavailable without partial results.

    .PARAMETER Type
        Selects memory-content or folder exclusions.

    .PARAMETER Force
        Bypasses the cached response for this exclusion type.

    .EXAMPLE
        Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type Folder

    .NOTES
        HTTP 410 emits XdrEndpointAutomatedInvestigationExclusionUnavailable with category
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
        Returns the API response, including its count and results properties.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('MemoryContent', 'Folder')]
        [string]$Type,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $cacheKey = "GetXdrEndpointConfigurationAutomatedInvestigationExclusion$Type"
        $currentCacheValue = Get-XdrCache -CacheKey $cacheKey -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            return $currentCacheValue.Value
        } elseif ($Force) {
            Clear-XdrCache -CacheKey $cacheKey
        }

        if ($Type -eq 'Folder') {
            $uri = 'https://security.microsoft.com/apiproxy/mtp/autoIr/folder_exclusion/all?page_size=99999&type=folder'
        } else {
            $uri = 'https://security.microsoft.com/apiproxy/mtp/autoIr/acl/all?type=memory_content'
        }

        try {
            $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers -MaximumRedirection 0 -ErrorAction Stop
            $page = $result
            $results = @($result.results)
            $visited = [System.Collections.Generic.HashSet[string]]::new()
            while ($page.PSObject.Properties['next'] -and $page.next) {
                $nextUri = [uri]::new([uri]$uri, [string]$page.next)
                if ($nextUri.Scheme -ne ([uri]$uri).Scheme -or
                    $nextUri.Port -ne ([uri]$uri).Port -or
                    $nextUri.UserInfo -ne '' -or
                    $nextUri.Host -ne 'security.microsoft.com' -or
                    $nextUri.AbsolutePath -ne ([uri]$uri).AbsolutePath -or
                    -not $visited.Add($nextUri.AbsoluteUri)) {
                    throw 'Invalid automated investigation exclusion continuation link.'
                }
                $page = Invoke-RestMethod -Uri $nextUri.AbsoluteUri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers -MaximumRedirection 0 -ErrorAction Stop
                $results += @($page.results)
            }
            if ($visited.Count -gt 0) {
                $result.results = $results
                $result.next = $null
            }
            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            if ($_.Exception -is [Microsoft.PowerShell.Commands.HttpResponseException] -and
                $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::Gone) {
                $unavailableTarget = if ($Type -eq 'Folder') {
                    [pscustomobject]@{ Route = '/apiproxy/mtp/autoIr/folder_exclusion/all'; Type = 'Folder'; StatusCode = 410 }
                } else {
                    [pscustomobject]@{ Route = '/apiproxy/mtp/autoIr/acl/all'; Type = 'MemoryContent'; StatusCode = 410 }
                }
                Write-Error -ErrorId 'XdrEndpointAutomatedInvestigationExclusionUnavailable' -Category NotImplemented `
                    -TargetObject $unavailableTarget `
                    -Message 'Legacy automated investigation exclusions are unavailable for the requested type (HTTP 410). Verify availability in the Defender portal.'
            } else {
                Write-Error -ErrorRecord $_
            }
        }
    }
}