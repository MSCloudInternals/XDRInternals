function Get-XdrEndpointConfigurationAutomatedInvestigationExclusion {
    <#
    .SYNOPSIS
        Retrieves automated investigation memory or folder exclusions.

    .DESCRIPTION
        Gets memory-content ACL or folder exclusions from Defender for Endpoint.
        Responses are cached for 30 minutes per exclusion type.

    .PARAMETER Type
        Selects memory-content or folder exclusions.

    .PARAMETER Force
        Bypasses the cached response for this exclusion type.

    .EXAMPLE
        Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type Folder

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
            $result = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers
            $page = $result
            $results = @($result.results)
            $visited = [System.Collections.Generic.HashSet[string]]::new()
            while ($page.PSObject.Properties['next'] -and $page.next) {
                $nextUri = [uri]::new([uri]$uri, [string]$page.next)
                if ($nextUri.Host -ne 'security.microsoft.com' -or $nextUri.AbsolutePath -ne ([uri]$uri).AbsolutePath -or -not $visited.Add($nextUri.AbsoluteUri)) {
                    throw 'Invalid automated investigation exclusion continuation link.'
                }
                $page = Invoke-RestMethod -Uri $nextUri.AbsoluteUri -Method Get -ContentType 'application/json' -WebSession $script:session -Headers $script:headers
                $results += @($page.results)
            }
            if ($visited.Count -gt 0) {
                $result.results = $results
                $result.next = $null
            }
            Set-XdrCache -CacheKey $cacheKey -Value $result -TTLMinutes 30
            return $result
        } catch {
            Write-Error "Failed to retrieve automated investigation $Type exclusions: $_"
        }
    }
}