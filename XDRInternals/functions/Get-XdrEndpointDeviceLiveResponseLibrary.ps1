function Get-XdrEndpointDeviceLiveResponseLibrary {
    <#
    .SYNOPSIS
        Retrieves the Live Response library files from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the list of files available in the Live Response library.
        These files can be used with the 'putfile' and 'run' commands during Live Response sessions.
        Results are cached for 15 minutes.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointDeviceLiveResponseLibrary
        Lists all files in the Live Response library.

    .EXAMPLE
        Get-XdrEndpointDeviceLiveResponseLibrary -Force
        Forces a fresh retrieval of the library file list.

    .OUTPUTS
        Object
        Returns the library file listing.
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
        $CacheKey = "XdrLiveResponseLibrary"
        if (-not $Force) {
            $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Live Response library data"
                return $cache.Value
            }
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/library/get_files?useV3Api=true"
            Write-Verbose "Retrieving Live Response library files"
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

            Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 15
            return $result
        } catch {
            Write-Error "Failed to retrieve Live Response library: $_"
        }
    }

    end {
    }
}
