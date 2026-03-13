function Get-XdrEndpointDeviceTag {
    <#
    .SYNOPSIS
        Retrieves all device tags from Microsoft Defender for Endpoint.

    .DESCRIPTION
        Gets device tags from the Microsoft Defender XDR portal. Supports two modes:
        - All (default): Retrieves all device tags in the tenant.
        - DeviceId: Retrieves tags for a single device via the machineTags API.
          Returns an object with BuiltInTags, UserDefinedTags, and DynamicRulesTags arrays.
          Results are cached for 5 minutes.
        This function includes caching support to reduce API calls.

    .PARAMETER DeviceId
        The device identifier (also known as MachineId or SenseMachineId). When specified,
        retrieves the tags for a single device. Results are cached for 5 minutes.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointDeviceTag
        Retrieves all device tags using cached data if available.

    .EXAMPLE
        Get-XdrEndpointDeviceTag -Force
        Forces a fresh retrieval of device tags, bypassing the cache.

    .EXAMPLE
        Get-XdrEndpointDeviceTag -DeviceId "abc123def456"
        Returns an object with BuiltInTags, UserDefinedTags, and DynamicRulesTags arrays.

    .EXAMPLE
        (Get-XdrEndpointDeviceTag -DeviceId "abc123def456").UserDefinedTags
        Returns only the user-defined tags for a single device.

    .OUTPUTS
        Object
        When using -DeviceId, returns an object with BuiltInTags, UserDefinedTags, and DynamicRulesTags.
        When using default mode, returns an array of all device tag strings in the tenant.
    #>
    [OutputType([object])]
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(ParameterSetName = 'DeviceId', Mandatory = $true)]
        [Alias('MachineId', 'SenseMachineId')]
        [ValidateLength(40,40)]
        [ValidatePattern('^[0-9a-fA-F]{40}$')]
        [string]$DeviceId,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'DeviceId') {
            $CacheKey = "XdrDeviceTags_$DeviceId"
            if (-not $Force) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached device tags for $DeviceId"
                    return $cache.Value
                }
            }

            $DeviceTagUri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/machineTags?senseMachineId=$DeviceId&tenantIds="
            Write-Verbose "Retrieving tags for DeviceId: $DeviceId"

            try {
                $result = Invoke-RestMethod -Uri $DeviceTagUri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                if ($result -is [string] -and $result -match '<!DOCTYPE html>') {
                    throw "machineTags endpoint returned auth redirect"
                }

                if ($null -eq $result) {
                    $result = [PSCustomObject]@{
                        BuiltInTags      = @()
                        UserDefinedTags  = @()
                        DynamicRulesTags = @()
                    }
                }

                Set-XdrCache -CacheKey $CacheKey -Value $result -TTLMinutes 5
                return $result
            } catch {
                throw "Failed to retrieve tags for DeviceId '$DeviceId': $_"
            }
        }

        $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointDeviceTags" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint Device Tags"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointDeviceTags"
        } else {
            Write-Verbose "XDR Endpoint Device Tags cache is missing or expired"
        }

        try {
            $Uri = "https://security.microsoft.com/apiproxy/mtp/ndr/machines/allMachinesTags"
            Write-Verbose "Retrieving XDR Endpoint Device Tags"
            $XdrEndpointDeviceTags = Invoke-RestMethod -Uri $Uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            Set-XdrCache -CacheKey "XdrEndpointDeviceTags" -Value $XdrEndpointDeviceTags -TTLMinutes 30
            return $XdrEndpointDeviceTags
        } catch {
            Write-Error "Failed to retrieve endpoint device tags: $_"
        }
    }

    end {
    }
}