function New-XdrCloudAppsConfigurationDiscoveryExclusion {
    <#
    .SYNOPSIS
        Creates a new discovery exclusion in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Creates a new discovery exclusion in Microsoft Defender for Cloud Apps.
        Exclusions allow you to exclude specific users, devices, or IP addresses from Cloud Discovery reports.

    .PARAMETER EntityType
        The type of entity to exclude. Valid values:
        - User: Exclude specific users from discovery
        - Device: Exclude specific devices from discovery
        - IP: Exclude specific IP addresses from discovery

    .PARAMETER Names
        Array of entity names or values to exclude.
        For users, provide usernames or email addresses.
        For devices, provide device names.
        For IPs, provide IP addresses.

    .PARAMETER Comment
        Optional comment describing the reason for the exclusion.

    .PARAMETER Confirm
        Prompts for confirmation before creating the exclusion.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        New-XdrCloudAppsConfigurationDiscoveryExclusion -EntityType User -Names "serviceaccount@contoso.com"
        Excludes a service account from Cloud Discovery reports.

    .EXAMPLE
        New-XdrCloudAppsConfigurationDiscoveryExclusion -EntityType IP -Names "10.0.0.1", "10.0.0.2" -Comment "Internal monitoring servers"
        Excludes multiple IP addresses with a comment.

    .EXAMPLE
        New-XdrCloudAppsConfigurationDiscoveryExclusion -EntityType Device -Names "SCANNER01", "PRINTER01" -Comment "Network devices"
        Excludes specific devices from discovery reports.

    .OUTPUTS
        PSObject
        Returns the API response for the created exclusion.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'Device', 'IP')]
        [string]$EntityType,

        [Parameter(Mandatory = $true)]
        [string[]]$Names,

        [Parameter()]
        [string]$Comment
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/api/v1/discovery/exclude_entities/upload/"

        # Map entity type to API numeric value
        # Based on observed API: 1=User, 2=IP, 3=Device
        $entityTypeMap = @{
            'User'   = 1
            'IP'     = 2
            'Device' = 3
        }

        # Build request body matching the observed API format
        $body = @{
            comment    = if ($Comment) { $Comment } else { "" }
            dateAdded  = [long]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
            entityType = $entityTypeMap[$EntityType]
            groups     = @()
            names      = $Names
        }

        $bodyJson = $body | ConvertTo-Json -Compress

        $target = "Discovery Exclusion for $EntityType(s): $($Names -join ', ')"
        $action = "Create"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Creating discovery exclusion for $EntityType"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $bodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for discovery exclusions
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationDiscoveryExclusion*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully created discovery exclusion"
                return $result
            }
            catch {
                Write-Error "Failed to create discovery exclusion: $_"
            }
        }
    }

    end {
    }
}
