function New-XdrCloudAppsConfigurationDiscoveryAppTag {
    <#
    .SYNOPSIS
        Creates a new discovery app tag in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Creates a new discovery app tag in Microsoft Defender for Cloud Apps.
        App tags are used to categorize and organize discovered cloud applications.

    .PARAMETER TagName
        The name for the new app tag.

    .PARAMETER Confirm
        Prompts for confirmation before creating the tag.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        New-XdrCloudAppsConfigurationDiscoveryAppTag -TagName "Approved"
        Creates a new discovery app tag named "Approved".

    .EXAMPLE
        New-XdrCloudAppsConfigurationDiscoveryAppTag -TagName "Under Review" -WhatIf
        Shows what would happen if a tag named "Under Review" was created.

    .EXAMPLE
        @("Approved", "Blocked", "Under Review") | ForEach-Object { New-XdrCloudAppsConfigurationDiscoveryAppTag -TagName $_ }
        Creates multiple discovery app tags.

    .OUTPUTS
        PSObject
        Returns the API response for the created tag.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TagName
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/app_tags/create_tag/"

        # Build request body
        $body = @{
            tagName = $TagName
        }

        $bodyJson = $body | ConvertTo-Json -Compress

        $target = "Discovery App Tag '$TagName'"
        $action = "Create"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Creating discovery app tag: $TagName"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $bodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for discovery app tags
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationDiscoveryAppTag*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully created discovery app tag: $TagName"
                return $result
            }
            catch {
                Write-Error "Failed to create discovery app tag '$TagName': $_"
            }
        }
    }

    end {
    }
}
