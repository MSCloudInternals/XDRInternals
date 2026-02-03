function New-XdrCloudAppsConfigurationScopedProfile {
    <#
    .SYNOPSIS
        Creates a new scoped profile in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Creates a new scoped profile in Microsoft Defender for Cloud Apps for Cloud Discovery.
        Scoped profiles allow you to assign specific machine groups to Cloud Discovery data sources,
        enabling segmented visibility of discovered apps.

    .PARAMETER Name
        The name of the scoped profile.

    .PARAMETER Description
        Optional description of the scoped profile.

    .PARAMETER GroupIds
        Array of machine group IDs to include in the scoped profile.
        Machine groups can be retrieved using Get-XdrCloudAppsConfigurationAutocomplete with -Type MachineGroups.

    .PARAMETER IsInclude
        Specifies whether this is an include or exclude profile.
        Default is $true (include profile).

    .PARAMETER Confirm
        Prompts for confirmation before creating the profile.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        New-XdrCloudAppsConfigurationScopedProfile -Name "EMEA Devices" -GroupIds 203
        Creates a new scoped profile named "EMEA Devices" that includes machine group ID 203.

    .EXAMPLE
        New-XdrCloudAppsConfigurationScopedProfile -Name "Excluded Devices" -GroupIds 204, 205 -IsInclude $false
        Creates a new scoped profile that excludes the specified machine groups.

    .EXAMPLE
        New-XdrCloudAppsConfigurationScopedProfile -Name "Test Profile" -GroupIds 342 -WhatIf
        Shows what would happen if creating the scoped profile without actually creating it.

    .OUTPUTS
        PSObject
        Returns the created profile ID.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [int[]]$GroupIds,

        [Parameter()]
        [bool]$IsInclude = $true
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/scoped_profiles/create_profile/"

        # Build request body - API expects isInclude as a string "true" or "false"
        $body = @{
            name = $Name
            groupIds = $GroupIds
            isInclude = $IsInclude.ToString().ToLower()
        }

        # Add description if provided
        if ($Description) {
            $body.description = $Description
        }

        $bodyJson = $body | ConvertTo-Json -Compress

        $target = "Scoped Profile '$Name'"
        $action = "Create"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Creating scoped profile: $Name"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $bodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for scoped profiles
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationScopedProfile*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully created scoped profile. ID: $($result.id)"
                return $result
            }
            catch {
                Write-Error "Failed to create scoped profile '$Name': $_"
            }
        }
    }

    end {
    }
}
