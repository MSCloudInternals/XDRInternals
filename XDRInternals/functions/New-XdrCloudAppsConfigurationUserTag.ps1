function New-XdrCloudAppsConfigurationUserTag {
    <#
    .SYNOPSIS
        Creates a new user tag in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Creates a new user tag in Microsoft Defender for Cloud Apps by importing an Azure AD group.
        User tags are used to group users for monitoring, policies, and scoped deployments.

    .PARAMETER AppId
        The application ID to associate with the user tag.
        Common values:
        - 11161: Microsoft Entra ID (Azure AD)
        Use Get-XdrCloudAppsConfigurationConnectedService to find app IDs for other connected apps.

    .PARAMETER GroupId
        The Azure AD group GUID to import as a user tag.
        This must be a valid GUID format (e.g., "7c8468b9-c8a0-4245-8d8a-cebf4c62dcac").

    .PARAMETER ShouldNotify
        Specifies whether to enable notifications for this user tag.
        Default is $true.

    .PARAMETER Confirm
        Prompts for confirmation before creating the user tag.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        New-XdrCloudAppsConfigurationUserTag -AppId 11161 -GroupId "7c8468b9-c8a0-4245-8d8a-cebf4c62dcac"
        Creates a new user tag from the specified Azure AD group using Entra ID as the source app.

    .EXAMPLE
        New-XdrCloudAppsConfigurationUserTag -AppId 11161 -GroupId "7c8468b9-c8a0-4245-8d8a-cebf4c62dcac" -ShouldNotify $false
        Creates a new user tag with notifications disabled.

    .EXAMPLE
        $groups = @("7c8468b9-c8a0-4245-8d8a-cebf4c62dcac", "8d9579ca-d9b1-5356-9e9b-ddf5d73edbd0")
        $groups | ForEach-Object { New-XdrCloudAppsConfigurationUserTag -AppId 11161 -GroupId $_ }
        Creates user tags from multiple Azure AD groups.

    .OUTPUTS
        PSObject
        Returns the created user tag ID.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $true)]
        [int]$AppId,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$GroupId,

        [Parameter()]
        [bool]$ShouldNotify = $true
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/user_tags/create_tag/"

        # Build request body
        $body = @{
            appId = $AppId
            groupId = $GroupId
            shouldNotify = $ShouldNotify
        }

        $bodyJson = $body | ConvertTo-Json -Compress

        $target = "User Tag for group '$GroupId' (AppId: $AppId)"
        $action = "Create"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Creating user tag for group: $GroupId"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $bodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for user tags
                Clear-XdrCache -CacheKey "XdrCloudAppsConfigurationUserTag*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully created user tag. ID: $($result.id)"
                return $result
            }
            catch {
                Write-Error "Failed to create user tag for group '$GroupId': $_"
            }
        }
    }

    end {
    }
}
