function Set-XdrCloudAppsDiscoveredApp {
    <#
    .SYNOPSIS
        Updates properties of a discovered app in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        The Set-XdrCloudAppsDiscoveredApp cmdlet updates properties of a discovered application
        in Cloud App Security. You can update the note, sanctioned status, or risk score.

        Use -Note to set or update the note for an app.
        Use -Sanctioned to mark an app as sanctioned or unsanctioned.
        Use -Score to set a custom risk score for an app.

    .PARAMETER AppId
        The unique identifier of the discovered app to update.

    .PARAMETER Note
        The note text to set for the discovered app. Can be used to document findings,
        add context, or track investigation status.

    .PARAMETER Sanctioned
        Specifies whether the app should be marked as sanctioned (approved) or unsanctioned.
        $true marks the app as sanctioned, $false marks it as unsanctioned.
        Requires -StreamId parameter.

    .PARAMETER SanctionTag
        An optional tag to categorize the sanctioned status. Can be used to indicate
        the reason for sanctioning or the approval category. Only used with -Sanctioned.

    .PARAMETER Score
        The custom risk score to assign to the app. Must be between 1 and 10,
        where 1 represents lowest risk and 10 represents highest risk.
        Requires -StreamId parameter.

    .PARAMETER StreamId
        The Cloud Discovery stream identifier where the app was discovered.
        Required when using -Sanctioned or -Score parameters.
        Use Get-XdrCloudAppsConfiguration -Type DiscoveryStream to retrieve available streams.

    .EXAMPLE
        Set-XdrCloudAppsDiscoveredApp -AppId "12345" -Note "Approved for marketing team use"

        Sets a note on the discovered app indicating it's approved for the marketing team.

    .EXAMPLE
        Set-XdrCloudAppsDiscoveredApp -AppId "12345" -Sanctioned $true -StreamId "stream-abc123"

        Marks the discovered app as sanctioned (approved) in the organization.

    .EXAMPLE
        Set-XdrCloudAppsDiscoveredApp -AppId "12345" -Sanctioned $true -SanctionTag "IT-Approved" -StreamId "stream-abc123"

        Marks the app as sanctioned with a specific approval tag.

    .EXAMPLE
        Set-XdrCloudAppsDiscoveredApp -AppId "12345" -Score 8 -StreamId "stream-abc123"

        Sets a high risk score of 8 for the discovered app.

    .EXAMPLE
        Get-XdrCloudAppsApp -Type Discovered -StreamId "stream-abc123" | Where-Object { $_.name -like "*Dropbox*" } |
            Set-XdrCloudAppsDiscoveredApp -Sanctioned $false -StreamId "stream-abc123"

        Finds Dropbox apps and marks them as unsanctioned.

    .NOTES
        This cmdlet requires an active XDR session. Use Connect-XdrByEstsCookie to authenticate.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Updates metadata only')]
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'Note')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('pk', 'Id', '_id')]
        [string]$AppId,

        [Parameter(ParameterSetName = 'Note', Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Note,

        [Parameter(ParameterSetName = 'Sanctioned', Mandatory = $true)]
        [bool]$Sanctioned,

        [Parameter(ParameterSetName = 'Sanctioned')]
        [string]$SanctionTag,

        [Parameter(ParameterSetName = 'Sanctioned', Mandatory = $true)]
        [Parameter(ParameterSetName = 'Score', Mandatory = $true)]
        [string]$StreamId,

        [Parameter(ParameterSetName = 'Score', Mandatory = $true)]
        [ValidateRange(1, 10)]
        [int]$Score
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Note' {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/discovery_app/update_app_note/"

                Write-Verbose "Updating note for discovered app: $AppId"

                $Body = @{
                    note = $Note
                    pk   = $AppId
                } | ConvertTo-Json -Depth 10

                Write-Verbose "Request body: $Body"

                try {
                    $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    Write-Verbose "Successfully updated note for app $AppId"
                    return $result
                } catch {
                    Write-Error "Failed to update note for discovered app '$AppId': $_"
                }
            }

            'Sanctioned' {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/discovery_app/$AppId/set_sanctioned/"

                Write-Verbose "Setting sanctioned status for discovered app: $AppId to $Sanctioned"

                $Body = @{
                    appId      = $AppId
                    sanctioned = $Sanctioned
                    streamId   = $StreamId
                }

                if ($PSBoundParameters.ContainsKey('SanctionTag')) {
                    $Body['sanctionTag'] = $SanctionTag
                }

                $JsonBody = $Body | ConvertTo-Json -Depth 10

                Write-Verbose "Request URI: $Uri"
                Write-Verbose "Request body: $JsonBody"

                try {
                    $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $JsonBody -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    Write-Verbose "Successfully updated sanctioned status for app $AppId"
                    return $result
                } catch {
                    Write-Error "Failed to update sanctioned status for discovered app '$AppId': $_"
                }
            }

            'Score' {
                $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/discovery_app/update_score/"

                Write-Verbose "Updating risk score for discovered app: $AppId to $Score"

                $Body = @{
                    appId    = $AppId
                    score    = $Score
                    streamId = $StreamId
                } | ConvertTo-Json -Depth 10

                Write-Verbose "Request body: $Body"

                try {
                    $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                    Write-Verbose "Successfully updated score for app $AppId"
                    return $result
                } catch {
                    Write-Error "Failed to update score for discovered app '$AppId': $_"
                }
            }
        }
    }

    end {
    }
}

