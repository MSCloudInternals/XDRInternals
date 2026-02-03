function New-XdrCloudAppsConfigurationApiToken {
    <#
    .SYNOPSIS
        Creates a new API token in Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Creates a new API token in Microsoft Defender for Cloud Apps.
        API tokens are used to authenticate API calls to the Cloud Apps Security API.
        
        IMPORTANT: The token value is only shown once upon creation. Make sure to save it securely.

    .PARAMETER Name
        The name for the new API token.

    .PARAMETER Confirm
        Prompts for confirmation before creating the token.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        New-XdrCloudAppsConfigurationApiToken -Name "SIEM Integration"
        Creates a new API token named "SIEM Integration" and returns the token details including the secret.

    .EXAMPLE
        $token = New-XdrCloudAppsConfigurationApiToken -Name "Automation Token"
        $token.token | Set-Clipboard
        Creates a new API token and copies the token value to the clipboard.

    .EXAMPLE
        New-XdrCloudAppsConfigurationApiToken -Name "Test Token" -WhatIf
        Shows what would happen if an API token named "Test Token" was created.

    .OUTPUTS
        PSObject
        Returns the API response containing the token details including:
        - _id: The token ID
        - name: The token name
        - token: The actual token value (only shown once!)
        - createdAt: Creation timestamp
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSObject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/tokens/generate/"

        # Build request body
        $body = @{
            name = $Name
        }

        $bodyJson = $body | ConvertTo-Json -Compress

        $target = "API Token '$Name'"
        $action = "Create"

        if ($PSCmdlet.ShouldProcess($target, $action)) {
            try {
                Write-Verbose "Creating API token: $Name"
                $result = Invoke-RestMethod -Uri $Uri -Method Post -Body $bodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for API tokens
                Clear-XdrCache -CacheKey "*XdrCloudAppsConfigurationApiToken*" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully created API token: $Name"
                Write-Warning "The API token value is only shown once. Make sure to save it securely!"

                return $result
            }
            catch {
                Write-Error "Failed to create API token '$Name': $_"
            }
        }
    }

    end {
    }
}
