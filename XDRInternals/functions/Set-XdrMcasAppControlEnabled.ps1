function Set-XdrMcasAppControlEnabled {
    <#
    .SYNOPSIS
        Enables or disables MCAS App Control.

    .DESCRIPTION
        Sends a POST request to update appControlEnabled. When disabling, MCAS requires
        the deleteConfiguredDomains flag to be included.

    .PARAMETER Enabled
        Target state for App Control.

    .PARAMETER DeleteConfiguredDomains
        Required when disabling App Control. Whether to delete configured domains as part of the operation.

    .PARAMETER PassThru
        Returns the API response if specified.

    .EXAMPLE
        Set-XdrMcasAppControlEnabled -Enabled $false -DeleteConfiguredDomains $false

    .PARAMETER Confirm
        Prompts for confirmation before performing the update.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [bool]$Enabled,

        [Parameter()]
        [bool]$DeleteConfiguredDomains,

        [Parameter()]
        [switch]$PassThru
    )

    begin { Update-XdrConnectionSettings }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/settings/"
        $body = @{ appControlEnabled = @([string]$Enabled.ToString().ToLower()) }

        if (-not $Enabled) {
            if (-not $PSBoundParameters.ContainsKey('DeleteConfiguredDomains')) {
                throw "Disabling app control requires -DeleteConfiguredDomains <true|false>."
            }
            $body.deleteConfiguredDomains = @([string]$DeleteConfiguredDomains.ToString().ToLower())
        } elseif ($PSBoundParameters.ContainsKey('DeleteConfiguredDomains')) {
            # If enabling and flag supplied, still pass through explicitly if provided
            $body.deleteConfiguredDomains = @([string]$DeleteConfiguredDomains.ToString().ToLower())
        }

        $json = $body | ConvertTo-Json -Depth 10
        if ($PSCmdlet.ShouldProcess($Uri, 'POST MCAS app control setting')) {
            try {
                $result = Invoke-XdrRestMethod -Uri $Uri -Method Post -ContentType 'application/json' -Body $json
                Clear-XdrCache -CacheKey "XdrMcasGeneralSettings" -ErrorAction SilentlyContinue
                if ($PassThru) { return $result }
            } catch { Write-Error "Failed to set MCAS app control: $_" }
        }
    }
}
