function Set-XdrMcasBlockAppsUrl {
    <#
    .SYNOPSIS
        Sets the MCAS blockAppsURL list.

    .DESCRIPTION
        Updates the MCAS setting "blockAppsURL" with one or more URLs. Values are
        posted as an array of strings per API requirements. Supports -WhatIf/-Confirm.

    .PARAMETER Url
        One or more URLs to block.

    .PARAMETER PassThru
        Returns the API response if specified.

    .PARAMETER Confirm
        Prompts for confirmation before performing the update.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Set-XdrMcasBlockAppsUrl -Url @('https://bad.example') -WhatIf -Verbose
        Demonstrates a dry run updating blockAppsURL.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string[]]$Url,

        [Parameter()]
        [switch]$PassThru
    )

    begin { Update-XdrConnectionSettings }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/settings/"
        $body = @{ blockAppsURL = @($Url | ForEach-Object { [string]$_ }) }
        $json = $body | ConvertTo-Json -Depth 10
        if ($PSCmdlet.ShouldProcess($Uri, 'POST MCAS blockAppsURL')) {
            try {
                $result = Invoke-XdrRestMethod -Uri $Uri -Method Post -ContentType 'application/json' -Body $json
                Clear-XdrCache -CacheKey "XdrMcasGeneralSettings" -ErrorAction SilentlyContinue
                if ($PassThru) { return $result }
            } catch { Write-Error "Failed to set MCAS blockAppsURL: $_" }
        }
    }
}
