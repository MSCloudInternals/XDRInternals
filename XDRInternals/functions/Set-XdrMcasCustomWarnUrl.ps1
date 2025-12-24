function Set-XdrMcasCustomWarnUrl {
    <#
    .SYNOPSIS
        Sets the MCAS customWarnURL list.

    .DESCRIPTION
        Updates the MCAS setting "customWarnURL" with one or more URLs used for
        custom warning pages. Values are posted as an array of strings. Supports
        -WhatIf/-Confirm.

    .PARAMETER Url
        One or more URLs for custom warning pages.

    .PARAMETER PassThru
        Returns the API response if specified.

    .PARAMETER Confirm
        Prompts for confirmation before performing the update.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Set-XdrMcasCustomWarnUrl -Url @('https://warn.example') -WhatIf -Verbose
        Demonstrates a dry run updating customWarnURL.
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
        $body = @{ customWarnURL = @($Url | ForEach-Object { [string]$_ }) }
        $json = $body | ConvertTo-Json -Depth 10
        if ($PSCmdlet.ShouldProcess($Uri, 'POST MCAS customWarnURL')) {
            try {
                $result = Invoke-XdrRestMethod -Uri $Uri -Method Post -ContentType 'application/json' -Body $json
                Clear-XdrCache -CacheKey "XdrMcasGeneralSettings" -ErrorAction SilentlyContinue
                if ($PassThru) { return $result }
            } catch { Write-Error "Failed to set MCAS customWarnURL: $_" }
        }
    }
}
