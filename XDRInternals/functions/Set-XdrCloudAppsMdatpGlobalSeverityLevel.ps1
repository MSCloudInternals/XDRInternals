function Set-XdrCloudAppsMdatpGlobalSeverityLevel {
    <#
    .SYNOPSIS
        Sets the Cloud Apps global severity level for Defender integration.

    .DESCRIPTION
        Updates the Cloud Apps setting "mdatpGlobalSeverityLevel" by POSTing to the
        Cloud Apps settings endpoint. Values are sent as an array of strings as required
        by the API. This command supports -WhatIf/-Confirm.

    .PARAMETER Level
        Integer severity level (e.g., 3).

    .PARAMETER PassThru
        Returns the API response if specified.

    .PARAMETER Confirm
        Prompts for confirmation before performing the update.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Set-XdrCloudAppsMdatpGlobalSeverityLevel -Level 3 -WhatIf -Verbose
        Demonstrates a dry run updating the global severity level to 3.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateRange(0, 3)]
        [int]$Level,

        [Parameter()]
        [switch]$PassThru
    )

    begin { Update-XdrConnectionSettings }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/Cloud Apps/cas/api/v1/settings/"
        $body = @{ mdatpGlobalSeverityLevel = @([string]$Level) }
        $json = $body | ConvertTo-Json -Depth 10
        if ($PSCmdlet.ShouldProcess($Uri, 'POST Cloud Apps mdatpGlobalSeverityLevel')) {
            try {
                $result = Invoke-XdrRestMethod -Uri $Uri -Method Post -ContentType 'application/json' -Body $json
                Clear-XdrCache -CacheKey "XdrCloudAppsGeneralSettings" -ErrorAction SilentlyContinue
                if ($PassThru) { return $result }
            } catch { Write-Error "Failed to set Cloud Apps mdatpGlobalSeverityLevel: $_" }
        }
    }
}
