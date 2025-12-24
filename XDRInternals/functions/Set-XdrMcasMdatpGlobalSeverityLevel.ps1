function Set-XdrMcasMdatpGlobalSeverityLevel {
    <#
    .SYNOPSIS
        Sets the MCAS global severity level for Defender integration.

    .DESCRIPTION
        Updates the MCAS setting "mdatpGlobalSeverityLevel" by POSTing to the
        MCAS settings endpoint. Values are sent as an array of strings as required
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
        Set-XdrMcasMdatpGlobalSeverityLevel -Level 3 -WhatIf -Verbose
        Demonstrates a dry run updating the global severity level to 3.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateRange(0, 10)]
        [int]$Level,

        [Parameter()]
        [switch]$PassThru
    )

    begin { Update-XdrConnectionSettings }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/settings/"
        $body = @{ mdatpGlobalSeverityLevel = @([string]$Level) }
        $json = $body | ConvertTo-Json -Depth 10
        if ($PSCmdlet.ShouldProcess($Uri, 'POST MCAS mdatpGlobalSeverityLevel')) {
            try {
                $result = Invoke-XdrRestMethod -Uri $Uri -Method Post -ContentType 'application/json' -Body $json
                Clear-XdrCache -CacheKey "XdrMcasGeneralSettings" -ErrorAction SilentlyContinue
                if ($PassThru) { return $result }
            } catch { Write-Error "Failed to set MCAS mdatpGlobalSeverityLevel: $_" }
        }
    }
}
