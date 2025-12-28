function Set-XdrCloudAppsGeneralSetting {
    <#
    .SYNOPSIS
        Updates Microsoft Defender for Cloud Apps (Cloud Apps) general settings.

    .DESCRIPTION
        Sends a POST request to the Cloud Apps general settings endpoint to update one or more settings.
        Only parameters provided will be included in the request body. On success, clears the
        cached value used by Get-XdrCloudAppsGeneralSetting so subsequent reads return fresh data.

    .PARAMETER BlockAppsUrl
        One or more URLs to block (mapped to API key "blockAppsURL").

    .PARAMETER CustomWarnUrl
        One or more URLs for custom warning pages (mapped to API key "customWarnURL").

    .PARAMETER MdatpGlobalSeverityLevel
        Global severity level for Defender integration (mapped to API key "mdatpGlobalSeverityLevel").
        Example: 3

    .PARAMETER AppControlEnabled
        Enables or disables app control (mapped to API key "appControlEnabled").

    .PARAMETER DeleteConfiguredDomains
        Required by Cloud Apps when disabling app control. Indicates whether to delete configured domains
        during the operation (mapped to API key "deleteConfiguredDomains").

    .PARAMETER PassThru
        When set, returns the API response.

    .EXAMPLE
        Set-XdrCloudAppsGeneralSetting -BlockAppsUrl "" -CustomWarnUrl "" -MdatpGlobalSeverityLevel 3 -AppControlEnabled $true -Verbose

    .EXAMPLE
        # Update only app control
        Set-XdrCloudAppsGeneralSetting -AppControlEnabled $false

    .NOTES
        The Cloud Apps API expects values as arrays of strings. This function converts types accordingly.

    .PARAMETER Confirm
        Prompts for confirmation before performing each update.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter()]
        [string[]]$BlockAppsUrl,

        [Parameter()]
        [string[]]$CustomWarnUrl,

        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$MdatpGlobalSeverityLevel,

        [Parameter()]
        [bool]$AppControlEnabled,

        [Parameter()]
        [bool]$DeleteConfiguredDomains,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $results = @()

        if ($PSBoundParameters.ContainsKey('BlockAppsUrl')) {
            Write-Verbose "Updating Cloud Apps blockAppsURL via Set-XdrCloudAppsBlockAppsUrl"
            $r = Set-XdrCloudAppsBlockAppsUrl -Url $BlockAppsUrl -PassThru:$PassThru
            if ($PassThru -and $null -ne $r) { $results += [pscustomobject]@{ Setting = 'blockAppsURL'; Result = $r } }
        }

        if ($PSBoundParameters.ContainsKey('CustomWarnUrl')) {
            Write-Verbose "Updating Cloud Apps customWarnURL via Set-XdrCloudAppsCustomWarnUrl"
            $r = Set-XdrCloudAppsCustomWarnUrl -Url $CustomWarnUrl -PassThru:$PassThru
            if ($PassThru -and $null -ne $r) { $results += [pscustomobject]@{ Setting = 'customWarnURL'; Result = $r } }
        }

        if ($PSBoundParameters.ContainsKey('MdatpGlobalSeverityLevel')) {
            Write-Verbose "Updating Cloud Apps mdatpGlobalSeverityLevel via Set-XdrCloudAppsMdatpGlobalSeverityLevel"
            $r = Set-XdrCloudAppsMdatpGlobalSeverityLevel -Level $MdatpGlobalSeverityLevel -PassThru:$PassThru
            if ($PassThru -and $null -ne $r) { $results += [pscustomobject]@{ Setting = 'mdatpGlobalSeverityLevel'; Result = $r } }
        }

        if ($PSBoundParameters.ContainsKey('AppControlEnabled') -or $PSBoundParameters.ContainsKey('DeleteConfiguredDomains')) {
            Write-Verbose "Updating Cloud Apps appControlEnabled via Set-XdrCloudAppsAppControlEnabled"
            if (-not $PSBoundParameters.ContainsKey('AppControlEnabled')) {
                throw "-DeleteConfiguredDomains was specified without -AppControlEnabled. Provide -AppControlEnabled to change app control state."
            }
            $params = @{ Enabled = $AppControlEnabled }
            if ($PSBoundParameters.ContainsKey('DeleteConfiguredDomains')) { $params.DeleteConfiguredDomains = $DeleteConfiguredDomains }
            if ($PassThru) { $params.PassThru = $true }
            $r = Set-XdrCloudAppsAppControlEnabled @params
            if ($PassThru -and $null -ne $r) { $results += [pscustomobject]@{ Setting = 'appControlEnabled'; Result = $r } }
        }

        if ($PassThru -and $results.Count -gt 0) { return $results }
        if (-not $PSBoundParameters.ContainsKey('BlockAppsUrl') -and -not $PSBoundParameters.ContainsKey('CustomWarnUrl') -and -not $PSBoundParameters.ContainsKey('MdatpGlobalSeverityLevel') -and -not $PSBoundParameters.ContainsKey('AppControlEnabled') -and -not $PSBoundParameters.ContainsKey('DeleteConfiguredDomains')) {
            Write-Error "No parameters provided. Specify at least one setting to update."
        }
    }

    end {}
}
