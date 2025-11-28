function Invoke-XdrRestMethod {
    <#
    .SYNOPSIS
        Invokes a REST API call to Microsoft Defender XDR with authenticated session.

    .DESCRIPTION
        Executes REST API requests to Microsoft Defender XDR endpoints using the authenticated session and headers.
        This is a wrapper function that ensures connection settings are updated before making the API call.

    .PARAMETER Uri
        The URI of the API endpoint to call.

    .PARAMETER Method
        The HTTP method to use for the request. Defaults to "GET".

    .PARAMETER ContentType
        The content type of the request. Defaults to "application/json".

    .PARAMETER WebSession
        The web session to use for the request. Defaults to the script-scoped session variable.

    .PARAMETER Headers
        The headers to include in the request. Defaults to the script-scoped headers variable.

    .PARAMETER Body
        The body of the request, if applicable.

    .EXAMPLE
        Invoke-XdrRestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/GetAdvancedFeaturesSetting"
        Makes a GET request to the specified XDR API endpoint.

    .EXAMPLE
        Invoke-XdrRestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/..." -Method "POST"
        Makes a POST request to the specified XDR API endpoint.

    .OUTPUTS
        Object
        Returns the response object from the API call.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [string]$ContentType = "application/json",

        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = $script:session,

        [Parameter(Mandatory = $false)]
        [Hashtable]$Headers = $script:headers,

        [Parameter()]
        $Body
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        try {
            if ($Body) {
                Invoke-RestMethod -Uri $Uri -Method $Method -ContentType $ContentType -WebSession $WebSession -Headers $Headers -Body $Body
            } else {
                Invoke-RestMethod -Uri $Uri -Method $Method -ContentType $ContentType -WebSession $WebSession -Headers $Headers
            }
        } catch {
            Write-Error "Failed to invoke XDR REST method: $_"
            throw
        }
    }

    end {

    }
}