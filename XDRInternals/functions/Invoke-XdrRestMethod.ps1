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
        [uri]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [string]$ContentType = "application/json",

        [Parameter(Mandatory = $false)]
        $WebSession,

        [Parameter(Mandatory = $false)]
        [Hashtable]$Headers,

        [Parameter()]
        $Body
    )

    begin {
        if (-not $Uri.IsAbsoluteUri -or
            $Uri.Scheme -ne 'https' -or
            -not $Uri.IsDefaultPort -or
            $Uri.DnsSafeHost -ne 'security.microsoft.com' -or
            -not [string]::IsNullOrWhiteSpace($Uri.UserInfo)) {
            throw 'Invoke-XdrRestMethod only sends an authenticated session to https://security.microsoft.com.'
        }

        Update-XdrConnectionSettings

        if (-not $PSBoundParameters.ContainsKey('WebSession')) {
            $WebSession = $script:session
        }
        if (-not $PSBoundParameters.ContainsKey('Headers')) {
            $Headers = $script:headers
        }
    }

    process {
        try {
            if ($Body) {
                Invoke-RestMethod -Uri $Uri -Method $Method -ContentType $ContentType -WebSession $WebSession -Headers $Headers -Body $Body
            } else {
                Invoke-RestMethod -Uri $Uri -Method $Method -ContentType $ContentType -WebSession $WebSession -Headers $Headers
            }
        } catch {
            $statusCode = if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                [int]$_.Exception.Response.StatusCode
            }
            if ($statusCode) {
                throw "The Defender XDR REST request failed with HTTP status $statusCode."
            }

            throw 'The Defender XDR REST request failed before a response was returned.'
        }
    }

    end {

    }
}
