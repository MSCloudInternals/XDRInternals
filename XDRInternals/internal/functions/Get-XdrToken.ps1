function Get-XdrToken {
    <#
    .SYNOPSIS
        Retrieves authentication tokens for various Microsoft security services.

    .DESCRIPTION
        Gets authentication tokens from Microsoft Defender XDR portal for accessing various Microsoft security services and resources.
        Supports both predefined resource names and manual resource specification.

    .PARAMETER ResourceName
        The name of the predefined resource to get a token for. Valid values are:
        - MATP: Microsoft Defender for Endpoint

    .PARAMETER Resource
        The custom resource URL or ID to get a token for. Use this for resources not covered by ResourceName.

    .PARAMETER ServiceType
        Optional. The service type for the custom resource.

    .EXAMPLE
        Get-XdrToken -ResourceName "MATP"
        Retrieves an authentication token for Microsoft Defender for Endpoint.

    .OUTPUTS
        Object
        Returns the authentication token response object.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Automatic')]
        [ValidateSet('Azure', 'LogAnalytics', 'MATP', 'MCAS', 'MicrosoftGraph', 'MicrosoftOffice', 'Purview', 'PurviewACC', 'ThreatIntelligencePortal')]
        [string]$ResourceName,

        [Parameter(Mandatory, ParameterSetName = 'Manual')]
        [string]$Resource,

        [Parameter(ParameterSetName = 'Manual')]
        [string]$ServiceType
    )
    begin {
        Update-XdrConnectionSettings
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Automatic') {
            switch ($ResourceName) {
                'MATP' {
                    # https://securitycenter.microsoft.com/mtp
                    $Resource = "MATP"
                }
                default {
                    throw "Unsupported ServiceType: $ServiceType"
                }
            }
        }
        Write-Verbose "Retrieving XDR token for service"
        $encodedResource = [System.Web.HttpUtility]::UrlEncode($Resource)
        if ( [string]::IsNullOrWhiteSpace($ServiceType) ) {
            $uri = "https://security.microsoft.com/api/Auth/getToken?resource=$encodedResource"
        } else {
            $uri = "https://security.microsoft.com/api/Auth/getToken?resource=$encodedResource&serviceType=$ServiceType"
        }
        Write-Verbose "Request URI: $uri"
        Invoke-RestMethod -Uri $uri -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }

    end {

    }
}


