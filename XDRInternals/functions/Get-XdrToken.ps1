function Get-XdrToken {
    <#
    .SYNOPSIS
        Retrieves authentication tokens for various Microsoft security services.
    
    .DESCRIPTION
        Gets authentication tokens from Microsoft Defender XDR portal for accessing various Microsoft security services and resources.
        Supports both predefined resource names and manual resource specification.
    
    .PARAMETER ResourceName
        The name of the predefined resource to get a token for. Valid values are:
        - Azure: Azure Management API
        - LogAnalytics: Log Analytics API
        - MATP: Microsoft Defender for Endpoint
        - MCAS: Microsoft Defender for Cloud Apps
        - MicrosoftGraph: Microsoft Graph API
        - MicrosoftOffice: Microsoft Office API
        - Purview: Microsoft Purview API
        - PurviewACC: Microsoft Purview Compliance Center
        - ThreatIntelligencePortal: Threat Intelligence Portal
    
    .PARAMETER Resource
        The custom resource URL or ID to get a token for. Use this for resources not covered by ResourceName.
    
    .PARAMETER ServiceType
        Optional. The service type for the custom resource.
    
    .EXAMPLE
        Get-XdrToken -ResourceName "MicrosoftGraph"
        Retrieves an authentication token for Microsoft Graph API.
    
    .EXAMPLE
        Get-XdrToken -ResourceName "MATP"
        Retrieves an authentication token for Microsoft Defender for Endpoint.
    
    .EXAMPLE
        Get-XdrToken -Resource "https://management.core.windows.net/"
        Retrieves an authentication token for a custom resource URL.
    
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
                'Azure' {
                    $Resource = "https://management.core.windows.net/"
                    $ServiceType = $null
                }
                'LogAnalytics' {
                    $Resource = "ca7f3f0b-7d91-482c-8e09-c5d840d0eac5"
                }

                'MATP' {
                    # https://securitycenter.microsoft.com/mtp
                    $Resource = "MATP"
                }
                'MCAS' {
                    # Microsoft Defendwer for Cloud Apps
                    $Resource = "MCAS"
                }
                'MicrosoftGraph' {
                    $Resource = "https://graph.microsoft.com/"
                }
                'MicrosoftOffice' {
                    $Resource = "https://portal.office.com"
                }
                'Purview' {
                    $Resource = "https://api.purview-service.microsoft.com"
                    # 73c2949e-da2d-457a-9607-fcc665198967 = Azure Purview
                    $ServiceType = "73c2949e-da2d-457a-9607-fcc665198967"

                }
                'PurviewACC' {
                    $TenantId = (Get-XdrTenantContext).AuthInfo.TenantId
                    $Resource = "https://$($TenantId)-api.purview-service.microsoft.com"
                    # 73c2949e-da2d-457a-9607-fcc665198967 = Azure Purview
                    $ServiceType = "73c2949e-da2d-457a-9607-fcc665198967"
                }
                'ThreatIntelligencePortal' {
                    $Resource = "478d8d1a-326f-49da-a58e-8f576faa4b5e"
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


