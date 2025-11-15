function Get-XdrToken {
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


