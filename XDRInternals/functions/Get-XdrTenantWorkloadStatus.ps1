function Get-XdrTenantWorkloadStatus {
    <#
    .SYNOPSIS
        Retrieves and evaluates the workload status from Microsoft Defender XDR tenant context.

    .DESCRIPTION
        Gets the tenant context information and evaluates all properties named "Is*Active" to determine which
        Microsoft Defender workloads are active in the tenant. Provides friendly names and descriptions for known workloads.

    .PARAMETER Workload
        Filter results to a specific workload. Can match either the OriginalProperty or WorkloadName.
        Supports wildcards.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrTenantWorkloadStatus
        Retrieves and evaluates all workload statuses using cached data if available.

    .EXAMPLE
        Get-XdrTenantWorkloadStatus -Workload "IsMdeActive"
        Retrieves only the Microsoft Defender for Endpoint workload status.

    .EXAMPLE
        Get-XdrTenantWorkloadStatus -Workload "IsMdatpActive"
        Retrieves the workload status using the original property name.

    .EXAMPLE
        Get-XdrTenantWorkloadStatus -Workload "*Sentinel*"
        Retrieves workload statuses that match the Sentinel pattern.

    .EXAMPLE
        Get-XdrTenantWorkloadStatus -Force
        Forces a fresh retrieval of the tenant context and evaluates workload statuses.

    .OUTPUTS
        Array
        Returns an array of objects containing the workload name, status, and description.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Workload,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings

        # Lookup table for known workload properties
        $workloadLookup = @{
            'IsMdatpActive'    = @{
                FriendlyName = 'IsMdeActive'
                Description  = 'Is Microsoft Defender for Endpoint active in this tenant'
            }
            'IsOatpActive'     = @{
                FriendlyName = 'IsMdoActive'
                Description  = 'Is Microsoft Defender for Office 365 active in this tenant'
            }
            'IsMapgActive'     = @{
                FriendlyName = 'IsMdaActive'
                Description  = 'Is Microsoft Defender for Cloud Apps active in this tenant'
            }
            'IsAadIpActive'    = @{
                FriendlyName = 'IsEIdActive'
                Description  = 'Is Entra ID Protection active in this tenant'
            }
            'IsDlpActive'      = @{
                FriendlyName = 'IsDlpActive'
                Description  = 'Is Data Loss Prevention active in this tenant'
            }
            'IsIrmActive'      = @{
                FriendlyName = 'IsPurviewActive'
                Description  = 'Is Microsoft Purview active in this tenant'
            }
            'IsMdiActive'      = @{
                FriendlyName = 'IsMdiActive'
                Description  = 'Is Microsoft Defender for Identity active in this tenant'
            }
            'IsMdcActive'      = @{
                FriendlyName = 'IsMdcActive'
                Description  = 'Is Microsoft Defender for Cloud active in this tenant'
            }
            'IsSentinelActive' = @{
                FriendlyName = 'IsSentinelActive'
                Description  = 'Is Microsoft Sentinel active in this tenant'
            }
        }
    }

    process {
        # Get tenant context
        if ($Force) {
            $tenantContext = Get-XdrTenantContext -Force
        } else {
            $tenantContext = Get-XdrTenantContext
        }

        # Find all properties that match the pattern "Is*Active"
        $activeProperties = $tenantContext.PSObject.Properties | Where-Object { $_.Name -match '^Is.*Active$' }

        # Build the result array
        $results = foreach ($property in $activeProperties) {
            $propertyName = $property.Name
            $propertyValue = $property.Value

            # Check if we have a friendly name and description in the lookup table
            if ($workloadLookup.ContainsKey($propertyName)) {
                [PSCustomObject]@{
                    OriginalProperty = $propertyName
                    WorkloadName     = $workloadLookup[$propertyName].FriendlyName
                    IsActive         = $propertyValue
                    Description      = $workloadLookup[$propertyName].Description
                }
            } else {
                # Unknown property - still include it in the output
                [PSCustomObject]@{
                    OriginalProperty = $propertyName
                    WorkloadName     = $propertyName
                    IsActive         = $propertyValue
                    Description      = "Status of $propertyName (unknown workload)"
                }
            }
        }

        # Apply workload filter if specified
        if ($PSBoundParameters.ContainsKey('Workload')) {
            $results = $results | Where-Object {
                $_.OriginalProperty -like $Workload -or $_.WorkloadName -like $Workload
            }
        }

        return $results
    }

    end {
    }
}
