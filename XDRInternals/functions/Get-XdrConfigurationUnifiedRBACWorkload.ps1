function Get-XdrConfigurationUnifiedRBACWorkload {
    <#
    .SYNOPSIS
        Retrieves Unified RBAC workload configuration from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the Unified RBAC workload configuration for all workloads from the Microsoft Defender XDR portal,
        including workload eligibility, provisioning status, URBAC enablement, and cloud scoping activation status.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrConfigurationUnifiedRBACWorkload
        Retrieves the Unified RBAC workload configuration using cached data if available.

    .EXAMPLE
        Get-XdrConfigurationUnifiedRBACWorkload -Force
        Forces a fresh retrieval of the Unified RBAC workload configuration, bypassing the cache.

    .OUTPUTS
        Array
        Returns an array of objects containing workload configuration details with cloud scoping activation status.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $currentCacheValue = Get-XdrCache -CacheKey "XdrUnifiedRBACWorkloadConfiguration" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Unified RBAC workload configuration"
            return $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrUnifiedRBACWorkloadConfiguration"
        } else {
            Write-Verbose "XDR Unified RBAC workload configuration cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/urbacConfiguration/gw/unifiedrbac/configuration/tenantinfo/"
        Write-Verbose "Retrieving XDR Unified RBAC workload configuration"
        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
        } catch {
            Write-Error "Failed to retrieve Unified RBAC workload configuration: $_"
            return
        }

        # Process the result to flatten workloads and add cloudScopingActivationStatus
        $processedResult = @()

        foreach ($property in $result.workloads.PSObject.Properties) {
            $workloadName = $property.Name
            $workloadData = $property.Value

            # Translate workload names
            $translatedName = switch ($workloadName) {
                'Aad' { 'EntraID' }
                'Mdc' { 'DefenderForCloud' }
                'Mde' { 'DefenderForEndpoint' }
                'Mdo' { 'DefenderForOffice365' }
                'Mdi' { 'DefenderForIdentity' }
                'Mda' { 'DefenderForCloudApps' }
                default { $workloadName }
            }

            # Create processed workload object with all properties at the same level
            $processedWorkload = [PSCustomObject]@{
                Workload                          = $translatedName
                IsWorkloadEligible                = $workloadData.isWorkloadEligible
                IsWorkloadProvisioned             = $workloadData.isWorkloadProvisioned
                IsUrbacEnabled                    = $workloadData.isUrbacEnabled
                MigrationLastImportedDate         = $workloadData.migrationInfo.lastImportedDate
                MigrationHasRoles                 = $workloadData.migrationInfo.hasRoles
                UserAccessLevel                   = $workloadData.userAccessLevel
                MaxAccessLevelForAllUnifiedScopes = $workloadData.maxAccessLevelForAllUnifiedScopes
                MaxAccessLevelIgnoreScopes        = $workloadData.maxAccessLevelIgnoreScopes
                HasEnablementToggle               = $workloadData.hasEnablementToggle
                UiTextKey                         = $workloadData.uiTextKey
            }

            # Add Mdo-specific property if it exists
            if ($workloadName -eq 'Mdo' -and $null -ne $workloadData.isExoEnabled) {
                $processedWorkload | Add-Member -MemberType NoteProperty -Name 'IsExoEnabled' -Value $workloadData.isExoEnabled
            }

            # Add to result array
            $processedResult += $processedWorkload
        }

        # Add CloudScopingActivationStatus as its own workload entry
        $cloudScopingWorkload = [PSCustomObject]@{
            Workload                          = 'CloudScopingActivationStatus'
            IsWorkloadEligible                = $null
            IsWorkloadProvisioned             = $null
            IsUrbacEnabled                    = $null
            MigrationLastImportedDate         = $null
            MigrationHasRoles                 = $null
            UserAccessLevel                   = $null
            MaxAccessLevelForAllUnifiedScopes = $null
            MaxAccessLevelIgnoreScopes        = $null
            HasEnablementToggle               = $null
            UiTextKey                         = $null
            CloudScopingActivationStatus      = $result.cloudScopingActivationStatus
        }
        $processedResult += $cloudScopingWorkload

        Set-XdrCache -CacheKey "XdrUnifiedRBACWorkloadConfiguration" -Value $processedResult -TTLMinutes 30
        return $processedResult
    }

    end {

    }
}
