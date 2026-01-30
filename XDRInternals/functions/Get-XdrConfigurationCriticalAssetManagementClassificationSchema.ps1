function Get-XdrConfigurationCriticalAssetManagementClassificationSchema {
    <#
    .SYNOPSIS
        Retrieves the schema for Critical Asset Management rules from Microsoft Defender XDR.

    .DESCRIPTION
        Gets the schema definition for the Critical Asset Management query builder. This includes
        the available asset types (Devices, Identities, CloudResources) and their filterable
        properties that can be used when creating custom critical asset rules.

        Each property includes its name and type (e.g., ClosedList, Boolean, String, Array).
        This information is useful for understanding what criteria can be used to identify
        critical assets in your organization.

    .PARAMETER AssetType
        Filter the schema to a specific asset type. Valid values are:
        - Devices: Properties for device-based rules
        - Identities: Properties for identity/user-based rules
        - CloudResources: Properties for cloud resource-based rules

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassificationSchema
        Retrieves the full schema for all asset types.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassificationSchema -AssetType Identities
        Retrieves only the schema for identity-based rules.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassificationSchema -AssetType Devices |
            Select-Object -ExpandProperty properties
        Lists all available properties for device-based critical asset rules.

    .EXAMPLE
        Get-XdrConfigurationCriticalAssetManagementClassificationSchema -Force
        Forces a fresh retrieval of the schema, bypassing the cache.

    .EXAMPLE
        # Discover schema and create a rule based on available properties
        $deviceProps = Get-XdrConfigurationCriticalAssetManagementClassificationSchema -AssetType Devices |
            Select-Object -ExpandProperty properties

        # Display available properties
        $deviceProps | Format-Table name, propertyType

        # Create a rule using one of the discovered properties
        New-XdrConfigurationCriticalAssetManagementClassification `
            -RuleName "Critical Servers" `
            -RuleDescription "Servers with critical tag" `
            -AssetType Devices `
            -CriticalityLevel VeryHigh `
            -Property "Tags" `
            -Operator Contains `
            -Value "Critical"

        Discovers available properties and creates a rule using one of them.

    .OUTPUTS
        PSCustomObject[]
        Returns an array of asset type schemas, each containing:
        - assetType: The type of asset (Devices, Identities, CloudResources)
        - properties: An array of property definitions with name and propertyType

    .NOTES
        Property types include:
        - ClosedList: Enumerated values (dropdown selection)
        - ClosedListAsArray: Multiple enumerated values
        - ClosedListAsJson: JSON-based enumerated values
        - Boolean: True/False values
        - String: Free-text values
        - Array: Multiple free-text values
        - DeviceEntity: Device name lookup
        - UserEntity: User/account name lookup
    #>
    [OutputType([System.Object[]])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('Devices', 'Identities', 'CloudResources')]
        [string]$AssetType,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $CacheKey = "XdrCriticalAssetManagementClassificationSchema"
        if (-not $Force) {
            $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Critical Asset Management schema data"
                $schema = $cache.Value
            }
        }

        if (-not $schema) {
            if ($Force) {
                Write-Verbose "Force parameter specified, bypassing cache"
                Clear-XdrCache -CacheKey $CacheKey
            } else {
                Write-Verbose "Critical Asset Management schema cache is missing or expired"
            }

            $Uri = "https://security.microsoft.com/apiproxy/mtp/xspmatlas/assetrules/querybuilder/schema"
            Write-Verbose "Retrieving Critical Asset Management schema"

            $response = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            $schema = $response.schema

            Set-XdrCache -CacheKey $CacheKey -Value $schema -TTLMinutes 60
        }

        # Filter by asset type if specified
        if ($AssetType) {
            Write-Verbose "Filtering schema to asset type: $AssetType"
            $schema = $schema | Where-Object { $_.assetType -eq $AssetType }
        }

        return $schema
    }

    end {
    }
}
