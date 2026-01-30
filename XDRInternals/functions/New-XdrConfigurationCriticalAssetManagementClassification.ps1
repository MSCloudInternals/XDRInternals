function New-XdrConfigurationCriticalAssetManagementClassification {
    <#
    .SYNOPSIS
        Creates a new Critical Asset Management classification rule in Microsoft Defender XDR.

    .DESCRIPTION
        Creates a custom Critical Asset Management classification rule to identify and classify
        critical assets in your organization. Rules can target Devices, Identities, or CloudResources
        and use property-based conditions to match assets.

        Use Get-XdrConfigurationCriticalAssetManagementClassificationSchema to discover available properties
        and their types for building rule conditions.

    .PARAMETER RuleName
        The display name for the new classification rule. Must be unique.

    .PARAMETER RuleDescription
        A description explaining what the rule identifies and its purpose.

    .PARAMETER AssetType
        The type of assets this rule applies to. Valid values are:
        - Devices: Target device/endpoint assets
        - Identities: Target user/identity assets
        - CloudResources: Target cloud resource assets

    .PARAMETER CriticalityLevel
        The criticality level to assign to matching assets. Accepts either numeric values
        or friendly names:
        - 0 or 'VeryHigh': Very High criticality
        - 1 or 'High': High criticality
        - 2 or 'Medium': Medium criticality
        - 3 or 'Low': Low criticality

    .PARAMETER Property
        The property name to filter on. Use Get-XdrConfigurationCriticalAssetManagementClassificationSchema
        to see available properties for each asset type.

    .PARAMETER Operator
        The comparison operator. Valid values are:
        - Equals: Exact match
        - NotEquals: Does not match
        - Contains: Contains the value (for string properties)
        - NotContains: Does not contain the value

    .PARAMETER Value
        The value(s) to match against. Can be a single value or an array of values.

    .PARAMETER RuleDefinition
        Advanced: A complete rule definition hashtable for complex rules with multiple conditions.
        When specified, Property, Operator, and Value parameters are ignored.

        Example structure:
        @{
            conditionType = "Operational"
            logicalOperator = "AND"  # or "OR"
            conditions = @(
                @{
                    conditionType = "Simple"
                    predicate = @{
                        property = "Property Name"
                        operator = "Equals"
                        value = @("value1", "value2")
                    }
                }
            )
        }

    .PARAMETER Disabled
        If specified, creates the rule in a disabled state.

    .PARAMETER PassThru
        When specified, returns the full rule object after creation.
        By default, only the ruleId is returned.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .PARAMETER Confirm
        Prompts you for confirmation before running the cmdlet.

    .EXAMPLE
        New-XdrConfigurationCriticalAssetManagementClassification -RuleName "Executive Accounts" `
            -RuleDescription "Identifies executive user accounts" `
            -AssetType Identities `
            -CriticalityLevel VeryHigh `
            -Property "Job Title" `
            -Operator Equals `
            -Value "CEO", "CFO", "CTO"

        Creates a Very High criticality rule for executive accounts using the friendly name.

    .EXAMPLE
        New-XdrConfigurationCriticalAssetManagementClassification -RuleName "Domain Controllers" `
            -RuleDescription "Identifies domain controller servers" `
            -AssetType Devices `
            -CriticalityLevel 1 `
            -Property "Device Role" `
            -Operator Equals `
            -Value "DomainController"

        Creates a High criticality rule for domain controllers using numeric level.

    .EXAMPLE
        # Discover available properties for Devices, then create a rule
        Get-XdrConfigurationCriticalAssetManagementClassificationSchema -AssetType Devices |
            Select-Object -ExpandProperty properties

        New-XdrConfigurationCriticalAssetManagementClassification -RuleName "Windows Servers" `
            -RuleDescription "Windows Server devices" `
            -AssetType Devices `
            -CriticalityLevel High `
            -Property "OS Platform" `
            -Operator Equals `
            -Value "Windows" `
            -PassThru

        Discovers schema properties, then creates a rule and returns the full rule object.

    .EXAMPLE
        $rule = @{
            conditionType = "Operational"
            logicalOperator = "AND"
            conditions = @(
                @{
                    conditionType = "Simple"
                    predicate = @{
                        property = "Device Type"
                        operator = "Equals"
                        value = @("Server")
                    }
                },
                @{
                    conditionType = "Simple"
                    predicate = @{
                        property = "Tags"
                        operator = "Contains"
                        value = @("Production")
                    }
                }
            )
        }
        New-XdrConfigurationCriticalAssetManagementClassification -RuleName "Production Servers" `
            -RuleDescription "Production server devices" `
            -AssetType Devices `
            -CriticalityLevel High `
            -RuleDefinition $rule

        Creates a rule with multiple conditions using AND logic.

    .EXAMPLE
        # Full workflow: Create, verify, check affected assets, then clean up
        $newRule = New-XdrConfigurationCriticalAssetManagementClassification `
            -RuleName "Test Rule" `
            -RuleDescription "Temporary test rule" `
            -AssetType Devices `
            -CriticalityLevel Low `
            -Property "Tags" `
            -Operator Contains `
            -Value "Test" `
            -PassThru

        # View the created rule with affected assets
        Get-XdrConfigurationCriticalAssetManagementClassification -RuleId $newRule.ruleId -IncludeAffectedAssets

        # Clean up test rule
        $newRule | Remove-XdrConfigurationCriticalAssetManagementClassification -Force

        Demonstrates a complete workflow of creating, verifying, and removing a rule.

    .OUTPUTS
        PSCustomObject
        Returns an object containing the ruleId of the newly created rule.

    .NOTES
        - Rule names must be unique within the tenant
        - Use Get-XdrConfigurationCriticalAssetManagementClassificationSchema to discover available properties
        - Rules are always created in an enabled state (the -Disabled parameter is currently
          ignored by the API). To disable a rule after creation, use
          Set-XdrConfigurationCriticalAssetManagementClassification -Enabled $false
        - Predefined rules cannot be created; this cmdlet only creates user-defined rules
    #>
    [OutputType([PSCustomObject])]
    [CmdletBinding(DefaultParameterSetName = 'Simple', SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RuleName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RuleDescription,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Devices', 'Identities', 'CloudResources')]
        [string]$AssetType,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -is [int] -and $_ -ge 0 -and $_ -le 3) { return $true }
            if ($_ -in 'VeryHigh', 'High', 'Medium', 'Low') { return $true }
            throw "CriticalityLevel must be 0-3 or 'VeryHigh', 'High', 'Medium', 'Low'"
        })]
        $CriticalityLevel,

        [Parameter(Mandatory = $true, ParameterSetName = 'Simple')]
        [ValidateNotNullOrEmpty()]
        [string]$Property,

        [Parameter(Mandatory = $true, ParameterSetName = 'Simple')]
        [ValidateSet('Equals', 'NotEquals', 'Contains', 'NotContains')]
        [string]$Operator,

        [Parameter(Mandatory = $true, ParameterSetName = 'Simple')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'Advanced')]
        [ValidateNotNull()]
        [hashtable]$RuleDefinition,

        [Parameter()]
        [switch]$Disabled,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        Update-XdrConnectionSettings

        # Transform CriticalityLevel if string alias was provided
        $criticalityMap = @{
            'VeryHigh' = 0
            'High'     = 1
            'Medium'   = 2
            'Low'      = 3
        }
    }

    process {
        # Transform CriticalityLevel from string to int if needed
        $criticalityValue = if ($CriticalityLevel -is [string]) {
            $criticalityMap[$CriticalityLevel]
        } else {
            [int]$CriticalityLevel
        }

        # Build rule definition based on parameter set
        if ($PSCmdlet.ParameterSetName -eq 'Simple') {
            $ruleDefBody = @{
                conditionType    = "Operational"
                logicalOperator  = "AND"
                conditions       = @(
                    @{
                        conditionType = "Simple"
                        predicate     = @{
                            property = $Property
                            operator = $Operator
                            value    = @($Value)
                        }
                    }
                )
            }
        } else {
            $ruleDefBody = $RuleDefinition
        }

        # Build the complete request body
        $body = @{
            actions        = @(
                @{
                    actionType = "CriticalityLevel"
                    value      = $criticalityValue
                }
            )
            assetType      = $AssetType
            isDisabled     = [bool]$Disabled
            ruleDefinition = $ruleDefBody
            ruleDescription = $RuleDescription
            ruleId         = ""
            ruleName       = $RuleName
            ruleType       = "CreatedByUser"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/xspmatlas/assetrules"
        Write-Verbose "Creating new Critical Asset Management rule: $RuleName"
        Write-Verbose "Request body: $($body | ConvertTo-Json -Depth 10)"

        if (-not $PSCmdlet.ShouldProcess($RuleName, "Create Critical Asset Management rule")) {
            return
        }

        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 10) -WebSession $script:session -Headers $script:headers

            # Clear the rules cache since we've added a new rule
            Clear-XdrCache -CacheKey "XdrConfigurationCriticalAssetManagementClassification" -ErrorAction SilentlyContinue

            Write-Verbose "Successfully created rule with ID: $($result.ruleId)"

            if ($PassThru) {
                # Return the full rule object with all properties
                return Get-XdrConfigurationCriticalAssetManagementClassification -RuleId $result.ruleId -Force
            }
            return $result
        } catch {
            $errorMessage = $_.Exception.Message
            if ($_.ErrorDetails.Message) {
                $errorMessage = $_.ErrorDetails.Message
            }
            throw "Failed to create Critical Asset Management rule: $errorMessage"
        }
    }

    end {
    }
}
