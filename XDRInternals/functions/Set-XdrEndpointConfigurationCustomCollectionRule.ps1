function Set-XdrEndpointConfigurationCustomCollectionRule {
    <#
    .SYNOPSIS
        Updates an existing custom collection rule for Microsoft Defender for Endpoint.

    .DESCRIPTION
        Updates custom collection rules for Microsoft Defender for Endpoint by importing YAML files or PSObjects.
        The YAML files should follow the schema format used by Get-XdrEndpointConfigurationCustomCollectionRule.
        Each rule is validated before submission to ensure proper schema structure and that the rule exists.

        More information about the schema can be found here: https://github.com/FalconForceTeam/TelemetryCollectionManager

    .PARAMETER FilePath
        Path to one or more YAML files containing custom collection rule definitions.
        Supports wildcards for batch processing.
        When using YAML files, the RuleId parameter must be provided.

    .PARAMETER RuleId
        The GUID of the rule to update. Required when using FilePath parameter.
        This ensures you're updating the correct rule when using YAML files.

    .PARAMETER InputObject
        PSObject containing the rule to update. The object must include a ruleId property.
        Typically obtained from Get-XdrEndpointConfigurationCustomCollectionRule.

    .PARAMETER BypassCache
        Bypasses any existing cache entries when updating the rule.
        Will slow down processing if multiple rules are updated in succession.

    .PARAMETER Confirm
        Prompts for confirmation before creating each rule.

    .PARAMETER WhatIf
    Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        Set-XdrEndpointConfigurationCustomCollectionRule -FilePath "C:\Rules\FileMonitoring.yaml" -RuleId "12345678-1234-1234-1234-123456789012"
        Updates a single custom collection rule from the specified YAML file.

    .EXAMPLE
        Set-XdrEndpointConfigurationCustomCollectionRule -FilePath "C:\Rules\*.yaml" -RuleId "12345678-1234-1234-1234-123456789012"
        Updates custom collection rules from all YAML files in the specified directory.

    .EXAMPLE
        Get-XdrEndpointConfigurationCustomCollectionRule |
            Where-Object { $_.ruleName -eq "My Rule" } |
            Set-XdrEndpointConfigurationCustomCollectionRule
        Updates a rule by passing a PSObject from Get cmdlet through the pipeline.

    .EXAMPLE
        $rule = Get-XdrEndpointConfigurationCustomCollectionRule | Where-Object { $_.ruleName -eq "My Rule" }
        $rule.isEnabled = $false
        Set-XdrEndpointConfigurationCustomCollectionRule -InputObject $rule
        Gets a rule, modifies it, and updates it.

    .OUTPUTS
        Object
        Returns the updated custom collection rule object(s) from the API.

    .NOTES
        Required YAML properties:
        - name: Rule name (string)
        - enabled: Rule enabled status (boolean)
        - platform: Target platform (Windows, Linux, macOS)
        - scope: Rule scope (Organization)
        - table: Target table (DeviceFileEvents, DeviceNetworkEvents, etc.)
        - actionType: Event type to collect
        - filters: Filter expressions object

        Optional YAML properties:
        - description: Rule description (string)

        When using InputObject, the following API properties are required:
        - ruleId: The rule identifier (GUID)
        - ruleName, isEnabled, platform, scope, table, actionType, filters
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding(DefaultParameterSetName = 'PSObject', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'YAML', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName', 'Path')]
        [string[]]$FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'YAML')]
        [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
        [string]$RuleId,

        [Parameter(Mandatory = $true, ParameterSetName = 'PSObject', ValueFromPipeline = $true)]
        [object]$InputObject,

        [switch]$BypassCache
    )

    begin {
        Update-XdrConnectionSettings

        # Check if ConvertFrom-Yaml is available when using YAML parameter set
        if ($PSCmdlet.ParameterSetName -eq 'YAML' -and -not (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue)) {
            # Try to import powershell-yaml module for PowerShell 5.1
            if (-not (Get-Module -Name powershell-yaml -ListAvailable)) {
                throw "YAML parsing requires either PowerShell 7+ or the 'powershell-yaml' module. Install with: Install-Module -Name powershell-yaml"
            }
            Import-Module powershell-yaml -ErrorAction Stop
        }

        # Get current user for lastModifiedBy field
        $tenantContext = Get-XdrTenantContext -ErrorAction Stop -Force:$BypassCache
        $lastModifiedBy = $tenantContext.AuthInfo.UserName
        if (-not $lastModifiedBy) {
            throw "Unable to determine current user principal name from tenant context"
        }

        # Get all existing rules for validation
        $existingRules = Get-XdrEndpointConfigurationCustomCollectionRule -Force:$BypassCache -ErrorAction Stop
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'YAML') {
            # Process YAML files
            foreach ($file in $FilePath) {
                # Resolve wildcards and get actual file paths
                $resolvedPaths = Resolve-Path -Path $file -ErrorAction SilentlyContinue

                if (-not $resolvedPaths) {
                    Write-Error "File not found: $file"
                    continue
                }

                foreach ($resolvedPath in $resolvedPaths) {
                    try {
                        Write-Verbose "Processing file: $($resolvedPath.Path)"

                        # Read YAML content
                        $yamlContent = Get-Content -Path $resolvedPath.Path -Raw -ErrorAction Stop

                        # Parse YAML using ConvertFrom-Yaml
                        $rule = ConvertFrom-Yaml -Yaml $yamlContent -ErrorAction Stop

                        # Validate required properties
                        $requiredProps = @('name', 'enabled', 'platform', 'scope', 'table', 'actionType', 'filters')
                        foreach ($prop in $requiredProps) {
                            if ($rule.GetEnumerator().Name -notcontains $prop) {
                                throw "Missing required property: $prop"
                            }
                        }

                        # Verify the rule exists
                        $existingRule = $existingRules | Where-Object { $_.ruleId -eq $RuleId }
                        if (-not $existingRule) {
                            throw "No custom collection rule found with ruleId '$RuleId'. Use New-XdrEndpointConfigurationCustomCollectionRule to create a new rule."
                        }

                        # Build API request body
                        $body = @{
                            ruleId              = $RuleId
                            ruleName            = $rule.name
                            ruleDescription     = if ($rule.description) { $rule.description } else { "" }
                            isEnabled           = $rule.enabled
                            table               = $rule.table
                            platform            = $rule.platform
                            actionType          = $rule.actionType
                            scope               = $rule.scope
                            filters             = ConvertTo-ApiFilterFormat -Filters $rule.filters
                            tags                = $existingRule.tags
                            createdBy           = $existingRule.createdBy
                            creationDateTimeUtc = $existingRule.creationDateTimeUtc
                            lastModifiedBy      = $lastModifiedBy
                            version             = [int]$existingRule.version
                            updateKey           = $existingRule.updateKey
                        } | ConvertTo-Json -Depth 20

                        $Uri = "https://security.microsoft.com/apiproxy/mtp/mdeCustomCollection/rules/$($RuleId)"

                        # If WhatIf is specified, output the JSON body
                        if ($WhatIfPreference) {
                            Write-Host "Uri: $Uri"
                            Write-Host "JSON Body for rule '$($rule.name)' (ID: $RuleId):"
                            Write-Host $body
                            continue
                        }

                        if ($PSCmdlet.ShouldProcess("$($rule.name) (ID: $RuleId)", "Update custom collection rule")) {
                            Write-Verbose "Updating custom collection rule: $($rule.name) (ID: $RuleId)"

                            $result = Invoke-RestMethod -Uri $Uri -Method Put -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

                            # Clear the cache for the Get cmdlet
                            Clear-XdrCache -CacheKey "XdrEndpointConfigurationCustomCollectionRule" -ErrorAction SilentlyContinue

                            Write-Verbose "Successfully updated rule with ID: $($result.ruleId)"
                            Write-Host $result
                        }
                    } catch {
                        Write-Error "Failed to update custom collection rule from file '$($resolvedPath.Path)': $($_.Exception.Message)"
                    }
                }
            }
        } else {
            # Process PSObject
            try {
                # Validate that InputObject has ruleId
                if (-not $InputObject.ruleId) {
                    throw "InputObject must contain a 'ruleId' property. Ensure you're passing an object from Get-XdrEndpointConfigurationCustomCollectionRule."
                }

                # Verify the rule exists
                $existingRule = $existingRules | Where-Object { $_.ruleId -eq $InputObject.ruleId }
                if (-not $existingRule) {
                    throw "No custom collection rule found with ruleId '$($InputObject.ruleId)'. Use New-XdrEndpointConfigurationCustomCollectionRule to create a new rule."
                }

                # Validate required properties
                $requiredProps = @('ruleName', 'isEnabled', 'platform', 'scope', 'table', 'actionType', 'filters')
                foreach ($prop in $requiredProps) {
                    if (-not $InputObject.PSObject.Properties[$prop]) {
                        throw "Missing required property: $prop"
                    }
                }

                # Build API request body
                $body = @{
                    ruleId              = $InputObject.ruleId
                    ruleName            = $InputObject.ruleName
                    ruleDescription     = if ($InputObject.ruleDescription) { $InputObject.ruleDescription } else { "" }
                    isEnabled           = $InputObject.isEnabled
                    table               = $InputObject.table
                    platform            = $InputObject.platform
                    actionType          = $InputObject.actionType
                    scope               = $InputObject.scope
                    filters             = $InputObject.filters
                    tags                = $InputObject.tags
                    createdBy           = $existingRule.createdBy
                    creationDateTimeUtc = $existingRule.creationDateTimeUtc
                    lastModifiedBy      = $lastModifiedBy
                    version             = [int]$existingRule.version
                    updateKey           = $existingRule.updateKey
                } | ConvertTo-Json -Depth 20

                $Uri = "https://security.microsoft.com/apiproxy/mtp/mdeCustomCollection/rules/$($InputObject.ruleId)"

                # If WhatIf is specified, output the JSON body
                if ($WhatIfPreference) {
                    Write-Host "Uri: $Uri"
                    Write-Host "JSON Body for rule '$($InputObject.ruleName)' (ID: $($InputObject.ruleId)):"
                    Write-Host $body
                    return
                }

                if ($PSCmdlet.ShouldProcess("$($InputObject.ruleName) (ID: $($InputObject.ruleId))", "Update custom collection rule")) {
                    Write-Verbose "Updating custom collection rule: $($InputObject.ruleName) (ID: $($InputObject.ruleId))"

                    $result = Invoke-RestMethod -Uri $Uri -Method Put -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

                    # Clear the cache for the Get cmdlet
                    Clear-XdrCache -CacheKey "XdrEndpointConfigurationCustomCollectionRule" -ErrorAction SilentlyContinue

                    Write-Verbose "Successfully updated rule with ID: $($result.ruleId)"
                    Write-Host $result
                }
            } catch {
                Write-Error "Failed to update custom collection rule '$($InputObject.ruleName)': $($_.Exception.Message)"
            }
        }
    }

    end {

    }
}
