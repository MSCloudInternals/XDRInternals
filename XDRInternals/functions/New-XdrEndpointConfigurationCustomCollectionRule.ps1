function New-XdrEndpointConfigurationCustomCollectionRule {
    <#
    .SYNOPSIS
        Creates a new custom collection rule for Microsoft Defender for Endpoint from a YAML file.

    .DESCRIPTION
        Creates custom collection rules for Microsoft Defender for Endpoint by importing YAML files.
        The YAML files should follow the schema format used by Get-XdrEndpointConfigurationCustomCollectionRule.
        Each file is validated before submission to ensure proper schema structure.

        More information about the schema can be found here: https://github.com/FalconForceTeam/TelemetryCollectionManager

    .PARAMETER FilePath
        Path to one or more YAML files containing custom collection rule definitions.
        Supports wildcards for batch processing.

    .PARAMETER Enabled
        Specifies whether the created rule(s) should be enabled. Default is $false.

    .PARAMETER BypassCache
        Bypasses any existing cache entries when creating the rule.
        Will slow down processing if multiple rules are created in succession.

    .PARAMETER Confirm
        Prompts for confirmation before creating each rule.

    .PARAMETER WhatIf
    Shows what would happen if the cmdlet runs. The cmdlet is not run.

    .EXAMPLE
        New-XdrEndpointConfigurationCustomCollectionRule -FilePath "C:\Rules\FileMonitoring.yaml"
        Creates a single custom collection rule from the specified YAML file.

    .EXAMPLE
        New-XdrEndpointConfigurationCustomCollectionRule -FilePath "C:\Rules\*.yaml"
        Creates custom collection rules from all YAML files in the specified directory.

    .EXAMPLE
        Get-ChildItem "C:\Rules" -Filter "*.yaml" |
            New-XdrEndpointConfigurationCustomCollectionRule
        Creates custom collection rules from all YAML files using pipeline input.

    .OUTPUTS
        Object
        Returns the created custom collection rule object(s) from the API.

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
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName', 'Path')]
        [string[]]$FilePath,

        [Parameter()]
        [bool]$Enabled = $false,

        [switch]$BypassCache
    )

    begin {
        Update-XdrConnectionSettings

        # Check if ConvertFrom-Yaml is available (PowerShell 7+)
        if (-not (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue)) {
            # Try to import powershell-yaml module for PowerShell 5.1
            if (-not (Get-Module -Name powershell-yaml -ListAvailable)) {
                throw "YAML parsing requires either PowerShell 7+ or the 'powershell-yaml' module. Install with: Install-Module -Name powershell-yaml"
            }
            Import-Module powershell-yaml -ErrorAction Stop
        }

        # Get current user for createdBy field
        $tenantContext = Get-XdrTenantContext -ErrorAction Stop -Force:$BypassCache
        $createdBy = $tenantContext.AuthInfo.UserName
        if (-not $createdBy) {
            throw "Unable to determine current user principal name from tenant context"
        }
    }

    process {
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
                    $requiredProps = @('name', 'platform', 'scope', 'table', 'actionType', 'filters')
                    foreach ($prop in $requiredProps) {
                        if ($rule.GetEnumerator().Name -notcontains $prop) {
                            throw "Missing required property: $prop"
                        }
                    }

                    # Check if there is a rule with the same name already existing
                    $existingRules = Get-XdrEndpointConfigurationCustomCollectionRule
                    if ($existingRules.RuleName -contains $rule.name) {
                        throw "A custom collection rule with the name '$($rule.name)' already exists. Choose a different name."
                    }

                    # Build API request body
                    $body = @{
                        ruleName        = $rule.name
                        ruleDescription = if ($rule.description) { $rule.description } else { "" }
                        isEnabled       = $Enabled
                        table           = $rule.table
                        platform        = $rule.platform
                        actionType      = $rule.actionType
                        scope           = $rule.scope
                        filters         = ConvertTo-ApiFilterFormat -Filters $rule.filters
                        tags            = $null
                        createdBy       = $createdBy
                    } | ConvertTo-Json -Depth 20

                    $Uri = "https://security.microsoft.com/apiproxy/mtp/mdeCustomCollection/rules"

                    # If WhatIf is specified, output the JSON body
                    if ($WhatIfPreference) {
                        Write-Host "JSON Body for rule '$($rule.name)':"
                        Write-Host $body
                        continue
                    }

                    if ($PSCmdlet.ShouldProcess($rule.name, "Create custom collection rule")) {
                        Write-Verbose "Creating custom collection rule: $($rule.name)"

                        $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

                        # Clear the cache for the Get cmdlet
                        Clear-XdrCache -CacheKey "XdrEndpointConfigurationCustomCollectionRule" -ErrorAction SilentlyContinue

                        Write-Verbose "Successfully created rule with ID: $($result.ruleId)"
                        Write-Host $result
                    }
                } catch {
                    Write-Error "Failed to create custom collection rule from file '$($resolvedPath.Path)': $($_.Exception.Message)"
                }
            }
        }
    }

    end {

    }
}
