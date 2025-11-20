function Get-XdrEndpointConfigurationCustomCollectionRule {
    <#
    .SYNOPSIS
        Retrieves custom collection rules for Microsoft Defender for Endpoint.

    .DESCRIPTION
        Gets the custom collection rules configured for Microsoft Defender for Endpoint.
        Custom collection rules allow you to collect specific file, registry, process, and network events
        based on defined criteria to support advanced hunting and detection scenarios.
        This function includes caching support with a 30-minute TTL to reduce API calls.

        It incorporates the same YAML schema as used by Telemetry Collection Manager
        https://github.com/FalconForceTeam/TelemetryCollectionManager
        for easy export and version control of custom collection rules.

    .PARAMETER Output
        Specifies the output format. Valid values are 'PSObject' (default) and 'YAML'.
        - PSObject: Returns PowerShell objects
        - YAML: Returns rules formatted as YAML text for easy export and version control

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointConfigurationCustomCollectionRule
        Retrieves all custom collection rules using cached data if available.

    .EXAMPLE
        Get-XdrEndpointConfigurationCustomCollectionRule -Force
        Forces a fresh retrieval of custom collection rules, bypassing the cache.

    .EXAMPLE
        Get-XdrEndpointConfigurationCustomCollectionRule | Where-Object { $_.isEnabled -eq $true }
        Retrieves only enabled custom collection rules.

    .EXAMPLE
        Get-XdrEndpointConfigurationCustomCollectionRule |
            Where-Object { $_.table -eq "DeviceFileEvents" } |
            Format-Table ruleName, actionType, platform, isEnabled -AutoSize
        Retrieves custom collection rules for file events and displays them in a table.

    .EXAMPLE
        $rules = Get-XdrEndpointConfigurationCustomCollectionRule
        $rules | Where-Object { $_.createdBy -eq "admin@contoso.com" }
        Retrieves all rules created by a specific user.

    .EXAMPLE
        Get-XdrEndpointConfigurationCustomCollectionRule |
            Select-Object ruleName, table, actionType, scope, isEnabled
        Retrieves custom collection rules and displays key properties.

    .EXAMPLE
        Get-XdrEndpointConfigurationCustomCollectionRule -Output YAML
        Retrieves custom collection rules in YAML format for export.
        YAML format is intended to use with https://github.com/FalconForceTeam/TelemetryCollectionManager

    .EXAMPLE
        Get-XdrEndpointConfigurationCustomCollectionRule -Output YAML | Out-File "rules.yaml"
        Exports all custom collection rules to a YAML file.

    .OUTPUTS
        Object[] or String
        When Output is 'PSObject' (default): Returns an array of custom collection rule objects.
        When Output is 'YAML': Returns a string containing YAML-formatted rules.
        When Output is 'PSObject' (default): Returns an array of custom collection rule objects containing:
        - ruleId: Unique identifier for the rule (GUID)
        - ruleName: Name of the collection rule
        - ruleDescription: Description of the rule
        - scope: Rule scope (e.g., "Organization")
        - isEnabled: Boolean indicating if the rule is active
        - table: Target table (e.g., DeviceFileEvents, DeviceNetworkEvents)
        - actionType: Event type to collect (e.g., FileDeleted, ConnectionSuccess)
        - createdBy: User who created the rule
        - creationDateTimeUtc: Creation timestamp
        - lastModifiedBy: User who last modified the rule
        - lastModificationDateTimeUtc: Last modification timestamp
        - platform: Target platform (e.g., Windows, Linux, macOS)
        - filters: Filter criteria for the collection rule
        - version: Rule version number
        - updateKey: Optimistic concurrency control key
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet('PSObject', 'YAML')]
        [string]$Output = 'PSObject',

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings

        # Check if ConvertTo-Yaml is available for YAML output
        if ($Output -eq 'YAML' -and -not (Get-Command ConvertTo-Yaml -ErrorAction SilentlyContinue)) {
            # Try to import powershell-yaml module
            if (-not (Get-Module -Name powershell-yaml -ListAvailable)) {
                throw "YAML output requires either PowerShell 7+ or the 'powershell-yaml' module. Install with: Install-Module -Name powershell-yaml"
            }
            Import-Module powershell-yaml -ErrorAction Stop
        }
    }

    process {
        try {
            $currentCacheValue = Get-XdrCache -CacheKey "XdrEndpointConfigurationCustomCollectionRule" -ErrorAction SilentlyContinue
        } catch {
            $currentCacheValue = $null
        }
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Endpoint custom collection rules"
            if ($Output -eq 'YAML') {
                Write-Verbose "Converting custom collection rules to YAML format"
                return ConvertTo-CustomCollectionYaml -Rules $currentCacheValue.Value
            } else {
                return $currentCacheValue.Value
            }
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrEndpointConfigurationCustomCollectionRule"
        } else {
            Write-Verbose "XDR Endpoint custom collection rules cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/mdeCustomCollection/rules"
        Write-Verbose "Retrieving XDR Endpoint custom collection rules"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        if ($null -eq $result) {
            $result = @()
        }

        Write-Verbose "Retrieved $($result.Count) custom collection rule(s)"

        Set-XdrCache -CacheKey "XdrEndpointConfigurationCustomCollectionRule" -Value $result -TTLMinutes 30

        # If YAML output is requested, convert to YAML format
        if ($Output -eq 'YAML') {
            Write-Verbose "Converting custom collection rules to YAML format"
            return ConvertTo-CustomCollectionYaml -Rules $result
        } else {
            return $result
        }
    }

    end {

    }
}

function ConvertTo-CustomCollectionYaml {
    <#
    .SYNOPSIS
        Converts custom collection rules to YAML format.

    .DESCRIPTION
        Internal helper function to convert rule objects to YAML format using ConvertTo-Yaml.

    .PARAMETER Rules
        Array of rule objects to convert.
    #>
    [OutputType([System.String])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Rules
    )

    if ($Rules.Count -eq 0) {
        return "# No custom collection rules found"
    }

    $yamlOutput = [System.Text.StringBuilder]::new()

    foreach ($rule in $Rules) {
        # Add rule header with separator
        if ($yamlOutput.Length -gt 0) {
            [void]$yamlOutput.AppendLine("---")
        }

        # Prepare rule object for YAML conversion (exclude metadata, only keep schema fields)
        $yamlRule = [ordered]@{
            name       = $rule.ruleName
            enabled    = $rule.isEnabled
            platform   = $rule.platform
            scope      = $rule.scope
            table      = $rule.table
            actionType = $rule.actionType
        }

        # Add description if present
        if (-not [string]::IsNullOrWhiteSpace($rule.ruleDescription)) {
            $yamlRule.Insert(1, 'description', $rule.ruleDescription)
        }

        # Convert filters to simplified format (remove expressionType properties)
        $yamlRule.filters = ConvertTo-YamlFilterFormat -Expression $rule.filters

        # Convert to YAML
        $ruleYaml = ConvertTo-Yaml -Data $yamlRule
        [void]$yamlOutput.Append($ruleYaml)

        # Add metadata as comments
        [void]$yamlOutput.AppendLine("# Metadata:")
        [void]$yamlOutput.AppendLine("# ruleId: $($rule.ruleId)")
        [void]$yamlOutput.AppendLine("# createdBy: $($rule.createdBy)")
        [void]$yamlOutput.AppendLine("# creationDateTimeUtc: $($rule.creationDateTimeUtc)")
        [void]$yamlOutput.AppendLine("# lastModifiedBy: $($rule.lastModifiedBy)")
        [void]$yamlOutput.AppendLine("# lastModificationDateTimeUtc: $($rule.lastModificationDateTimeUtc)")
        [void]$yamlOutput.AppendLine("# version: $($rule.version)")
    }

    return $yamlOutput.ToString()
}

function ConvertTo-YamlFilterFormat {
    <#
    .SYNOPSIS
        Converts API filter format to simplified YAML format.

    .DESCRIPTION
        Removes expressionType properties and simplifies the filter structure for YAML export.

    .PARAMETER Expression
        The filter expression object to convert.
    #>
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Expression
    )

    $result = [ordered]@{
        operator    = $Expression.operator
        expressions = @()
    }

    foreach ($expr in $Expression.expressions) {
        if ($expr.expressionType -eq "Predicate") {
            # Predicate expression - remove expressionType
            $result.expressions += [ordered]@{
                source = $expr.source
                filter = $expr.filter
                values = $expr.values
            }
        } elseif ($expr.expressionType -eq "Nested") {
            # Nested group - recurse and wrap in group key
            $result.expressions += [ordered]@{
                group = ConvertTo-YamlFilterFormat -Expression $expr
            }
        }
    }

    return $result
}
