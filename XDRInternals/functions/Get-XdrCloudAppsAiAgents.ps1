function Get-XdrCloudAppsAiAgents {
    <#
    .SYNOPSIS
        Retrieves AI agent data from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Gets AI agent information from Microsoft Defender for Cloud Apps including agent inventory, counts by
        platform, discovery timeline, and schema definitions. By default, returns agent inventory data
        transformed into PowerShell objects.

        The cmdlet uses schemaId "all_agents" internally. If additional schema identifiers are discovered in
        the future, this may be exposed as a parameter.

        Data is automatically transformed from the API's grid/table format (columns/rows) into proper
        PowerShell objects for easier manipulation. Use -Raw to get the untransformed API response including
        paging metadata.

        Pagination is designed to be automatic (fetching all pages transparently), but is not yet implemented
        due to lack of testable data with continuation tokens.

    .PARAMETER CountByPlatform
        Returns agent counts grouped by platform.

    .PARAMETER DiscoveredOvertime
        Returns timeline of agent discovery over time.

    .PARAMETER Schema
        Returns the schema definition for AI agents including column definitions and filter options.

    .PARAMETER All
        Returns all available data: Agent inventory, CountByPlatform metrics, DiscoveredOvertime timeline,
        and Schema definition. When used, queries all platforms regardless of -Platforms parameter.

    .PARAMETER Platforms
        Array of platforms to include in the results. Supports tab completion.
        Valid values: azureFoundry, copilotStudio, awsBedrock, gcpVertex
        Default: All four platforms

    .PARAMETER Columns
        Array of column names to include in agent inventory results. If not specified, default columns
        will be returned. Use -Schema switch to discover available columns.
        Only applies to agent inventory (default behavior, not switches).

    .PARAMETER Filters
        Array of filter objects to apply to agent inventory queries. Each filter should contain the column
        name, operator, and value(s) to filter by.
        Only applies to agent inventory (default behavior, not switches).

    .PARAMETER PageSize
        Number of results to return per page. Default is 50. Valid range is 1 to 1000.
        Note: Automatic pagination (fetching all pages) is planned but not yet implemented.

    .PARAMETER DaysAgo
        Time range for discovery timeline data. Default is 60d.
        Valid values: 7d, 14d, 30d, 60d, 90d
        Only applies to -DiscoveredOvertime switch.

    .PARAMETER Raw
        Returns untransformed API responses including paging metadata and original structure.
        By default, responses are transformed from grid format (columns/rows) to PowerShell objects.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrCloudAppsAiAgent
        Retrieves AI agents from all platforms, returning transformed PowerShell objects.

    .EXAMPLE
        Get-XdrCloudAppsAiAgent -Platforms azureFoundry, copilotStudio
        Retrieves AI agents from Azure Foundry and Copilot Studio only.

    .EXAMPLE
        Get-XdrCloudAppsAiAgent -CountByPlatform
        Retrieves agent counts grouped by platform.

    .EXAMPLE
        Get-XdrCloudAppsAiAgent -DiscoveredOvertime -DaysAgo 30d
        Retrieves agent discovery timeline for the last 30 days.

    .EXAMPLE
        Get-XdrCloudAppsAiAgent -Schema
        Retrieves the schema definition showing available columns and filters.

    .EXAMPLE
        Get-XdrCloudAppsAiAgent -All
        Retrieves all data types (Agent, CountByPlatform, DiscoveredOvertime, Schema) from all platforms.

    .EXAMPLE
        Get-XdrCloudAppsAiAgent -Raw
        Retrieves agent data in raw API format including paging information.

    .EXAMPLE
        Get-XdrCloudAppsAiAgent -Columns @("agentName", "platform", "status", "agentCreationTime")
        Retrieves agents with only the specified columns.

    .EXAMPLE
        Get-XdrCloudAppsAiAgent -PageSize 100 -Verbose
        Retrieves up to 100 agents with verbose output showing cache and API activity.

    .OUTPUTS
        By default (no switches): XdrCloudAppsAiAgent[] - Array of transformed agent objects
        -CountByPlatform: XdrCloudAppsAiAgentCountByPlatform - Platform count metrics
        -DiscoveredOvertime: XdrCloudAppsAiAgentDiscoveredOvertime - Discovery timeline data
        -Schema: XdrCloudAppsAiAgentSchema - Schema definition (not transformed)
        -All: PSCustomObject with Agent, CountByPlatform, DiscoveredOvertime, and Schema properties
        -Raw: Returns untransformed API responses with original structure
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'This cmdlet retrieves multiple agents, plural is appropriate')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Raw', Justification = 'Used in conditional transformation logic')]
    param (
        [Parameter()]
        [switch]$CountByPlatform,

        [Parameter()]
        [switch]$DiscoveredOvertime,

        [Parameter()]
        [switch]$Schema,

        [Parameter()]
        [switch]$All,

        [Parameter()]
        [ValidateSet("azureFoundry", "copilotStudio", "awsBedrock", "gcpVertex")]
        [string[]]$Platforms = @("azureFoundry", "copilotStudio", "awsBedrock", "gcpVertex"),

        [Parameter()]
        [string[]]$Columns,

        [Parameter()]
        [array]$Filters,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$PageSize = 50,

        [Parameter()]
        [ValidateSet("7d", "14d", "30d", "60d", "90d")]
        [string]$DaysAgo = "60d",

        [Parameter()]
        [switch]$Raw,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings

        # Helper function to get data with caching and transformation
        function Get-AiAgentData {
            param(
                [string]$CacheKey,
                [string]$Uri,
                [string]$Description,
                [hashtable]$Body,
                [string]$TypeName,
                [bool]$ForceRefresh,
                [bool]$ReturnRaw,
                [bool]$SkipTransform = $false,
                [int]$TTLMinutes = 5
            )

            if (-not $ForceRefresh) {
                $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                    Write-Verbose "Using cached $Description"
                    $result = $cache.Value

                    # Apply transformation if not raw and not skipping
                    if (-not $ReturnRaw -and -not $SkipTransform) {
                        $result = ConvertFrom-XdrCloudAppsResponse -InputObject $result -TypeName $TypeName
                    } elseif ($TypeName -and $result.PSObject.TypeNames[0] -ne $TypeName) {
                        $result.PSObject.TypeNames.Insert(0, $TypeName)
                    }

                    return $result
                }
            }

            Write-Verbose "Retrieving $Description from API"

            try {
                $bodyJson = $Body | ConvertTo-Json -Compress -Depth 10
                $response = Invoke-RestMethod -Uri $Uri -Method Post -Body $bodyJson -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                $rawResult = if ($null -ne $response.data) { $response.data } else { $response }

                if ($null -ne $rawResult) {
                    # Cache the raw result
                    Set-XdrCache -CacheKey $CacheKey -Value $rawResult -TTLMinutes $TTLMinutes

                    # Return raw or transformed based on parameter
                    if ($ReturnRaw) {
                        if ($TypeName) {
                            $rawResult.PSObject.TypeNames.Insert(0, $TypeName)
                        }
                        return $rawResult
                    } elseif (-not $SkipTransform) {
                        return ConvertFrom-XdrCloudAppsResponse -InputObject $rawResult -TypeName $TypeName
                    } else {
                        if ($TypeName) {
                            $rawResult.PSObject.TypeNames.Insert(0, $TypeName)
                        }
                        return $rawResult
                    }
                }

                return $null
            } catch {
                Write-Error "Failed to retrieve ${Description}: $_"
                return $null
            }
        }
    }

    process {
        # Convert Platforms array to comma-separated string for API
        # When -All is used, always query all platforms
        $platformString = if ($All) {
            "azureFoundry,copilotStudio,awsBedrock,gcpVertex"
        } else {
            $Platforms -join ','
        }

        # Count how many switches are specified
        $switchCount = 0
        if ($CountByPlatform) { $switchCount++ }
        if ($DiscoveredOvertime) { $switchCount++ }
        if ($Schema) { $switchCount++ }

        # If -All or multiple switches, return combined object
        if ($All -or $switchCount -gt 1) {
            $results = [ordered]@{}

            # Agent inventory (for -All or when no specific switch is selected)
            if ($All -or ($switchCount -eq 0)) {
                $CacheKey = "XdrCloudAppsAiAgent-$platformString-all_agents-$PageSize"
                $useCache = ($null -eq $Columns -or $Columns.Count -eq 0) -and ($null -eq $Filters -or $Filters.Count -eq 0)

                $cachedAgent = $null
                if (-not $Force -and $useCache) {
                    $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
                    if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                        Write-Verbose "Using cached Cloud Apps AI agents"
                        $cachedAgent = $cache.Value
                    }
                }

                if ($cachedAgent) {
                    $results['Agent'] = if ($Raw) { $cachedAgent } else {
                        ConvertFrom-XdrCloudAppsResponse -InputObject $cachedAgent -TypeName 'XdrCloudAppsAiAgent'
                    }
                } else {
                    Write-Verbose "Retrieving Cloud Apps AI agents (Platforms: $platformString, PageSize: $PageSize)"
                    $agentBody = @{
                        schemaId = "all_agents"
                        schemaParameters = @{ platforms = $platformString }
                        paging = @{ pageSize = $PageSize }
                    }
                    if ($null -ne $Columns -and $Columns.Count -gt 0) { $agentBody.columns = $Columns }
                    if ($null -ne $Filters -and $Filters.Count -gt 0) { $agentBody.filters = $Filters }

                    $results['Agent'] = Get-AiAgentData `
                        -CacheKey $CacheKey `
                        -Uri "https://security.microsoft.com/apiproxy/mdc/views/inventory/ai-agents-v3/items" `
                        -Description "Cloud Apps AI agents" `
                        -Body $agentBody `
                        -TypeName 'XdrCloudAppsAiAgent' `
                        -ForceRefresh $Force `
                        -ReturnRaw $Raw
                }
            }

            if ($All -or $CountByPlatform) {
                $results['CountByPlatform'] = Get-AiAgentData `
                    -CacheKey "XdrCloudAppsAiAgentCountByPlatform-$platformString" `
                    -Uri "https://security.microsoft.com/apiproxy/mdc/views/inventory/ai-agents-v3/agents-current-count-by-platform-metrics" `
                    -Description "Cloud Apps AI agent count by platform" `
                    -Body @{
                        paging = @{ continuationToken = $null; pageSize = 100 }
                        platforms = $platformString
                    } `
                    -TypeName 'XdrCloudAppsAiAgentCountByPlatform' `
                    -ForceRefresh $Force `
                    -ReturnRaw $Raw
            }

            if ($All -or $DiscoveredOvertime) {
                $results['DiscoveredOvertime'] = Get-AiAgentData `
                    -CacheKey "XdrCloudAppsAiAgentDiscoveredOvertime-$platformString-$DaysAgo" `
                    -Uri "https://security.microsoft.com/apiproxy/mdc/views/inventory/ai-agents-v3/agents-discovered-overtime" `
                    -Description "Cloud Apps AI agent discovered overtime" `
                    -Body @{
                        daysAgo = $DaysAgo
                        paging = @{ continuationToken = $null; pageSize = 100 }
                        platforms = $platformString
                    } `
                    -TypeName 'XdrCloudAppsAiAgentDiscoveredOvertime' `
                    -ForceRefresh $Force `
                    -ReturnRaw $Raw
            }

            if ($All -or $Schema) {
                $results['Schema'] = Get-AiAgentData `
                    -CacheKey "XdrCloudAppsAiAgentSchema-all_agents" `
                    -Uri "https://security.microsoft.com/apiproxy/mdc/views/inventory/ai-agents-v3/schema" `
                    -Description "Cloud Apps AI agent schema" `
                    -Body @{ schemaId = "all_agents" } `
                    -TypeName 'XdrCloudAppsAiAgentSchema' `
                    -ForceRefresh $Force `
                    -ReturnRaw $Raw `
                    -SkipTransform $true
            }

            return [PSCustomObject]$results
        }

        # Single switch - return that data directly
        if ($CountByPlatform) {
            return Get-AiAgentData `
                -CacheKey "XdrCloudAppsAiAgentCountByPlatform-$platformString" `
                -Uri "https://security.microsoft.com/apiproxy/mdc/views/inventory/ai-agents-v3/agents-current-count-by-platform-metrics" `
                -Description "Cloud Apps AI agent count by platform" `
                -Body @{
                    paging = @{ continuationToken = $null; pageSize = 100 }
                    platforms = $platformString
                } `
                -TypeName 'XdrCloudAppsAiAgentCountByPlatform' `
                -ForceRefresh $Force `
                -ReturnRaw $Raw
        }

        if ($DiscoveredOvertime) {
            return Get-AiAgentData `
                -CacheKey "XdrCloudAppsAiAgentDiscoveredOvertime-$platformString-$DaysAgo" `
                -Uri "https://security.microsoft.com/apiproxy/mdc/views/inventory/ai-agents-v3/agents-discovered-overtime" `
                -Description "Cloud Apps AI agent discovered overtime" `
                -Body @{
                    daysAgo = $DaysAgo
                    paging = @{ continuationToken = $null; pageSize = 100 }
                    platforms = $platformString
                } `
                -TypeName 'XdrCloudAppsAiAgentDiscoveredOvertime' `
                -ForceRefresh $Force `
                -ReturnRaw $Raw
        }

        if ($Schema) {
            return Get-AiAgentData `
                -CacheKey "XdrCloudAppsAiAgentSchema-all_agents" `
                -Uri "https://security.microsoft.com/apiproxy/mdc/views/inventory/ai-agents-v3/schema" `
                -Description "Cloud Apps AI agent schema" `
                -Body @{ schemaId = "all_agents" } `
                -TypeName 'XdrCloudAppsAiAgentSchema' `
                -ForceRefresh $Force `
                -ReturnRaw $Raw `
                -SkipTransform $true
        }

        # Default: Agent inventory
        $CacheKey = "XdrCloudAppsAiAgent-$platformString-all_agents-$PageSize"
        $useCache = ($null -eq $Columns -or $Columns.Count -eq 0) -and ($null -eq $Filters -or $Filters.Count -eq 0)

        if (-not $Force -and $useCache) {
            $cache = Get-XdrCache -CacheKey $CacheKey -ErrorAction SilentlyContinue
            if ($cache -and $cache.NotValidAfter -gt (Get-Date)) {
                Write-Verbose "Using cached Cloud Apps AI agents"
                $result = $cache.Value

                if ($Raw) {
                    if ($result.PSObject.TypeNames[0] -ne 'XdrCloudAppsAiAgent') {
                        $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsAiAgent')
                    }
                    return $result
                }

                return ConvertFrom-XdrCloudAppsResponse -InputObject $result -TypeName 'XdrCloudAppsAiAgent'
            }
        }

        if ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey $CacheKey
        } else {
            Write-Verbose "Cloud Apps AI agents cache is missing or expired"
        }

        Write-Verbose "Retrieving Cloud Apps AI agents (Platforms: $platformString, PageSize: $PageSize)"

        $agentBody = @{
            schemaId = "all_agents"
            schemaParameters = @{ platforms = $platformString }
            paging = @{ pageSize = $PageSize }
        }
        if ($null -ne $Columns -and $Columns.Count -gt 0) { $agentBody.columns = $Columns }
        if ($null -ne $Filters -and $Filters.Count -gt 0) { $agentBody.filters = $Filters }

        return Get-AiAgentData `
            -CacheKey $CacheKey `
            -Uri "https://security.microsoft.com/apiproxy/mdc/views/inventory/ai-agents-v3/items" `
            -Description "Cloud Apps AI agents" `
            -Body $agentBody `
            -TypeName 'XdrCloudAppsAiAgent' `
            -ForceRefresh $Force `
            -ReturnRaw $Raw
    }

    end {
    }
}
