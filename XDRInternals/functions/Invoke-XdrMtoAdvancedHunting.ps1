function Invoke-XdrMtoAdvancedHunting {
    <#
    .SYNOPSIS
        Executes an Advanced Hunting query across multiple tenants in MTO (Multi-Tenant Organization).

    .DESCRIPTION
        Runs a KQL (Kusto Query Language) Advanced Hunting query across one or more tenants
        in the Microsoft Defender XDR multi-tenant view. Supports querying across tenants
        with configurable time ranges and optional workspace selection.

    .PARAMETER QueryText
        The KQL query to execute. This is a required parameter.

    .PARAMETER TenantIds
        Array of tenant IDs (GUIDs) to query. If not provided, uses the tenant ID from the cache
        (the currently selected tenant in MTO view).

    .PARAMETER DaysAgo
        Number of days to look back from now for the query time range. Default is 7 days.
        Cannot be used with -StartTime or -MinutesAgo parameters.

    .PARAMETER MinutesAgo
        Number of minutes to look back from now for the query time range.
        Cannot be used with -StartTime or -DaysAgo parameters.

    .PARAMETER StartTime
        Custom start time for the query (DateTime object or string in ISO 8601 format).
        Cannot be used with -DaysAgo or -MinutesAgo parameters.

    .PARAMETER EndTime
        End time for the query (DateTime object or string in ISO 8601 format).
        Default is the current time.

    .PARAMETER MaxRecordCount
        Maximum number of records to return. If not specified, the API default is used.

    .PARAMETER SelectedWorkspaces
        Hashtable mapping tenant IDs to arrays of workspace IDs for querying specific workspaces.
        Example: @{ "tenantId1" = @("workspaceId1", "workspaceId2"); "tenantId2" = @("workspaceId3") }

    .EXAMPLE
        Invoke-XdrMtoAdvancedHunting -QueryText "DeviceEvents | limit 10"
        Executes a simple query across the current tenant for the last 7 days.

    .EXAMPLE
        Invoke-XdrMtoAdvancedHunting -QueryText "DeviceEvents | limit 10" -DaysAgo 30
        Executes a query across the current tenant for the last 30 days.

    .EXAMPLE
        Invoke-XdrMtoAdvancedHunting -QueryText "DeviceEvents | limit 10" -MinutesAgo 60
        Executes a query for the last 60 minutes.

    .EXAMPLE
        $tenants = @("e3686c4f-af27-4f22-b9de-062f05b93aac", "48315f62-774c-49c9-884b-34a8931b2b1f")
        Invoke-XdrMtoAdvancedHunting -QueryText "DeviceInfo | take 5" -TenantIds $tenants
        Executes a query across multiple specified tenants.

    .EXAMPLE
        $query = @"
        DeviceProcessEvents
        | where Timestamp > ago(1h)
        | where FileName =~ "powershell.exe"
        | take 100
        "@
        Invoke-XdrMtoAdvancedHunting -QueryText $query -DaysAgo 1 -Verbose
        Executes a multi-line query with verbose output showing per-tenant latency.

    .EXAMPLE
        $workspaces = @{
            "e3686c4f-af27-4f22-b9de-062f05b93aac" = @("008e3d12-e648-46e1-83ec-f631d94bf434")
        }
        Invoke-XdrMtoAdvancedHunting -QueryText "DeviceEvents | limit 10" -SelectedWorkspaces $workspaces
        Executes a query with specific workspace selection.

    .OUTPUTS
        PSCustomObject
        Returns a custom object containing:
        - Schema: Array of column definitions with Name, Type, and Entity properties
        - Results: Array of result objects containing the query results
        - Quota: Array of quota information per tenant
        - ChartVisualization: Array of chart type information per tenant

    .NOTES
        This cmdlet requires an active MTO session established via Connect-Xdr.
        Warnings are generated for any tenant that returns an error.
        Verbose output includes per-tenant latency information.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseLiteralInitializerForHashtable', '', Justification = 'PSUseLiteralInitializerForHashtable')]
    [CmdletBinding(DefaultParameterSetName = 'DaysAgo')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$QueryText,

        [Alias("TenantId")]
        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$TenantIds,

        [Parameter(ParameterSetName = 'DaysAgo')]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$DaysAgo = 7,

        [Parameter(ParameterSetName = 'MinutesAgo')]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$MinutesAgo,

        [Parameter(ParameterSetName = 'CustomTime')]
        [datetime]$StartTime,

        [Parameter()]
        [datetime]$EndTime = (Get-Date),

        [Parameter()]
        [int]$MaxRecordCount,

        [Parameter()]
        [hashtable]$SelectedWorkspaces
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # Determine TenantIds - if not provided, get from cache
        if (-not $TenantIds) {
            Write-Verbose "No TenantIds provided, attempting to retrieve from cache"
            try {
                $cachedTenantList = Get-XdrCache -CacheKey "XdrTenants" -ErrorAction Stop
                if ($cachedTenantList.Value) {
                    # Get the selected tenant from the cached list
                    $TenantIds = $cachedTenantList.Value | Select-Object -Unique -ExpandProperty tenantId
                    Write-Verbose "Using tenant from cache: $($TenantIds.name) ($($TenantIds.tenantId))"
                } else {
                    $XdrTenantId = Get-XdrCache -CacheKey "XdrTenantId" -ErrorAction SilentlyContinue
                    $tenantId = $XdrTenantId.Value
                    $TenantIds = @($tenantId)
                    Write-Warning "No tenant list found in cache. Using cached TenantId: $tenantId"
                }
            } catch {
                Write-Error "Failed to retrieve tenant information from cache. Please provide TenantIds explicitly or ensure you're connected to MTO."
                return
            }
        } else {
            Write-Verbose "Using provided TenantIds: $($TenantIds -join ', ')"
        }

        # Calculate StartTime based on parameter set
        switch ($PSCmdlet.ParameterSetName) {
            'DaysAgo' {
                $calculatedStartTime = $EndTime.AddDays(-$DaysAgo)
                Write-Verbose "Time range: Last $DaysAgo days"
            }
            'MinutesAgo' {
                $calculatedStartTime = $EndTime.AddMinutes(-$MinutesAgo)
                Write-Verbose "Time range: Last $MinutesAgo minutes"
            }
            'CustomTime' {
                $calculatedStartTime = $StartTime
                Write-Verbose "Time range: Custom from $StartTime to $EndTime"
            }
        }

        # Convert times to ISO 8601 format
        $startTimeString = $calculatedStartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $endTimeString = $EndTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

        Write-Verbose "Start time: $startTimeString"
        Write-Verbose "End time: $endTimeString"

        # Build the request body
        $body = [hashtable]::new();
        $body.Add("QueryText" , $QueryText)
        $body.Add("EncodedQueryText" , $QueryText)
        $body.Add("StartTime"        , $startTimeString)
        $body.Add("EndTime"          , $endTimeString)
        $body.Add("MaxRecordCount"   , $null)
        $body.Add("TenantIds"        , $TenantIds)
        $body.Add("tenantIds"        , $TenantIds)

        Write-Debug "Request Body: $($body | ConvertTo-Json -Depth 10 -Compress)"

        # Add optional parameters
        if ($PSBoundParameters.ContainsKey('MaxRecordCount')) {
            $body.MaxRecordCount = $MaxRecordCount
        }

        if ($SelectedWorkspaces) {
            $body.selectedWorkspaces = $SelectedWorkspaces
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10 -Compress

        # Create custom MTO context header
        $mtoContextHeader = @{
            targetTenantIds = $TenantIds
            stoTimeoutInMs  = 600000
        } | ConvertTo-Json -Compress
        
        # Clone script headers and add the MTO context header
        $customHeaders = $script:headers.Clone()
        $customHeaders["mto-context"] = $mtoContextHeader
        $customHeaders["m-package"] = "hunting"
        $customHeaders["m-componentname"] = "createHuntingUsxMsecHost"

        $Uri = "https://mto.security.microsoft.com/apiproxy/mtoapi/mtp/huntingService/queryExecutor?useFanOut=true"
        
        Write-Verbose "Executing MTO Advanced Hunting query across $($TenantIds.Count) tenant(s)"
        
        try {
            Write-Debug "Request URI: $Uri"
            Write-Debug "Request Headers: $($customHeaders | ConvertTo-Json -Compress)"
            Write-Debug "Request Body JSON: $($bodyJson | ConvertTo-Json -Compress)"

            $response = Invoke-RestMethod -ContentType "application/json" -Uri $Uri -Method Post -Body $bodyJson -Headers $customHeaders -WebSession $script:session
            # Reset web session to avoid issues with custom headers in subsequent calls
            Set-XdrConnectionSettings -ResetWebSession

            # Check for errors in metadata.responses
            if ($response.metadata -and $response.metadata.responses) {
                foreach ($tenantId in $response.metadata.responses.PSObject.Properties.Name) {
                    $tenantResponses = $response.metadata.responses.$tenantId
                    foreach ($tenantResponse in $tenantResponses) {
                        if ($tenantResponse.errorCode -ne "OK") {
                            Write-Warning "Tenant $tenantId returned error: $($tenantResponse.errorCode) (Status: $($tenantResponse.status))"
                        }
                        
                        # Verbose output for latency
                        Write-Verbose "Tenant $tenantId - Latency: $($tenantResponse.latencyInMs)ms, Status: $($tenantResponse.status), Retries: $($tenantResponse.retryCount)"
                    }
                }
            }

            # Return the result object with Schema and Results
            if ($response.result) {
                Write-Verbose "Query returned $($response.result.Results.Count) result(s)"
                
                # Create PSCustomObjects based on the schema
                if ($response.result.Results -and $response.result.Results.Count -gt 0) {
                    $typedResults = foreach ($resultRow in $response.result.Results) {
                        $orderedProperties = [ordered]@{}
                        
                        # Build properties based on schema order
                        foreach ($schemaColumn in $response.result.Schema) {
                            $columnName = $schemaColumn.Name
                            $columnValue = $resultRow.$columnName
                            
                            # Add property to ordered hashtable
                            $orderedProperties[$columnName] = $columnValue
                        }
                        
                        # Create PSCustomObject with ordered properties
                        [PSCustomObject]$orderedProperties
                    }
                    
                    Write-Verbose "Converted $($typedResults.Count) result(s) to PSCustomObjects"
                    return $typedResults
                } else {
                    Write-Verbose "No results in response"
                    return $null
                }
            } else {
                Write-Verbose "No results returned"
                return $null
            }
        } catch {
            Write-Error "Failed to execute MTO Advanced Hunting query: $_"
        }
    }

    end {
    }
}
