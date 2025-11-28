function Get-XdrAdvancedHuntingFunction {
    <#
    .SYNOPSIS
        Retrieves Advanced Hunting functions from Microsoft Defender XDR.

    .DESCRIPTION
        Gets saved functions for Advanced Hunting queries in Microsoft Defender XDR.
        Functions can be filtered by ID or retrieved all at once.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Id
        Optional ID of a specific function to retrieve.
        If not specified, all functions will be returned.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrAdvancedHuntingFunction
        Retrieves all Advanced Hunting functions using cached data if available.

    .EXAMPLE
        Get-XdrAdvancedHuntingFunction -Force
        Forces a fresh retrieval of all functions, bypassing the cache.

    .EXAMPLE
        Get-XdrAdvancedHuntingFunction -Id 6
        Retrieves a specific function by ID.

    .EXAMPLE
        Get-XdrAdvancedHuntingFunction | Where-Object { $_.IsShared -eq $true }
        Retrieves only shared functions.

    .EXAMPLE
        Get-XdrAdvancedHuntingFunction | Where-Object { $_.Path -like "MyFolder*" }
        Retrieves functions in a specific folder path.

    .OUTPUTS
        Object[]
        Returns an array of Advanced Hunting function objects containing:
        - Id: Unique identifier for the function
        - Name: Function name
        - Body: KQL query body
        - Description: Function description
        - Path: Folder path
        - IsShared: Sharing status
        - CreatedBy: Creator's UPN
        - LastUpdatedBy: Last updater's UPN
        - LastUpdateTime: Last update timestamp
        - InputParameters: Function parameters (if any)
        - OutputColumns: Schema of the function output
        - IsReadOnly: Whether the function is read-only
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [int]$Id,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        # If ID is specified, query the specific function directly
        if ($PSBoundParameters.ContainsKey('Id')) {
            Write-Verbose "Retrieving specific function with ID: $Id"
            $Uri = "https://security.microsoft.com/apiproxy/mtp/huntingService/functions/defender/savedfunctions/$Id"
            
            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
                return $result
            } catch {
                Write-Warning "No function found with ID: $Id"
                return $null
            }
        }

        # Otherwise, retrieve all functions with caching
        Write-Warning "Without specifying an ID, all functions will be retrieved but the KQL query will not be included in the output."
        $currentCacheValue = Get-XdrCache -CacheKey "XdrAdvancedHuntingFunction" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached XDR Advanced Hunting functions"
            $result = $currentCacheValue.Value
        } elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "XdrAdvancedHuntingFunction"
        }
        
        if (-not $result) {
            Write-Verbose "XDR Advanced Hunting functions cache is missing or expired"
            
            $Uri = "https://security.microsoft.com/apiproxy/mtp/huntingService/savedFunctions"
            Write-Verbose "Retrieving XDR Advanced Hunting functions"
            try {
                $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            } catch {
                Write-Error "Failed to retrieve Advanced Hunting functions: $_"
                $result = @()
            }

            if ($null -eq $result) {
                $result = @()
            }

            Write-Verbose "Retrieved $($result.Count) Advanced Hunting function(s)"
            Set-XdrCache -CacheKey "XdrAdvancedHuntingFunction" -Value $result -TTLMinutes 30
        }

        return $result
    }

    end {

    }
}
