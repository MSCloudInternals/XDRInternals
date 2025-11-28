function Get-XdrAdvancedHuntingUserHistory {
    <#
    .SYNOPSIS
        Retrieves Advanced Hunting user history from Microsoft Defender XDR.
    
    .DESCRIPTION
        Gets the user's Advanced Hunting query history from the Microsoft Defender XDR portal.
        By default, retrieves the last 28 days of history with a maximum of 30 results.
    
    .PARAMETER StartTime
        The start time for retrieving user history. Cannot be used together with Days parameter.
    
    .PARAMETER Days
        The number of days to look back from the current date. Cannot be used together with StartTime parameter.
        Defaults to 28 days if neither StartTime nor Days is specified.
    
    .PARAMETER MaxResults
        The maximum number of results to return. Defaults to 30.
    
    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.
    
    .EXAMPLE
        Get-XdrAdvancedHuntingUserHistory
        Retrieves the last 28 days of Advanced Hunting user history with up to 30 results.
    
    .EXAMPLE
        Get-XdrAdvancedHuntingUserHistory -Days 7 -MaxResults 50
        Retrieves the last 7 days of user history with up to 50 results.
    
    .EXAMPLE
        Get-XdrAdvancedHuntingUserHistory -StartTime "2025-10-18T18:36:11.482Z"
        Retrieves user history from the specified start time with up to 30 results.
    
    .OUTPUTS
        Object
        Returns the Advanced Hunting user history from the hunting service.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Days')]
    param (
        [Parameter(ParameterSetName = 'StartTime')]
        [datetime]$StartTime,
        
        [Parameter(ParameterSetName = 'Days')]
        [int]$Days = 28,
        
        [Parameter()]
        [int]$MaxResults = 30
    )
    
    begin {
        Update-XdrConnectionSettings
    }
    
    process {
        # Calculate the actual start time based on parameter set
        if ($PSCmdlet.ParameterSetName -eq 'Days') {
            $calculatedStartTime = (Get-Date).AddDays(-$Days)
        } else {
            $calculatedStartTime = $StartTime
        }
        
        # Convert to ISO 8601 format with milliseconds
        $startTimeString = $calculatedStartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        # Alternative would be https://security.microsoft.com/apiproxy/mtp/sentinelOnboarding/sentinel/workspaces/isOnboarded
        $Uri = "https://security.microsoft.com/apiproxy/mtp/huntingService/reports/userHistory"
        $Body = @{
            startTime  = $startTimeString
            maxResults = $MaxResults
        } | ConvertTo-Json
        
        Write-Verbose "Retrieving Advanced Hunting user history (StartTime: $startTimeString, MaxResults: $MaxResults)"
        try {
            $AdvancedHuntingUserHistory = Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -WebSession $script:session -Headers $script:headers
            return $AdvancedHuntingUserHistory
        } catch {
            Write-Error "Failed to retrieve Advanced Hunting user history: $_"
        }
    }
    
    end {
        
    }
}
