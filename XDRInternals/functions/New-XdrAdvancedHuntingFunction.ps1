function New-XdrAdvancedHuntingFunction {
    <#
    .SYNOPSIS
        Creates a new Advanced Hunting function in Microsoft Defender XDR.

    .DESCRIPTION
        Creates a new saved function for Advanced Hunting queries in Microsoft Defender XDR.
        These functions can be reused across multiple hunting queries and detection rules.
        Functions can be shared with the organization or kept private in folder structures.

    .PARAMETER Name
        The name of the function. This will be used to call the function in queries.

    .PARAMETER KQLQuery
        The KQL (Kusto Query Language) body of the function.
        This is the query logic that will be executed when the function is called.

    .PARAMETER Description
        Optional description of what the function does.

    .PARAMETER IsShared
        Switch to make the function shared with the organization.
        If not specified, the function will be private to the creator.

    .PARAMETER FolderPath
        Optional folder path for organizing private functions.
        Use forward slashes (/) or backslashes (\) - they will be automatically converted to double backslashes.
        Example: "MyFolder/SubFolder" or "MyFolder\SubFolder"

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The function is not created.

    .PARAMETER Confirm
        Prompts you for confirmation before running the cmdlet.

    .EXAMPLE
        New-XdrAdvancedHuntingFunction -Name "GetSuspiciousLogons" -KQLQuery "DeviceLogonEvents | where LogonType == 'Network'" -IsShared
        Creates a shared function that can be used across the organization.

    .EXAMPLE
        New-XdrAdvancedHuntingFunction -Name "ExtendedEntraIdSignInEvents" -KQLQuery $query -Description "Combines XDR and Sentinel data" -IsShared
        Creates a shared function with a description.

    .EXAMPLE
        New-XdrAdvancedHuntingFunction -Name "MyFunction" -KQLQuery "DeviceEvents" -FolderPath "TestFolder/SubFolder"
        Creates a private function in a folder structure.

    .EXAMPLE
        $query = @"
        EntraIdSignInEvents
        | where RiskLevelAggregated > 50
        | project Timestamp, AccountUpn, IPAddress
        "@
        New-XdrAdvancedHuntingFunction -Name "HighRiskSignIns" -KQLQuery $query -Description "Returns high-risk sign-ins" -IsShared
        Creates a shared function with a multi-line query.

    .OUTPUTS
        Object
        Returns the created function object from the API including:
        - Id: Unique identifier for the function
        - Name: Function name
        - Body: KQL query body
        - Description: Function description
        - Path: Folder path
        - IsShared: Sharing status
        - CreatedBy: Creator's UPN
        - LastUpdatedBy: Last updater's UPN
        - LastUpdateTime: Last update timestamp
        - OutputColumns: Schema of the function output

    .NOTES
        Functions can be called in queries using their name, e.g.: GetSuspiciousLogons()
        Shared functions are visible to all users in the organization.
        Private functions can be organized in folders for better management.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$KQLQuery,

        [Parameter()]
        [string]$Description = "",

        [Parameter()]
        [switch]$IsShared,

        [Parameter()]
        [string]$FolderPath = ""
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        try {
            # Normalize folder path: convert / or \ to \\
            if (-not [string]::IsNullOrWhiteSpace($FolderPath)) {
                # Replace forward slashes with backslashes first
                $normalizedPath = $FolderPath -replace '/', '\'
                # Then double the backslashes for JSON
                $normalizedPath = $normalizedPath -replace '\\', '\\'
            } else {
                $normalizedPath = ""
            }

            # Build API request body
            $body = @{
                Name            = $Name
                Path            = $normalizedPath
                Description     = $Description
                InputParameters = @()
                IsShared        = $IsShared.IsPresent
                Body            = $KQLQuery
            } | ConvertTo-Json -Depth 10

            $Uri = "https://security.microsoft.com/apiproxy/mtp/huntingService/savedFunctions"

            # If WhatIf is specified, output the JSON body
            if ($WhatIfPreference) {
                Write-Host "JSON Body for function '$Name':"
                Write-Host $body
                return
            }

            if ($PSCmdlet.ShouldProcess($Name, "Create Advanced Hunting function")) {
                Write-Verbose "Creating Advanced Hunting function: $Name"

                $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

                Write-Verbose "Successfully created function with ID: $($result.Id)"
                Write-Host $result
            }
        } catch {
            Write-Error "Failed to create Advanced Hunting function '$Name': $($_.Exception.Message)"
        }
    }

    end {

    }
}
