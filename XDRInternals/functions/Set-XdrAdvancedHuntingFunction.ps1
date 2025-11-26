function Set-XdrAdvancedHuntingFunction {
    <#
    .SYNOPSIS
        Updates an existing Advanced Hunting function in Microsoft Defender XDR.

    .DESCRIPTION
        Updates a saved function for Advanced Hunting queries in Microsoft Defender XDR.
        The function must exist before it can be updated. The cmdlet will verify the function exists before attempting the update.

    .PARAMETER Id
        The ID of the function to update. This is mandatory to ensure the correct function is updated.

    .PARAMETER Name
        The new name of the function. If not specified, the existing name is preserved.

    .PARAMETER KQLQuery
        The new KQL (Kusto Query Language) body of the function.
        If not specified, the existing query is preserved.

    .PARAMETER Description
        The new description of the function. If not specified, the existing description is preserved.

    .PARAMETER IsShared
        Switch to make the function shared with the organization.
        If not specified, the existing sharing status is preserved.

    .PARAMETER FolderPath
        The new folder path for organizing the function.
        Use forward slashes (/) or backslashes (\) - they will be automatically converted to double backslashes.
        If not specified, the existing path is preserved.

    .PARAMETER InputObject
        PSObject containing the function to update. The object must include an Id property.
        Typically obtained from Get-XdrAdvancedHuntingFunction.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The function is not created.

    .PARAMETER Confirm
        Prompts you for confirmation before running the cmdlet.

    .EXAMPLE
        Set-XdrAdvancedHuntingFunction -Id 6 -Name "UpdatedFunctionName"
        Updates the name of function with ID 6.

    .EXAMPLE
        Set-XdrAdvancedHuntingFunction -Id 6 -KQLQuery $newQuery -Description "Updated description"
        Updates the query and description of a function.

    .EXAMPLE
        $function = Get-XdrAdvancedHuntingFunction -Id 6
        $function.IsShared = $false
        Set-XdrAdvancedHuntingFunction -InputObject $function
        Gets a function, modifies it, and updates it.

    .EXAMPLE
        Set-XdrAdvancedHuntingFunction -Id 6 -IsShared -FolderPath "NewFolder/SubFolder"
        Makes a function shared and moves it to a new folder path.

    .OUTPUTS
        Object
        Returns the updated function object from the API.

    .NOTES
        The function must exist before it can be updated.
        All unspecified parameters will preserve their existing values.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding(DefaultParameterSetName = 'Parameters', SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Parameters')]
        [int]$Id,

        [Parameter(ParameterSetName = 'Parameters')]
        [string]$Name,

        [Parameter(ParameterSetName = 'Parameters')]
        [string]$KQLQuery,

        [Parameter(ParameterSetName = 'Parameters')]
        [string]$Description,

        [Parameter(ParameterSetName = 'Parameters')]
        [switch]$IsShared,

        [Parameter(ParameterSetName = 'Parameters')]
        [string]$FolderPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'InputObject', ValueFromPipeline = $true)]
        [object]$InputObject
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'InputObject') {
                # Extract parameters from InputObject
                if (-not $InputObject.Id) {
                    throw "InputObject must contain an 'Id' property. Ensure you're passing an object from Get-XdrAdvancedHuntingFunction."
                }
                $Id = $InputObject.Id
            }

            # Verify the function exists by forcing a fresh retrieval
            Write-Verbose "Verifying function with ID $Id exists"
            $existingFunction = Get-XdrAdvancedHuntingFunction -Id $Id -Force

            if (-not $existingFunction) {
                throw "No Advanced Hunting function found with ID '$Id'. Use New-XdrAdvancedHuntingFunction to create a new function."
            }

            # Build the update body based on parameter set
            if ($PSCmdlet.ParameterSetName -eq 'InputObject') {
                # Use values from InputObject
                $functionName = $InputObject.Name
                $functionBody = $InputObject.Body
                $functionDescription = if ($InputObject.Description) { $InputObject.Description } else { "" }
                $functionIsShared = $InputObject.IsShared
                $functionPath = if ($InputObject.Path) { $InputObject.Path } else { "" }
                $functionInputParameters = if ($InputObject.InputParameters) { $InputObject.InputParameters } else { @() }
            } else {
                # Use provided parameters or existing values
                $functionName = if ($PSBoundParameters.ContainsKey('Name')) { $Name } else { $existingFunction.Name }
                $functionBody = if ($PSBoundParameters.ContainsKey('KQLQuery')) { $KQLQuery } else { $existingFunction.Body }
                $functionDescription = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { if ($existingFunction.Description) { $existingFunction.Description } else { "" } }
                $functionIsShared = if ($PSBoundParameters.ContainsKey('IsShared')) { $IsShared.IsPresent } else { $existingFunction.IsShared }

                # Handle folder path
                if ($PSBoundParameters.ContainsKey('FolderPath')) {
                    if (-not [string]::IsNullOrWhiteSpace($FolderPath)) {
                        # Replace forward slashes with backslashes first
                        $functionPath = $FolderPath -replace '/', '\'
                        # Then double the backslashes for JSON
                        $functionPath = $functionPath -replace '\\', '\\'
                    } else {
                        $functionPath = ""
                    }
                } else {
                    $functionPath = if ($existingFunction.Path) { $existingFunction.Path } else { "" }
                }

                $functionInputParameters = if ($existingFunction.InputParameters) { $existingFunction.InputParameters } else { @() }
            }

            # Build API request body
            $body = @{
                Id              = $Id
                Name            = $functionName
                Path            = $functionPath
                Description     = $functionDescription
                InputParameters = $functionInputParameters
                IsShared        = $functionIsShared
                Body            = $functionBody
            } | ConvertTo-Json -Depth 10

            $Uri = "https://security.microsoft.com/apiproxy/mtp/huntingService/savedFunctions/$Id"

            # If WhatIf is specified, output the JSON body
            if ($WhatIfPreference) {
                Write-Host "JSON Body for function '$functionName' (ID: $Id):"
                Write-Host $body
                return
            }

            if ($PSCmdlet.ShouldProcess("$functionName (ID: $Id)", "Update Advanced Hunting function")) {
                Write-Verbose "Updating Advanced Hunting function: $functionName (ID: $Id)"

                $result = Invoke-RestMethod -Uri $Uri -Method PATCH -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "XdrAdvancedHuntingFunction" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully updated function with ID: $($result.Id)"
                Write-Host $result
            }
        } catch {
            Write-Error "Failed to update Advanced Hunting function with ID '$Id': $($_.Exception.Message)"
        }
    }

    end {

    }
}
