function Remove-XdrAdvancedHuntingFunction {
    <#
    .SYNOPSIS
        Removes an Advanced Hunting function from Microsoft Defender XDR.

    .DESCRIPTION
        Deletes a saved function for Advanced Hunting queries in Microsoft Defender XDR.
        The function must exist before it can be removed. The cmdlet will verify the function exists before attempting deletion.

    .PARAMETER Id
        The ID of the function to remove. This is mandatory to ensure the correct function is deleted.

    .PARAMETER InputObject
        PSObject containing the function to remove. The object must include an Id property.
        Typically obtained from Get-XdrAdvancedHuntingFunction.

    .PARAMETER WhatIf
        Shows what would happen if the cmdlet runs. The function is not created.

    .PARAMETER Confirm
        Prompts you for confirmation before running the cmdlet.

    .EXAMPLE
        Remove-XdrAdvancedHuntingFunction -Id 6
        Removes the function with ID 6.

    .EXAMPLE
        Get-XdrAdvancedHuntingFunction -Id 6 | Remove-XdrAdvancedHuntingFunction
        Gets a function and removes it through the pipeline.

    .EXAMPLE
        Get-XdrAdvancedHuntingFunction | Where-Object { $_.Name -eq "OldFunction" } | Remove-XdrAdvancedHuntingFunction
        Finds a function by name and removes it.

    .OUTPUTS
        None
        This cmdlet does not return any output upon successful deletion.

    .NOTES
        The function must exist before it can be removed.
        This operation requires confirmation by default due to high impact.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding(DefaultParameterSetName = 'Id', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Id', Position = 0)]
        [int]$Id,

        [Parameter(Mandatory = $true, ParameterSetName = 'InputObject', ValueFromPipeline = $true)]
        [object]$InputObject
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'InputObject') {
                # Extract ID from InputObject
                if (-not $InputObject.Id) {
                    throw "InputObject must contain an 'Id' property. Ensure you're passing an object from Get-XdrAdvancedHuntingFunction."
                }
                $Id = $InputObject.Id
                $functionName = if ($InputObject.Name) { $InputObject.Name } else { "ID: $Id" }
            } else {
                # Verify the function exists by forcing a fresh retrieval
                Write-Verbose "Verifying function with ID $Id exists"
                $existingFunction = Get-XdrAdvancedHuntingFunction -Id $Id -Force

                if (-not $existingFunction) {
                    throw "No Advanced Hunting function found with ID '$Id'. Cannot remove a non-existent function."
                }

                $functionName = if ($existingFunction.Name) { $existingFunction.Name } else { "ID: $Id" }
            }

            $Uri = "https://security.microsoft.com/apiproxy/mtp/huntingService/savedFunctions/$Id"

            if ($PSCmdlet.ShouldProcess("$functionName (ID: $Id)", "Remove Advanced Hunting function")) {
                Write-Verbose "Removing Advanced Hunting function: $functionName (ID: $Id)"

                $null = Invoke-RestMethod -Uri $Uri -Method Delete -ContentType "application/json" -WebSession $script:session -Headers $script:headers

                # Clear the cache for the Get cmdlet
                Clear-XdrCache -CacheKey "XdrAdvancedHuntingFunction" -ErrorAction SilentlyContinue

                Write-Verbose "Successfully removed function with ID: $Id"
            }
        } catch {
            Write-Error "Failed to remove Advanced Hunting function with ID '$Id': $($_.Exception.Message)"
        }
    }

    end {

    }
}
