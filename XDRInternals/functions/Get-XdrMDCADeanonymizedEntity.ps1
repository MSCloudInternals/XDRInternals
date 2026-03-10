function Get-XdrMDCADeanonymizedEntity {
    <#
    .SYNOPSIS
        Deanonymizes Cloud Discovery entity names from Microsoft Defender for Cloud Apps.

    .DESCRIPTION
        Resolves anonymized Cloud Discovery usernames back to their real identities
        using the Microsoft Defender for Cloud Apps deanonymization API.

    .PARAMETER Usernames
        One or more anonymized usernames to deanonymize (e.g. "User_aaaaaabbbbb=").

    .PARAMETER Justification
        The justification for deanonymizing the entity names. This parameter is mandatory.

    .EXAMPLE
        Get-XdrMDCADeanonymizedEntity -Usernames "User_aaaaaabbbbb="
        Deanonymizes a single username.

    .EXAMPLE
        Get-XdrMDCADeanonymizedEntity -Usernames "User_aaaaaabbbbb=", "User_zzzzzzzzXXXXXXX="
        Deanonymizes multiple usernames in a single request.

    .OUTPUTS
        PSCustomObject
        Returns the deanonymized entity mapping from anonymized names to real identities.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Usernames,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Justification
    )

    begin {
        Update-XdrConnectionSettings
        $collectedUsernames = [System.Collections.Generic.List[string]]::new()
    }

    process {
        foreach ($username in $Usernames) {
            $collectedUsernames.Add($username)
        }
    }

    end {
        $Uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/deanonymize_entity_names/"
        $Body = @{
            usernames     = @($collectedUsernames)
            justification = $Justification
            entityType    = 1
        } | ConvertTo-Json

        Write-Verbose "Deanonymizing $($collectedUsernames.Count) entity name(s)"
        try {
            $result = Invoke-XdrRestMethod -Uri $Uri -Method Post -Body $Body
            return $result.data
        } catch {
            Write-Error "Failed to deanonymize entity names: $_"
        }
    }
}
