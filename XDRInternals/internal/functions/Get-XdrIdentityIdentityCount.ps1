function Get-XdrIdentityIdentityCount {
    <#
    .SYNOPSIS
        Retrieves the total count of identities matching the specified filters.

    .DESCRIPTION
        Gets the total count of identities from Microsoft Defender for Identity based on the provided filters and search text.
        This is an internal function used for pagination support.

    .PARAMETER Filters
        The filters to apply when counting identities.

    .PARAMETER SearchText
        Text to search for in identities.

    .EXAMPLE
        Get-XdrIdentityIdentityCount -Filters @{} -SearchText ""
        Gets the total count of all identities.

    .EXAMPLE
        Get-XdrIdentityIdentityCount -Filters @{ IdentityProviders = @{ has = @('ActiveDirectory') } } -SearchText "admin"
        Gets the count of Active Directory identities matching "admin".
    #>
    [OutputType([int])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Filters,

        [Parameter()]
        [string]$SearchText = ''
    )

    begin {
        Update-XdrConnectionSettings
        $mdiHeaders = Get-XdrIdentityHeaders
    }

    process {
        $body = @{
            Filters    = $Filters
            SearchText = $SearchText
        }

        try {
            $uri = 'https://security.microsoft.com/apiproxy/mdi/identity/userapiservice/identities/count'
            Write-Verbose "Retrieving XDR identity count (SearchText: '$SearchText')"
            $response = Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 10) -WebSession $script:session -Headers $mdiHeaders -ErrorAction Stop
        } catch {
            Write-Error -Exception $_.Exception `
                -ErrorId 'XdrIdentityIdentityCountRequestFailed' `
                -Category ConnectionError `
                -TargetObject $body `
                -Message "Failed to retrieve XDR identity count: $($_.Exception.Message)"
            throw
        }

        $countCandidate = $response
        if ($null -ne $response) {
            $candidateNames = @('count', 'Count', 'totalCount', 'TotalCount', 'value', 'Value')

            if ($response -is [System.Collections.IDictionary]) {
                foreach ($propertyName in $candidateNames) {
                    if ($response.Contains($propertyName)) {
                        $countCandidate = $response[$propertyName]
                        break
                    }
                }
            } else {
                foreach ($propertyName in $candidateNames) {
                    if ($response.PSObject.Properties[$propertyName]) {
                        $countCandidate = $response.$propertyName
                        break
                    }
                }
            }
        }

        $count = 0
        if (-not [int]::TryParse([string]$countCandidate, [ref]$count)) {
            $message = "Identity count response was not numeric. Raw response: $($response | ConvertTo-Json -Depth 5 -Compress)"
            Write-Error -ErrorId 'XdrIdentityIdentityCountInvalidResponse' -Category InvalidResult -TargetObject $response -Message $message -ErrorAction Stop
        }

        return $count
    }
}


