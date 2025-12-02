function ConvertTo-XdrEncodedAdvancedHuntingQuery {
    <#
    .SYNOPSIS
        Encodes an Advanced Hunting query for use in Microsoft Defender XDR.

    .DESCRIPTION
        Converts a KQL (Kusto Query Language) query into an encoded format that can be used
        in Microsoft Defender XDR Advanced Hunting. This is useful for generating shareable
        query links or for API operations that require encoded queries.

    .PARAMETER QueryText
        The KQL query text to be encoded. This should be a valid Advanced Hunting query.

    .EXAMPLE
        ConvertTo-XdrEncodedAdvancedHuntingQuery -QueryText "DeviceInfo | take 10"
        Encodes a simple query to retrieve 10 device records.

    .EXAMPLE
        $query = @"
        ExposureGraphNodes
        | where NodeLabel !in ("iam.user" ,"gcp-user", "user")
        | where EntityIds has_any ("AzureResourceId","AwsResourceName","GcpFullResourceName")
        | where isnotnull(NodeProperties.rawData.criticalityLevel)
        "@
        ConvertTo-XdrEncodedAdvancedHuntingQuery -QueryText $query
        Encodes a multi-line query for exposure graph analysis.

    .EXAMPLE
        Get-Content query.kql -Raw | ConvertTo-XdrEncodedAdvancedHuntingQuery
        Encodes a query from a file using pipeline input.

    .OUTPUTS
        String
        Returns the encoded query string that can be used in URLs or API calls.

    .NOTES
        This cmdlet requires an active session established via Connect-Xdr.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$QueryText
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $Uri = "https://security.microsoft.com/apiproxy/mtp/huntingService/queries/encode"
        
        $body = @{
            QueryText = $QueryText
        } | ConvertTo-Json -Compress

        Write-Verbose "Encoding Advanced Hunting query"
        Write-Verbose "Query length: $($QueryText.Length) characters"
        
        try {
            $result = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -WebSession $script:session -Headers $script:headers
            
            Write-Verbose "Query successfully encoded"
            return $result
        } catch {
            Write-Error "Failed to encode Advanced Hunting query: $_"
            return $null
        }
    }

    end {
    }
}
