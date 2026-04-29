function ConvertFrom-XdrCloudAppsResponse {
    <#
    .SYNOPSIS
        Transforms Cloud Apps API responses from grid/table format to PowerShell objects.

    .DESCRIPTION
        Converts Microsoft Defender for Cloud Apps API responses that use the
        properties.columns/properties.rows structure into proper PowerShell objects.
        This flattens the data structure to make it more PowerShell-friendly.

        The raw API returns data like:
        @{
            type = "itemsResponse"
            properties = @{
                columns = @("col1", "col2", "col3")
                rows = @(
                    @("val1", "val2", "val3"),
                    @("val4", "val5", "val6")
                )
                paging = @{ continuationToken = "..." }
            }
        }

        This function transforms it to:
        @(
            @{ col1 = "val1"; col2 = "val2"; col3 = "val3" },
            @{ col1 = "val4"; col2 = "val5"; col3 = "val6" }
        )

    .PARAMETER InputObject
        The raw API response object to transform. Can be a single object or array.

    .PARAMETER TypeName
        Optional PSTypeName to assign to transformed objects for custom formatting.

    .EXAMPLE
        $raw = Get-XdrCloudAppsAiAgent -Raw
        $transformed = ConvertFrom-XdrCloudAppsResponse -InputObject $raw

    .NOTES
        TODO: Automatic pagination support - when .properties.paging.continuationToken exists,
        implement logic to automatically fetch additional pages and aggregate all results.
        This will be added once testable data with pagination is available.
    #>
    [OutputType([object[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$InputObject,

        [Parameter()]
        [string]$TypeName
    )

    process {
        # If input is null, return null
        if ($null -eq $InputObject) {
            return $null
        }

        # Check if this object has the properties.columns/rows structure
        if ($InputObject.PSObject.Properties['properties'] -and
            $InputObject.properties.PSObject.Properties['columns'] -and
            $InputObject.properties.PSObject.Properties['rows']) {

            $columns = $InputObject.properties.columns
            $rows = $InputObject.properties.rows

            # If no rows, return empty array
            if ($null -eq $rows -or $rows.Count -eq 0) {
                return @()
            }

            # Transform each row into an object
            $transformedObjects = foreach ($row in $rows) {
                $obj = [ordered]@{}
                
                for ($i = 0; $i -lt $columns.Count; $i++) {
                    # Column can be a string or an object with 'id' property
                    $columnName = if ($columns[$i] -is [string]) {
                        $columns[$i]
                    } elseif ($columns[$i].PSObject.Properties['id']) {
                        $columns[$i].id
                    } else {
                        "Column$i"
                    }
                    
                    $value = if ($i -lt $row.Count) { $row[$i] } else { $null }
                    $obj[$columnName] = $value
                }

                $psObj = [PSCustomObject]$obj

                # Add TypeName if specified
                if ($TypeName) {
                    $psObj.PSObject.TypeNames.Insert(0, $TypeName)
                }

                $psObj
            }

            return $transformedObjects
        }

        # If it doesn't have the expected structure, return as-is
        # This handles objects that don't need transformation (like Schema responses)
        if ($TypeName -and $InputObject.PSObject.TypeNames[0] -ne $TypeName) {
            $InputObject.PSObject.TypeNames.Insert(0, $TypeName)
        }

        return $InputObject
    }
}

