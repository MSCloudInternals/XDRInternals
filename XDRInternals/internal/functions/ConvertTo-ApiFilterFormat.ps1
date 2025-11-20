function ConvertTo-ApiFilterFormat {
    <#
    .SYNOPSIS
        Converts filter object to API format with expressionType properties.

    .DESCRIPTION
        Recursively processes filter expressions and adds expressionType properties.

    .PARAMETER Filters
        Filter object from YAML (PSCustomObject or Hashtable).

    .EXAMPLE
        $filter = @{
            operator = "AND"
            expressions = @(
                @{
                    source = "severity"
                    filter = "equals"
                    values = "high"
                },
                @{
                    group = @{
                        operator = "OR"
                        expressions = @(
                            @{
                                source = "status"
                                filter = "equals"
                                values = @("active", "inProgress")
                            },
                            @{
                                source = "assignedTo"
                                filter = "equals"
                                values = "john.doe"
                            }
                        )
                    }
                }
            )
        }
        $apiFilter = ConvertTo-ApiFilterFormat -Filters $filter
        Converts the filter object to the API format.

    .OUTPUTS
        Hashtable
        Returns the filter object formatted for API consumption.
    #>
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Filters
    )

    # Convert PSCustomObject to hashtable for easier processing
    if ($Filters -is [System.Management.Automation.PSCustomObject]) {
        $filtersHash = @{}
        foreach ($prop in $Filters.PSObject.Properties) {
            $filtersHash[$prop.Name] = $prop.Value
        }
    } else {
        $filtersHash = $Filters
    }

    $result = @{
        operator       = $filtersHash.operator
        expressionType = "Nested"
        expressions    = [System.Collections.ArrayList]::new()
    }

    if ($filtersHash.ContainsKey('expressions') -and $filtersHash.expressions) {
        foreach ($expr in $filtersHash.expressions) {
            # Convert expression to hashtable if it's a PSCustomObject
            if ($expr -is [System.Management.Automation.PSCustomObject]) {
                $exprHash = @{}
                foreach ($prop in $expr.PSObject.Properties) {
                    $exprHash[$prop.Name] = $prop.Value
                }
            } else {
                $exprHash = $expr
            }

            if ($exprHash.ContainsKey('source')) {
                # Predicate expression
                $values = $exprHash.values
                # Ensure values is always an array
                if ($values -isnot [System.Collections.ArrayList] -and $values -isnot [array]) {
                    $values = @($values)
                }

                $predicate = @{
                    expressionType = "Predicate"
                    source         = $exprHash.source
                    filter         = $exprHash.filter
                    values         = $values
                }
                [void]$result.expressions.Add($predicate)
            } elseif ($exprHash.ContainsKey('group')) {
                # Nested group
                $nestedGroup = ConvertTo-ApiFilterFormat -Filters $exprHash.group
                [void]$result.expressions.Add($nestedGroup)
            }
        }
    }

    return $result
}