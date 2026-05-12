<#
.SYNOPSIS
    Synchronizes cmdlet documentation across README, PSD1 manifest, and API mapping files.

.DESCRIPTION
    This script scans all cmdlet files in XDRInternals/functions/, extracts their metadata
    (name, synopsis, API URIs, parameters), and updates:
    - ./README.md (cmdlet table with descriptions)
    - ./XDRInternals/XDRInternals.psd1 (FunctionsToExport array)
    - ./XDRay/CmdletApiMapping.json (cmdlet to API mappings)
    - ./XDRay Firefox/CmdletApiMapping.json (same as above for Firefox extension)

.PARAMETER WhatIf
    Shows what changes would be made without actually making them.

.EXAMPLE
    .\build\Sync-CmdletDocumentation.ps1
    
    Syncs all cmdlet documentation.

.EXAMPLE
    .\build\Sync-CmdletDocumentation.ps1 -WhatIf
    
    Shows what changes would be made without modifying files.
#>

[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'

# Resolve paths relative to repository root
$repoRoot = Split-Path -Parent $PSScriptRoot
$functionsPath = Join-Path $repoRoot "XDRInternals\functions"
$readmePath = Join-Path $repoRoot "README.md"
$psd1Path = Join-Path $repoRoot "XDRInternals\XDRInternals.psd1"
$jsonPath = Join-Path $repoRoot "XDRay\CmdletApiMapping.json"
$firefoxJsonPath = Join-Path $repoRoot "XDRay Firefox\CmdletApiMapping.json"

Write-Verbose "Scanning cmdlet files in: $functionsPath"

# Get all cmdlet files
$cmdletFiles = Get-ChildItem -Path $functionsPath -Filter "*.ps1" | Sort-Object Name

if ($cmdletFiles.Count -eq 0) {
    Write-Warning "No cmdlet files found in $functionsPath"
    exit 1
}

Write-Verbose "Found $($cmdletFiles.Count) cmdlet files"

# Helper function to sort hashtable keys alphabetically
function ConvertTo-SortedHashtable {
    param([hashtable]$InputHashtable)
    
    if ($InputHashtable.Count -eq 0) {
        return @{}
    }
    
    $sorted = [ordered]@{}
    $InputHashtable.Keys | Sort-Object | ForEach-Object {
        $sorted[$_] = $InputHashtable[$_]
    }
    return $sorted
}

# Helper function to convert PSCustomObject or hashtable to sorted hashtable
function ConvertTo-SortedHashtableFromObject {
    param($InputObject)
    
    if ($null -eq $InputObject) {
        return @{}
    }
    
    if ($InputObject -is [PSCustomObject]) {
        $hash = @{}
        $InputObject.PSObject.Properties | ForEach-Object {
            $hash[$_.Name] = $_.Value
        }
        return ConvertTo-SortedHashtable -InputHashtable $hash
    } elseif ($InputObject -is [hashtable]) {
        return ConvertTo-SortedHashtable -InputHashtable $InputObject
    }
    
    return $InputObject
}

# Helper function to test if URI is incomplete or transient
function Test-IncompleteUri {
    param([string]$Uri)

    if ([string]::IsNullOrWhiteSpace($Uri)) {
        return $true
    }

    if ($Uri -match '^https://[^/]+\{[\w]+\}$') {
        return $true
    }

    if ($Uri -match '\{(?:Prev|Next|SkipToken|ContinuationToken)\}') {
        return $true
    }

    return $Uri -match '\w\{[\w]+\}$'
}

# Helper function to extract API parameter mappings from cmdlet content using PowerShell AST
function Get-CmdletFunctionAst {
    param(
        [string]$Content,
        [string]$ExpectedFunctionName
    )

    $tokens = $null
    $parseErrors = $null
    $scriptAst = [System.Management.Automation.Language.Parser]::ParseInput($Content, [ref]$tokens, [ref]$parseErrors)

    if ($parseErrors.Count -gt 0) {
        return $null
    }

    $functionAsts = @(
        $scriptAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true)
    )

    if ($functionAsts.Count -eq 0) {
        return $null
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedFunctionName)) {
        $expectedFunctionAst = @(
            $functionAsts |
                Where-Object { $_.Name -ceq $ExpectedFunctionName } |
                Select-Object -First 1
        )[0]

        if ($expectedFunctionAst) {
            return $expectedFunctionAst
        }
    }

    return @($functionAsts | Select-Object -First 1)[0]
}

function Get-ApiParameterMapping {
    param(
        [string]$Content,
        [string]$ExpectedFunctionName
    )

    $parameters = @{}
    $functionAst = Get-CmdletFunctionAst -Content $Content -ExpectedFunctionName $ExpectedFunctionName

    if ($null -eq $functionAst) {
        return $parameters
    }

    $commandParameterNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($parameter in @($functionAst.Body.ParamBlock.Parameters)) {
        [void]$commandParameterNames.Add($parameter.Name.VariablePath.UserPath)
    }

    $assignments = @(
        $functionAst.Body.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst]
            }, $true)
    )
    $parameterAliases = @{}
    $semanticParameterFallbacks = @{
        Body                              = 'KQLQuery'
        TroubleshootExpirationDateTimeUtc = 'TroubleshootDurationHours'
    }

    function Resolve-ExpressionAst {
        param($Ast)

        while ($Ast) {
            if ($Ast -is [System.Management.Automation.Language.CommandExpressionAst]) {
                $Ast = $Ast.Expression
                continue
            }

            if ($Ast -is [System.Management.Automation.Language.ParenExpressionAst]) {
                $Ast = $Ast.Pipeline
                continue
            }

            if ($Ast -is [System.Management.Automation.Language.PipelineAst]) {
                $pureExpression = $Ast.GetPureExpression()
                $Ast = if ($pureExpression) { $pureExpression } elseif ($Ast.PipelineElements.Count -gt 0) { $Ast.PipelineElements[0] } else { $null }
                continue
            }

            break
        }

        return $Ast
    }

    function Get-LiteralValue {
        param($Ast)

        $Ast = Resolve-ExpressionAst -Ast $Ast
        if ($Ast -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            $Ast -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -or
            $Ast -is [System.Management.Automation.Language.ConstantExpressionAst]) {
            return [string]$Ast.Value
        }

        return $null
    }

    function Resolve-VariableName {
        param([string]$VariableName)

        $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        while (-not [string]::IsNullOrWhiteSpace($VariableName) -and $visited.Add($VariableName)) {
            if ($commandParameterNames.Contains($VariableName)) {
                return $VariableName
            }

            if ($parameterAliases.ContainsKey($VariableName)) {
                $VariableName = $parameterAliases[$VariableName]
                continue
            }

            foreach ($parameterName in $commandParameterNames) {
                if ($VariableName.Length -gt $parameterName.Length -and $VariableName.EndsWith($parameterName, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $parameterName
                }
            }

            break
        }

        return $null
    }

    function Get-ReferencedParameterName {
        param($Ast)

        $Ast = Resolve-ExpressionAst -Ast $Ast
        if ($null -eq $Ast) {
            return $null
        }

        if ($Ast -is [System.Management.Automation.Language.VariableExpressionAst]) {
            return Resolve-VariableName -VariableName $Ast.VariablePath.UserPath
        }

        if ($Ast -is [System.Management.Automation.Language.MemberExpressionAst] -and $Ast -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            $memberName = Get-LiteralValue -Ast $Ast.Member
            if ($memberName -eq 'IsPresent') {
                return Get-ReferencedParameterName -Ast $Ast.Expression
            }

            return $null
        }

        $referencedParameters = @(
            $Ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.VariableExpressionAst]
                }, $true) |
                Where-Object {
                    $parent = $_.Parent
                    if ($parent -is [System.Management.Automation.Language.MemberExpressionAst]) {
                        (Get-LiteralValue -Ast $parent.Member) -eq 'IsPresent' -and $parent.Expression -eq $_
                    } else {
                        $true
                    }
                } |
                ForEach-Object { Resolve-VariableName -VariableName $_.VariablePath.UserPath } |
                Where-Object { $_ } |
                Select-Object -Unique
        )

        if (@($referencedParameters).Count -eq 1) {
            return @($referencedParameters)[0]
        }

        return $null
    }

    function Add-PathMapping {
        param(
            [string]$ParameterName,
            [string]$Path
        )

        if (-not [string]::IsNullOrWhiteSpace($ParameterName) -and -not [string]::IsNullOrWhiteSpace($Path)) {
            $parameters[$ParameterName] = $Path
        }
    }

    function Add-HashtableMapping {
        param(
            [System.Management.Automation.Language.HashtableAst]$HashtableAst,
            [string]$PathPrefix
        )

        foreach ($entry in $HashtableAst.KeyValuePairs) {
            $keyName = Get-LiteralValue -Ast $entry.Item1
            if ([string]::IsNullOrWhiteSpace($keyName)) {
                continue
            }

            $path = "$PathPrefix.$keyName"
            $valueAst = Resolve-ExpressionAst -Ast $entry.Item2
            if ($valueAst -is [System.Management.Automation.Language.HashtableAst]) {
                Add-HashtableMapping -HashtableAst $valueAst -PathPrefix $path
                continue
            }

            $parameterName = Get-ReferencedParameterName -Ast $valueAst
            if (-not $parameterName -and $semanticParameterFallbacks.ContainsKey($keyName)) {
                $fallbackParameterName = $semanticParameterFallbacks[$keyName]
                if ($commandParameterNames.Contains($fallbackParameterName)) {
                    $parameterName = $fallbackParameterName
                }
            }

            Add-PathMapping -ParameterName $parameterName -Path $path
        }
    }

    foreach ($assignment in $assignments) {
        if ($assignment.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $assignment.Left.VariablePath.UserPath -notmatch 'body$' -and
            -not $commandParameterNames.Contains($assignment.Left.VariablePath.UserPath)) {
            $aliasSourceAst = Resolve-ExpressionAst -Ast $assignment.Right
            if ($aliasSourceAst -is [System.Management.Automation.Language.CommandAst]) {
                continue
            }

            $aliasName = Get-ReferencedParameterName -Ast $aliasSourceAst
            if ($aliasName) {
                $parameterAliases[$assignment.Left.VariablePath.UserPath] = $aliasName
            }
        }
    }

    foreach ($assignment in $assignments) {
        if ($assignment.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $assignment.Left.VariablePath.UserPath -match 'body$') {
            $bodyAst = Resolve-ExpressionAst -Ast $assignment.Right
            if ($bodyAst -is [System.Management.Automation.Language.HashtableAst]) {
                Add-HashtableMapping -HashtableAst $bodyAst -PathPrefix 'body'
            }
            continue
        }

        if ($assignment.Left -isnot [System.Management.Automation.Language.IndexExpressionAst]) {
            continue
        }

        $headerTarget = $assignment.Left.Target
        if ($headerTarget -isnot [System.Management.Automation.Language.VariableExpressionAst]) {
            continue
        }

        if ($headerTarget.VariablePath.UserPath -notmatch 'headers$') {
            continue
        }

        Add-PathMapping -ParameterName (Get-ReferencedParameterName -Ast $assignment.Right) -Path ("header:{0}" -f (Get-LiteralValue -Ast $assignment.Left.Index))
    }

    return $parameters
}

# Helper function to convert metadata into an API mapping object
function ConvertTo-ApiMapping {
    param(
        [string]$CmdletName,
        [string]$Uri,
        [hashtable]$Parameters
    )
    
    $mapping = [ordered]@{
        Cmdlet = $CmdletName
        ApiUri = $Uri
    }
    
    if ($Parameters.Count -gt 0) {
        $mapping.Parameters = ConvertTo-SortedHashtable -InputHashtable $Parameters
    }
    
    return $mapping
}

function Get-ScopedApiParameterMapping {
    param(
        [string]$CmdletName,
        [string]$Uri,
        [hashtable]$DefaultParameters
    )

    $scopedParameters = @{}
    foreach ($key in $DefaultParameters.Keys) {
        $scopedParameters[$key] = $DefaultParameters[$key]
    }

    # Get-XdrCloudAppsDiscovery mixes multiple discovery operations behind one cmdlet.
    # Until the generator understands parameter-set-specific URIs, keep the shared
    # deanonymization body parameters off the other discovery endpoints.
    if ($CmdletName -eq 'Get-XdrCloudAppsDiscovery' -and $Uri -notmatch '/deanonymize_entity_names/$') {
        return @{}
    }

    return $scopedParameters
}

# Helper function to normalize API URIs
function ConvertTo-NormalizedApiUri {
    param([string]$Uri)
    
    # Strip query string parameters (everything after ?)
    if ($Uri -match '^([^?]+)') {
        $Uri = $Matches[1]
    }
    
    # Convert PowerShell variables to placeholders - order matters!
    
    # Pattern 1: $({variable}.property) -> {Property}
    while ($Uri -match '\$\(\{[^}]+\}\.(\w+)\)') {
        $propName = $Matches[1]
        $Uri = $Uri -replace [regex]::Escape($Matches[0]), "{$propName}"
    }
    
    # Pattern 2: $($variable.property) -> {Property}
    while ($Uri -match '\$\(\$\w+\.(\w+)\)') {
        $propName = $Matches[1]
        $Uri = $Uri -replace [regex]::Escape($Matches[0]), "{$propName}"
    }
    
    # Pattern 3: $({variable}) -> {Variable}
    $Uri = $Uri -replace '\$\(\{(\w+)\}\)', '{$1}'
    
    # Pattern 4: $($variable) -> {Variable}
    $Uri = $Uri -replace '\$\(\$?(\w+)\)', '{$1}'
    
    # Pattern 5: $variable -> {Variable}
    $Uri = $Uri -replace '\$(\w+)', '{$1}'
    
    return $Uri
}

# Extract cmdlet metadata
$cmdlets = @()

foreach ($file in $cmdletFiles) {
    Write-Verbose "Processing: $($file.Name)"
    
    $content = Get-Content -Path $file.FullName -Raw
    $functionAst = Get-CmdletFunctionAst -Content $content -ExpectedFunctionName $file.BaseName

    if ($null -eq $functionAst) {
        Write-Warning "Could not extract function name from $($file.Name)"
        continue
    }

    $cmdletName = $functionAst.Name
    $parameters = Get-ApiParameterMapping -Content $content -ExpectedFunctionName $cmdletName
    
    # Extract synopsis
    $synopsis = ""
    if ($content -match '\.SYNOPSIS\s*\n\s*(.+?)(?=\n\s*(?:\n|\.|#>)|\z)') {
        $synopsis = $Matches[1].Trim()
    }
    
    # Extract API URIs and build parameters mapping
    $apiMappings = [System.Collections.ArrayList]@()
    
    # Pattern 1: Find $Uri = "https://..." variable assignments
    $uriAssignmentPattern = '\$Uri\s*=\s*["\''](https://security\.microsoft\.com[^"'']+)["\'']\s*'
    $uriAssignmentMatches = [regex]::Matches($content, $uriAssignmentPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    
    foreach ($match in $uriAssignmentMatches) {
        $uri = $match.Groups[1].Value.Trim()
        
        # Normalize the URI (remove query strings, convert variables to placeholders)
        $uri = ConvertTo-NormalizedApiUri -Uri $uri
        
        # Skip URIs that are just the base domain + placeholder (incomplete URIs)
        if (Test-IncompleteUri -Uri $uri) {
            Write-Verbose "Skipping incomplete URI pattern in $($file.Name): $uri"
            continue
        }
        
        # Create mapping object
        $mappingParameters = Get-ScopedApiParameterMapping -CmdletName $cmdletName -Uri $uri -DefaultParameters $parameters
        $mapping = ConvertTo-ApiMapping -CmdletName $cmdletName -Uri $uri -Parameters $mappingParameters
        
        # Only add unique URIs for this cmdlet
        if (-not ($apiMappings | Where-Object { $_.ApiUri -eq $uri })) {
            [void]$apiMappings.Add($mapping)
        }
    }
    
    # Pattern 2: Find Invoke-RestMethod calls with literal URI strings (for cmdlets that don't use $Uri variable)
    $restMethodPattern = 'Invoke-RestMethod[^;]*?-Uri\s+["\''](https://security\.microsoft\.com[^"'']+)["\'']\s*[^;]*?(?:-Method\s+(\w+))?'
    $restMatches = [regex]::Matches($content, $restMethodPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    
    foreach ($match in $restMatches) {
        $uri = $match.Groups[1].Value.Trim()

        # Normalize the URI (remove query strings, convert variables to placeholders)
        $uri = ConvertTo-NormalizedApiUri -Uri $uri
        
        # Skip URIs that are just the base domain + placeholder (incomplete URIs)
        if (Test-IncompleteUri -Uri $uri) {
            Write-Verbose "Skipping incomplete URI pattern in $($file.Name): $uri"
            continue
        }
        
        # Create mapping object
        $mappingParameters = Get-ScopedApiParameterMapping -CmdletName $cmdletName -Uri $uri -DefaultParameters $parameters
        $mapping = ConvertTo-ApiMapping -CmdletName $cmdletName -Uri $uri -Parameters $mappingParameters
        
        # Only add unique URIs for this cmdlet
        if (-not ($apiMappings | Where-Object { $_.ApiUri -eq $uri })) {
            [void]$apiMappings.Add($mapping)
        }
    }
    
    $cmdlets += [PSCustomObject]@{
        Name        = $cmdletName
        Synopsis    = $synopsis
        ApiMappings = $apiMappings
        File        = $file.Name
    }
}

Write-Verbose "Extracted metadata from $($cmdlets.Count) cmdlets"

# Sort cmdlets alphabetically
$cmdlets = $cmdlets | Sort-Object Name

# ============================================================================
# Update README.md
# ============================================================================

Write-Verbose "`nUpdating README.md..."

$readmeContent = Get-Content -Path $readmePath -Raw

# Find the cmdlet table section
if ($readmeContent -match '(?s)(## Available Cmdlets\s*\n+\|[^\n]+\|\s*\n\|[^\n]+\|\s*\n)(.+?)(\n+##\s+\w+)') {
    $tableHeader = $Matches[1]
    $tableEnd = $Matches[3]
    
    # Build new table rows
    $tableRows = foreach ($cmdlet in $cmdlets) {
        $description = if ($cmdlet.Synopsis) { $cmdlet.Synopsis } else { "TODO: Add description" }
        "| $($cmdlet.Name.PadRight(63)) | $description |"
    }
    
    $newTable = $tableHeader + ($tableRows -join "`n") + $tableEnd
    
    $newReadmeContent = $readmeContent -replace '(?s)(## Available Cmdlets\s*\n+\|[^\n]+\|\s*\n\|[^\n]+\|\s*\n)(.+?)(\n+##\s+\w+)', $newTable
    
    if ($PSCmdlet.ShouldProcess($readmePath, "Update cmdlet table")) {
        $utf8Bom = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($readmePath, $newReadmeContent, $utf8Bom)
        Write-Verbose "Updated cmdlet table with $($cmdlets.Count) entries"
    }
} else {
    Write-Warning "Could not find cmdlet table in README.md"
}

# ============================================================================
# Update XDRInternals.psd1
# ============================================================================

Write-Verbose "`nUpdating XDRInternals.psd1..."

$psd1Content = Get-Content -Path $psd1Path -Raw

# Find FunctionsToExport array
if ($psd1Content -match '(?s)FunctionsToExport\s*=\s*@\([^)]+\)') {
    $functionNames = $cmdlets.Name | ForEach-Object { "        `"$_`"" }
    $newFunctionsArray = "FunctionsToExport = @(`n" + ($functionNames -join ",`n") + "`n    )"
    
    $newPsd1Content = $psd1Content -replace '(?s)FunctionsToExport\s*=\s*@\([^)]+\)', $newFunctionsArray
    
    if ($PSCmdlet.ShouldProcess($psd1Path, "Update FunctionsToExport array")) {
        $utf8Bom = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($psd1Path, $newPsd1Content, $utf8Bom)
        Write-Verbose "Updated FunctionsToExport with $($cmdlets.Count) entries"
    }
} else {
    Write-Warning "Could not find FunctionsToExport array in PSD1"
}

# ============================================================================
# Update API Mapping JSON files
# ============================================================================

Write-Verbose "`nBuilding API mappings..."

# Step 1: Load existing mappings and filter to only cmdlets that still exist
$validCmdletNames = @($cmdlets.Name)
$existingMappings = @{}
$deletedCount = 0

if (Test-Path $jsonPath) {
    try {
        $existingApiMappings = Get-Content -Path $jsonPath -Raw | ConvertFrom-Json
        foreach ($mapping in $existingApiMappings) {
            if ($validCmdletNames -contains $mapping.Cmdlet) {
                # Normalize the existing API URI
                $normalizedUri = ConvertTo-NormalizedApiUri -Uri $mapping.ApiUri
                
                # Skip incomplete URIs (just domain + placeholder)
                if (Test-IncompleteUri -Uri $normalizedUri) {
                    Write-Verbose "Removing incomplete URI pattern from cache: $($mapping.Cmdlet) - $normalizedUri"
                    $deletedCount++
                    continue
                }
                
                # Cmdlet still exists, keep the mapping
                $key = "$($mapping.Cmdlet)|$normalizedUri"
                
                # Update the mapping with normalized URI
                $updatedMapping = [ordered]@{
                    Cmdlet = $mapping.Cmdlet
                    ApiUri = $normalizedUri
                }
                if ($mapping.Parameters) {
                    $updatedMapping.Parameters = ConvertTo-SortedHashtableFromObject -InputObject $mapping.Parameters
                }
                
                $existingMappings[$key] = $updatedMapping
            } else {
                $deletedCount++
            }
        }
        Write-Verbose "Loaded $($existingMappings.Count) existing API mappings ($deletedCount orphaned entries removed)"
    } catch {
        Write-Warning "Could not load existing API mappings: $_"
    }
}

# Step 2-4: Add/update mappings in priority order (Get-*, Set-*, others)
# This ensures Get- cmdlets are preferred for any given URI
$newCount = 0
$updatedCount = 0

# Group cmdlets by prefix for priority processing
$getCmdlets = $cmdlets | Where-Object { $_.Name -like 'Get-*' }
$setCmdlets = $cmdlets | Where-Object { $_.Name -like 'Set-*' }
$otherCmdlets = $cmdlets | Where-Object { $_.Name -notlike 'Get-*' -and $_.Name -notlike 'Set-*' }

foreach ($cmdletGroup in @($getCmdlets, $setCmdlets, $otherCmdlets)) {
    foreach ($cmdlet in $cmdletGroup) {
        foreach ($mapping in $cmdlet.ApiMappings) {
            $key = "$($mapping.Cmdlet)|$($mapping.ApiUri)"
            
            if ($existingMappings.ContainsKey($key)) {
                # Update existing mapping (in case parameters changed)
                $existingMappings[$key] = $mapping
                $updatedCount++
            } else {
                # Add new mapping
                $existingMappings[$key] = $mapping
                $newCount++
            }
        }
    }
}

# Convert to array and sort alphabetically by Cmdlet, then by ApiUri for JSON output
# Note: Must convert ordered hashtables to PSCustomObjects for Sort-Object to work correctly
# Use explicit string comparison to ensure stable, deterministic sort order
$apiMappingArray = [System.Collections.ArrayList]@()
$existingMappings.Values | ForEach-Object {
    # Convert ordered hashtable to PSCustomObject
    [PSCustomObject]$_
} | Sort-Object -Property @{Expression = { $_.Cmdlet }; Ascending = $true }, @{Expression = { $_.ApiUri }; Ascending = $true } | ForEach-Object {
    # Convert back to ordered hashtable for JSON serialization
    $mapping = [ordered]@{
        Cmdlet = $_.Cmdlet
        ApiUri = $_.ApiUri
    }
    if ($_.Parameters) {
        $mapping.Parameters = ConvertTo-SortedHashtableFromObject -InputObject $_.Parameters
    }
    [void]$apiMappingArray.Add($mapping)
}

# Debug: Show first few entries to verify sort
Write-Verbose "First 5 cmdlets in sorted array: $($apiMappingArray[0..4].Cmdlet -join ', ')"

Write-Verbose "API mappings: $($apiMappingArray.Count) total ($newCount new, $updatedCount updated, $deletedCount removed)"

# Convert to JSON with proper formatting
$jsonContent = $apiMappingArray | ConvertTo-Json -Depth 10

# Update XDRay/CmdletApiMapping.json
if ($PSCmdlet.ShouldProcess($jsonPath, "Update API mappings")) {
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($jsonPath, $jsonContent, $utf8Bom)
    Write-Verbose "Updated $jsonPath"
}

# Update XDRay Firefox/CmdletApiMapping.json (same content)
if ($PSCmdlet.ShouldProcess($firefoxJsonPath, "Update API mappings")) {
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($firefoxJsonPath, $jsonContent, $utf8Bom)
    Write-Verbose "Updated $firefoxJsonPath"
}

Write-Verbose "`nSynchronization complete!"
Write-Verbose "README.md: $($cmdlets.Count) cmdlets"
Write-Verbose "PSD1 manifest: $($cmdlets.Count) exports"
Write-Verbose "API mappings: $($apiMappingArray.Count) entries"