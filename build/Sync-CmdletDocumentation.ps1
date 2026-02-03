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

Write-Host "🔍 Scanning cmdlet files in: $functionsPath" -ForegroundColor Cyan

# Get all cmdlet files
$cmdletFiles = Get-ChildItem -Path $functionsPath -Filter "*.ps1" | Sort-Object Name

if ($cmdletFiles.Count -eq 0) {
    Write-Warning "No cmdlet files found in $functionsPath"
    exit 1
}

Write-Host "📁 Found $($cmdletFiles.Count) cmdlet files" -ForegroundColor Green

# Extract cmdlet metadata
$cmdlets = @()

foreach ($file in $cmdletFiles) {
    Write-Verbose "Processing: $($file.Name)"
    
    $content = Get-Content -Path $file.FullName -Raw
    
    # Extract function name
    if ($content -match 'function\s+([\w-]+)\s*{') {
        $cmdletName = $Matches[1]
    } else {
        Write-Warning "Could not extract function name from $($file.Name)"
        continue
    }
    
    # Extract synopsis
    $synopsis = ""
    if ($content -match '\.SYNOPSIS\s*\n\s*(.+?)(?=\n\s*\n|\n\s*\.|\z)') {
        $synopsis = $Matches[1].Trim()
    }
    
    # Extract API URIs and build parameters mapping
    $apiMappings = @()
    
    # Find all Invoke-RestMethod calls with URIs
    $restMethodPattern = 'Invoke-RestMethod[^;]*?-Uri\s+["\''](https://security\.microsoft\.com[^"'']+)["\'']\s*[^;]*?(?:-Method\s+(\w+))?'
    $restMatches = [regex]::Matches($content, $restMethodPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    
    foreach ($match in $restMatches) {
        $uri = $match.Groups[1].Value.Trim()
        $method = if ($match.Groups[2].Success) { $match.Groups[2].Value } else { "GET" }
        
        # Try to extract parameter mappings
        $parameters = @{}
        
        # Look for body properties being set
        if ($content -match '(?s)\$body\s*=\s*@\{([^}]+)\}') {
            $bodyBlock = $Matches[1]
            # Extract key = value pairs from body
            $bodyMatches = [regex]::Matches($bodyBlock, '(\w+)\s*=\s*\$(\w+)')
            foreach ($bm in $bodyMatches) {
                $bodyKey = $bm.Groups[1].Value
                $paramName = $bm.Groups[2].Value
                $parameters[$paramName] = "body.$bodyKey"
            }
        }
        
        # Look for custom headers
        $headerMatches = [regex]::Matches($content, '\$(?:custom)?[Hh]eaders\[["\'']([\w-]+)["\'']]\s*=\s*\$(\w+)')
        foreach ($hm in $headerMatches) {
            $headerName = $hm.Groups[1].Value
            $paramName = $hm.Groups[2].Value
            $parameters[$paramName] = "header:$headerName"
        }
        
        $mapping = @{
            Cmdlet = $cmdletName
            ApiUri = $uri
        }
        
        if ($parameters.Count -gt 0) {
            $mapping.Parameters = $parameters
        }
        
        # Only add unique URIs for this cmdlet
        if (-not ($apiMappings | Where-Object { $_.ApiUri -eq $uri })) {
            $apiMappings += $mapping
        }
    }
    
    $cmdlets += [PSCustomObject]@{
        Name        = $cmdletName
        Synopsis    = $synopsis
        ApiMappings = $apiMappings
        File        = $file.Name
    }
}

Write-Host "✅ Extracted metadata from $($cmdlets.Count) cmdlets" -ForegroundColor Green

# Sort cmdlets alphabetically
$cmdlets = $cmdlets | Sort-Object Name

# ============================================================================
# Update README.md
# ============================================================================

Write-Host "`n📄 Updating README.md..." -ForegroundColor Cyan

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
    
    $newReadmeContent = $readmeContent -replace '(?s)(## Available Cmdlets\s*\n\s*\|[^\n]+\|[^\n]+\|\s*\n\|[^\n]+\|\s*\n)(.+?)(\n\n##)', $newTable
    
    if ($PSCmdlet.ShouldProcess($readmePath, "Update cmdlet table")) {
        $utf8Bom = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($readmePath, $newReadmeContent, $utf8Bom)
        Write-Host "  ✓ Updated cmdlet table with $($cmdlets.Count) entries" -ForegroundColor Green
    }
} else {
    Write-Warning "Could not find cmdlet table in README.md"
}

# ============================================================================
# Update XDRInternals.psd1
# ============================================================================

Write-Host "`n📦 Updating XDRInternals.psd1..." -ForegroundColor Cyan

$psd1Content = Get-Content -Path $psd1Path -Raw

# Find FunctionsToExport array
if ($psd1Content -match '(?s)FunctionsToExport\s*=\s*@\([^)]+\)') {
    $functionNames = $cmdlets.Name | ForEach-Object { "        `"$_`"" }
    $newFunctionsArray = "FunctionsToExport = @(`n" + ($functionNames -join ",`n") + "`n    )"
    
    $newPsd1Content = $psd1Content -replace '(?s)FunctionsToExport\s*=\s*@\([^)]+\)', $newFunctionsArray
    
    if ($PSCmdlet.ShouldProcess($psd1Path, "Update FunctionsToExport array")) {
        $utf8Bom = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($psd1Path, $newPsd1Content, $utf8Bom)
        Write-Host "  ✓ Updated FunctionsToExport with $($cmdlets.Count) entries" -ForegroundColor Green
    }
} else {
    Write-Warning "Could not find FunctionsToExport array in PSD1"
}

# ============================================================================
# Update API Mapping JSON files
# ============================================================================

Write-Host "`n🗺️  Building API mappings..." -ForegroundColor Cyan

# Collect all API mappings, prioritizing Get- cmdlets
$allApiMappings = @{}

foreach ($cmdlet in $cmdlets) {
    foreach ($mapping in $cmdlet.ApiMappings) {
        $uri = $mapping.ApiUri
        $isGetCmdlet = $cmdlet.Name -like 'Get-*'
        
        # If this URI doesn't exist yet, or current cmdlet is a Get- cmdlet, use it
        if (-not $allApiMappings.ContainsKey($uri) -or $isGetCmdlet) {
            $allApiMappings[$uri] = $mapping
        }
    }
}

# Convert to array and sort by cmdlet name
$apiMappingArray = @($allApiMappings.Values | Sort-Object Cmdlet)

Write-Host "  📊 Generated $($apiMappingArray.Count) API mappings" -ForegroundColor Green

# Convert to JSON with proper formatting
$jsonContent = $apiMappingArray | ConvertTo-Json -Depth 10

# Update XDRay/CmdletApiMapping.json
if ($PSCmdlet.ShouldProcess($jsonPath, "Update API mappings")) {
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($jsonPath, $jsonContent, $utf8Bom)
    Write-Host "  ✓ Updated $jsonPath" -ForegroundColor Green
}

# Update XDRay Firefox/CmdletApiMapping.json (same content)
if ($PSCmdlet.ShouldProcess($firefoxJsonPath, "Update API mappings")) {
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($firefoxJsonPath, $jsonContent, $utf8Bom)
    Write-Host "  ✓ Updated $firefoxJsonPath" -ForegroundColor Green
}

Write-Host "`n✨ Synchronization complete!" -ForegroundColor Green
Write-Host "   📄 README.md: $($cmdlets.Count) cmdlets" -ForegroundColor White
Write-Host "   📦 PSD1 manifest: $($cmdlets.Count) exports" -ForegroundColor White
Write-Host "   🗺️  API mappings: $($apiMappingArray.Count) entries" -ForegroundColor White