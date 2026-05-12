Describe 'Sync-CmdletDocumentation' {
    It 'uses the public cmdlet matching the file name when helper functions come first' {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $sourceScriptPath = Join-Path $repoRoot 'build\Sync-CmdletDocumentation.ps1'
        $fixtureRoot = Join-Path $TestDrive 'repo'
        $fixtureBuildPath = Join-Path $fixtureRoot 'build'
        $fixtureFunctionsPath = Join-Path $fixtureRoot 'XDRInternals\functions'
        $fixtureManifestPath = Join-Path $fixtureRoot 'XDRInternals\XDRInternals.psd1'
        $fixtureReadmePath = Join-Path $fixtureRoot 'README.md'
        $fixtureJsonPath = Join-Path $fixtureRoot 'XDRay\CmdletApiMapping.json'
        $fixtureFirefoxJsonPath = Join-Path $fixtureRoot 'XDRay Firefox\CmdletApiMapping.json'
        $fixtureFunctionPath = Join-Path $fixtureFunctionsPath 'Get-TestWidget.ps1'

        $null = New-Item -Path $fixtureBuildPath -ItemType Directory -Force
        $null = New-Item -Path $fixtureFunctionsPath -ItemType Directory -Force
        $null = New-Item -Path (Split-Path -Parent $fixtureJsonPath) -ItemType Directory -Force
        $null = New-Item -Path (Split-Path -Parent $fixtureFirefoxJsonPath) -ItemType Directory -Force

        Copy-Item -Path $sourceScriptPath -Destination (Join-Path $fixtureBuildPath 'Sync-CmdletDocumentation.ps1')

        Set-Content -Path $fixtureReadmePath -Value @'
## Available Cmdlets

| Cmdlet | Description |
|--------|-------------|
| Placeholder | Placeholder |

## Next Section
'@ -Encoding utf8

        Set-Content -Path $fixtureManifestPath -Value @'
@{
    FunctionsToExport = @(
        "Placeholder"
    )
}
'@ -Encoding utf8

        Set-Content -Path $fixtureJsonPath -Value '[]' -Encoding utf8
        Set-Content -Path $fixtureFirefoxJsonPath -Value '[]' -Encoding utf8

        Set-Content -Path $fixtureFunctionPath -Value @'
function ConvertFrom-TestWidgetJson {
    [CmdletBinding()]
    param(
        [string]$Json
    )

    return $Json
}

<#
.SYNOPSIS
Gets test widgets.
#>
function Get-TestWidget {
    [CmdletBinding()]
    param(
        [string]$WidgetId
    )

    $Uri = "https://security.microsoft.com/api/widgets/$WidgetId"
    Invoke-RestMethod -Uri $Uri -Method Get
}
'@ -Encoding utf8

        & (Join-Path $fixtureBuildPath 'Sync-CmdletDocumentation.ps1')

        $manifestContent = Get-Content -Path $fixtureManifestPath -Raw
        $apiMappings = Get-Content -Path $fixtureJsonPath -Raw | ConvertFrom-Json
        $firefoxApiMappings = Get-Content -Path $fixtureFirefoxJsonPath -Raw | ConvertFrom-Json
        $readmeContent = Get-Content -Path $fixtureReadmePath -Raw

        $manifestContent | Should -Match '"Get-TestWidget"'
        $manifestContent | Should -Not -Match '"ConvertFrom-TestWidgetJson"'
        @($apiMappings).Count | Should -Be 1
        @($firefoxApiMappings).Count | Should -Be 1
        @($apiMappings)[0].Cmdlet | Should -Be 'Get-TestWidget'
        @($firefoxApiMappings)[0].Cmdlet | Should -Be 'Get-TestWidget'
        $readmeContent | Should -Match '\| Get-TestWidget\s+\| Gets test widgets\.'
    }

        It 'adds a newly introduced cmdlet to generated outputs' {
                $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
                $sourceScriptPath = Join-Path $repoRoot 'build\Sync-CmdletDocumentation.ps1'
                $fixtureRoot = Join-Path $TestDrive 'repo'
                $fixtureBuildPath = Join-Path $fixtureRoot 'build'
                $fixtureFunctionsPath = Join-Path $fixtureRoot 'XDRInternals\functions'
                $fixtureManifestPath = Join-Path $fixtureRoot 'XDRInternals\XDRInternals.psd1'
                $fixtureReadmePath = Join-Path $fixtureRoot 'README.md'
                $fixtureJsonPath = Join-Path $fixtureRoot 'XDRay\CmdletApiMapping.json'
                $fixtureFirefoxJsonPath = Join-Path $fixtureRoot 'XDRay Firefox\CmdletApiMapping.json'
                $existingFunctionPath = Join-Path $fixtureFunctionsPath 'Get-ExistingWidget.ps1'
                $newFunctionPath = Join-Path $fixtureFunctionsPath 'Get-NewWidget.ps1'

                $null = New-Item -Path $fixtureBuildPath -ItemType Directory -Force
                $null = New-Item -Path $fixtureFunctionsPath -ItemType Directory -Force
                $null = New-Item -Path (Split-Path -Parent $fixtureJsonPath) -ItemType Directory -Force
                $null = New-Item -Path (Split-Path -Parent $fixtureFirefoxJsonPath) -ItemType Directory -Force

                Copy-Item -Path $sourceScriptPath -Destination (Join-Path $fixtureBuildPath 'Sync-CmdletDocumentation.ps1')

                Set-Content -Path $fixtureReadmePath -Value @'
## Available Cmdlets

| Cmdlet | Description |
|--------|-------------|
| Get-ExistingWidget | Gets existing widgets. |

## Next Section
'@ -Encoding utf8

                Set-Content -Path $fixtureManifestPath -Value @'
@{
        FunctionsToExport = @(
                "Get-ExistingWidget"
        )
}
'@ -Encoding utf8

                Set-Content -Path $fixtureJsonPath -Value @'
[
    {
        "Cmdlet": "Get-ExistingWidget",
        "ApiUri": "https://security.microsoft.com/api/existingWidgets/{WidgetId}",
        "Parameters": {
            "WidgetId": "WidgetId"
        }
    }
]
'@ -Encoding utf8
                Set-Content -Path $fixtureFirefoxJsonPath -Value @'
[
    {
        "Cmdlet": "Get-ExistingWidget",
        "ApiUri": "https://security.microsoft.com/api/existingWidgets/{WidgetId}",
        "Parameters": {
            "WidgetId": "WidgetId"
        }
    }
]
'@ -Encoding utf8

                Set-Content -Path $existingFunctionPath -Value @'
<#
.SYNOPSIS
Gets existing widgets.
#>
function Get-ExistingWidget {
        [CmdletBinding()]
        param(
                [string]$WidgetId
        )

        $Uri = "https://security.microsoft.com/api/existingWidgets/$WidgetId"
        Invoke-RestMethod -Uri $Uri -Method Get
}
'@ -Encoding utf8

                Set-Content -Path $newFunctionPath -Value @'
<#
.SYNOPSIS
Gets new widgets.
#>
function Get-NewWidget {
        [CmdletBinding()]
        param(
                [string]$WidgetId
        )

        $Uri = "https://security.microsoft.com/api/newWidgets/$WidgetId"
        Invoke-RestMethod -Uri $Uri -Method Get
}
'@ -Encoding utf8

                & (Join-Path $fixtureBuildPath 'Sync-CmdletDocumentation.ps1')

                $manifestContent = Get-Content -Path $fixtureManifestPath -Raw
                $apiMappings = @(Get-Content -Path $fixtureJsonPath -Raw | ConvertFrom-Json)
                $firefoxApiMappings = @(Get-Content -Path $fixtureFirefoxJsonPath -Raw | ConvertFrom-Json)
                $readmeContent = Get-Content -Path $fixtureReadmePath -Raw

                $manifestContent | Should -Match '"Get-ExistingWidget"'
                $manifestContent | Should -Match '"Get-NewWidget"'
                $readmeContent | Should -Match '\| Get-ExistingWidget\s+\| Gets existing widgets\.'
                $readmeContent | Should -Match '\| Get-NewWidget\s+\| Gets new widgets\.'
                $apiMappings.Cmdlet | Should -Contain 'Get-ExistingWidget'
                $apiMappings.Cmdlet | Should -Contain 'Get-NewWidget'
                $firefoxApiMappings.Cmdlet | Should -Contain 'Get-ExistingWidget'
                $firefoxApiMappings.Cmdlet | Should -Contain 'Get-NewWidget'

                @($apiMappings | Where-Object Cmdlet -eq 'Get-NewWidget').Count | Should -Be 1
                @($firefoxApiMappings | Where-Object Cmdlet -eq 'Get-NewWidget').Count | Should -Be 1
                @($apiMappings | Where-Object Cmdlet -eq 'Get-NewWidget')[0].ApiUri | Should -Be 'https://security.microsoft.com/api/newWidgets/{WidgetId}'
                @($firefoxApiMappings | Where-Object Cmdlet -eq 'Get-NewWidget')[0].ApiUri | Should -Be 'https://security.microsoft.com/api/newWidgets/{WidgetId}'
        }
}