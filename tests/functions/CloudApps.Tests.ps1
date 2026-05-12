Describe 'Cloud Apps grouped command surface' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Invoke-XdrCloudAppsRequest { [pscustomobject]@{ ok = $true; path = $Path; body = $Body } } -ModuleName XDRInternals
        Mock Get-XdrCloudAppsDiscoveryStream {
            [pscustomobject]@{
                _id         = 'stream-1'
                displayName = 'Test stream'
            }
        } -ModuleName XDRInternals
    }

    It 'does not expose the misspelled Agressive timeline parameter alias' {
        $command = Get-Command Get-XdrCloudAppsActivityTimeline

        $command.Parameters.ContainsKey('Aggressive') | Should -BeTrue
        $command.Parameters.ContainsKey('Agressive') | Should -BeFalse
        $command.Parameters.ContainsKey('ExportFormat') | Should -BeTrue
    }

    It 'keeps only live-validated app type choices public' {
        $typeParameter = (Get-Command Get-XdrCloudAppsApp).Parameters['Type']
        $validValues = $typeParameter.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            Select-Object -ExpandProperty ValidValues

        $validValues | Should -Contain 'Discovered'
        $validValues | Should -Contain 'OAuth'
        $validValues | Should -Not -Contain 'AiAgent'
        $validValues | Should -Not -Contain 'ConnectedService'
    }

    It 'routes app catalog metadata through the grouped app command' {
        Get-XdrCloudAppsApp -Type Catalog -Metadata

        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/discovery/app_catalog/metadata/' -and
            $TypeName -eq 'XdrCloudAppsAppCatalogMetadata'
        }
    }

    It 'routes discovered app queries through discovery stream context' {
        Get-XdrCloudAppsApp -Type Discovered -StreamName 'Test*' -Limit 25

        Should -Invoke Get-XdrCloudAppsDiscoveryStream -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $StreamName -eq 'Test*'
        }
        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/discovery/discovered_apps/' -and
            $Method -eq 'Post' -and
            $Body.streamId -eq 'stream-1' -and
            $Body.limit -eq 25
        }
    }

    It 'keeps the legacy general settings wrapper routed through grouped configuration' {
        Mock Get-XdrCloudAppsConfiguration {
            $result = [pscustomobject]@{
                environmentName = 'Commercial'
                orgDisplayName  = 'Contoso'
            }
            $result.PSObject.TypeNames.Insert(0, 'XdrCloudAppsConfigurationSettings')
            $result
        } -ModuleName XDRInternals

        $result = Get-XdrCloudAppsGeneralSetting -Force

        $result.environmentName | Should -Be 'Commercial'
        $result.orgDisplayName | Should -Be 'Contoso'
        $result.PSObject.TypeNames | Should -Not -Contain 'XdrCloudAppsConfigurationSettings'
        Should -Invoke Get-XdrCloudAppsConfiguration -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Type -eq 'Settings' -and
            $Force
        }
    }

    It 'returns discovery streams from the dedicated parameter set' {
        $result = Get-XdrCloudAppsDiscovery -ListStreams

        $result._id | Should -Be 'stream-1'
        Should -Invoke Get-XdrCloudAppsDiscoveryStream -ModuleName XDRInternals -Times 1 -Exactly
    }

    It 'keeps the default discovery parameter set working for category queries' {
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{
                data = @([pscustomobject]@{ categoryName = 'Storage' })
            }
        } -ModuleName XDRInternals

        $result = Get-XdrCloudAppsDiscovery -Type Category

        $result[0].categoryName | Should -Be 'Storage'
        $result[0].PSObject.TypeNames[0] | Should -Be 'XdrCloudAppsDiscoveryCategory'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://security.microsoft.com/apiproxy/mcas/cas/api/v1/discovery/categories/' -and
            $Method -eq 'Get'
        }
    }

    It 'still requires EntityType for default discovery entity queries' {
        { Get-XdrCloudAppsDiscovery -Type Entity } |
            Should -Throw -ExpectedMessage "*The -EntityType parameter is required when -Type is 'Entity'*"
    }

    It 'routes Cloud Discovery user deanonymization through the grouped discovery command' {
        Get-XdrCloudAppsDiscovery -DeanonymizeUser -Usernames 'User_aaaaaabbbbb=' -Justification 'Incident response' | Out-Null

        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/discovery/deanonymize_entity_names/' -and
            $Method -eq 'Post' -and
            $Body.justification -eq 'Incident response' -and
            $Body.entityType -eq 1 -and
            $Body.usernames.Count -eq 1 -and
            $Body.usernames[0] -eq 'User_aaaaaabbbbb='
        }
    }

    It 'aggregates piped usernames for grouped Cloud Discovery deanonymization' {
        'User_aaaaaabbbbb=', 'User_zzzzzzzzXXXXXXX=' | Get-XdrCloudAppsDiscovery -DeanonymizeUser -Justification 'Incident response' | Out-Null

        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/discovery/deanonymize_entity_names/' -and
            $Body.usernames.Count -eq 2 -and
            $Body.usernames[0] -eq 'User_aaaaaabbbbb=' -and
            $Body.usernames[1] -eq 'User_zzzzzzzzXXXXXXX='
        }
    }

    It 'routes governance summary through App Governance status APIs' {
        Mock Invoke-XdrCloudAppsRequest {
            switch -Wildcard ($Path) {
                '*istenantonboarded' { $true }
                '*istenantinsightsready' { $true }
                '*tenantmetrics' { [pscustomobject]@{ numberOfApps = 10; numberOfHighPrivilegedApps = 2; numberOfOverPermissionedApps = 1; numberOfUnusedApps = 3; numberOfRiskyApps = 4 } }
            }
        } -ModuleName XDRInternals

        $result = Get-XdrCloudAppsGovernance

        $result.TotalApps | Should -Be 10
        $result.HighPrivilegeApps | Should -Be 2
        $result.IsOnboarded | Should -BeTrue
    }

    It 'reports File policy metadata as unsupported by the live Cloud Apps API' {
        { Get-XdrCloudAppsPolicy -Type File -Metadata } |
            Should -Throw -ExpectedMessage '*File policy metadata is not exposed by the live Cloud Apps API*'
    }

    It 'adds the File policy type filter without mutating caller filters' {
        $filters = @{ enabled = @{ eq = @($true) } }
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { [pscustomobject]@{ data = @([pscustomobject]@{ name = 'File policy' }) } } -ModuleName XDRInternals

        Get-XdrCloudAppsPolicy -Type File -Filters $filters | Out-Null

        $filters.ContainsKey('type') | Should -BeFalse
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            ($Body | ConvertFrom-Json).filters.type.eq[0] -eq 'FILE'
        }
    }

    It 'applies typed policy names when the API returns a single policy object' {
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            [pscustomobject]@{
                data = [pscustomobject]@{ name = 'Shadow IT policy' }
            }
        } -ModuleName XDRInternals

        $result = Get-XdrCloudAppsPolicy -Type ShadowIT -Force

        $result.name | Should -Be 'Shadow IT policy'
        $result.PSObject.TypeNames[0] | Should -Be 'XdrCloudAppsPolicyShadowIT'
    }

    It 'splits mixed recent and archived count-only timeline requests' {
        $from = [datetime]::UtcNow.AddDays(-35)
        $to = [datetime]::UtcNow.AddDays(-1)

        Get-XdrCloudAppsActivityTimeline -CountOnly -FromDate $from -ToDate $to

        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/archived_activities/count/'
        }
        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/activities/count/'
        }
    }

    It 'skips unreadable activity chunk files when partial data is allowed' {
        $chunkPath = Join-Path $TestDrive 'chunk_bad.json'
        Set-Content -Path $chunkPath -Value '{"Events":[{"_id":"activity-1"}' -Encoding UTF8

        InModuleScope -ModuleName XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            $result = Read-XdrCloudAppsActivityChunkFile -File (Get-Item -Path $ChunkPath) -AllowPartial -WarningAction SilentlyContinue

            $result | Should -BeNullOrEmpty
        }
    }

    It 'reads activity chunk files that contain keys differing only by case' {
        $chunkPath = Join-Path $TestDrive 'chunk_case_keys.json'
        Set-Content -Path $chunkPath -Value '{"Events":[{"_id":"activity-1","timestamp":1710000000000,"level":"low","Level":"High"}],"EventCount":1}' -Encoding UTF8

        InModuleScope -ModuleName XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            $result = Read-XdrCloudAppsActivityChunkFile -File (Get-Item -Path $ChunkPath)
            $activity = @(Get-XdrCloudAppsObjectValue -InputObject $result -Name 'Events')[0]

            (Get-XdrCloudAppsObjectValue -InputObject $activity -Name 'level') | Should -Be 'low'
            (Get-XdrCloudAppsObjectValue -InputObject $activity -Name 'Level') | Should -Be 'High'
            (Get-XdrCloudAppsActivityEventTime -Activity $activity).Kind | Should -Be ([DateTimeKind]::Utc)
        }
    }

    It 'throws unreadable activity chunk errors when partial data is not allowed' {
        $chunkPath = Join-Path $TestDrive 'chunk_bad_strict.json'
        Set-Content -Path $chunkPath -Value '{"Events":[{"_id":"activity-1"}' -Encoding UTF8

        InModuleScope -ModuleName XDRInternals -Parameters @{ ChunkPath = $chunkPath } {
            param($ChunkPath)

            { Read-XdrCloudAppsActivityChunkFile -File (Get-Item -Path $ChunkPath) } |
                Should -Throw -ExpectedMessage '*Conversion from JSON failed*'
        }
    }

    It 'routes discovered app note updates through the write cmdlet' {
        Set-XdrCloudAppsDiscoveredApp -AppId '12345' -Note 'Approved' -Confirm:$false | Out-Null

        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 1 -Exactly -ParameterFilter {
            $Path -eq '/mcas/cas/api/v1/discovery/discovery_app/update_app_note/' -and
            $Method -eq 'Post' -and
            $Body.pk -eq '12345' -and
            $Body.note -eq 'Approved'
        }
    }

    It 'honors WhatIf for discovered app note updates' {
        Set-XdrCloudAppsDiscoveredApp -AppId '12345' -Note 'Approved' -WhatIf

        Should -Invoke Invoke-XdrCloudAppsRequest -ModuleName XDRInternals -Times 0 -Exactly
    }
}

Describe 'Invoke-XdrCloudAppsRequest' {
    BeforeEach {
        $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
        $script:headers = @{}
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { [pscustomobject]@{ data = @([pscustomobject]@{ name = 'Item1' }) } } -ModuleName XDRInternals
    }

    It 'unwraps data arrays and applies the requested type name' {
        InModuleScope XDRInternals {
            $result = Invoke-XdrCloudAppsRequest -Path '/mcas/test' -TypeName 'XdrCloudAppsTest'

            $result.name | Should -Be 'Item1'
            $result.PSObject.TypeNames[0] | Should -Be 'XdrCloudAppsTest'
        }
    }

    It 'emits compact Cloud Apps request errors without portal HTML' {
        Mock Invoke-RestMethod {
            $exception = [System.Exception]::new('Response status code does not indicate success: 404 (Not Found).')
            $errorRecord = [System.Management.Automation.ErrorRecord]::new($exception, 'NotFound', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)
            $errorRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('var __ADALLOM_CONSTS = {};404Page not found')
            throw $errorRecord
        } -ModuleName XDRInternals

        InModuleScope XDRInternals {
            { Invoke-XdrCloudAppsRequest -Path '/mcas/missing' } |
                Should -Throw -ExpectedMessage '*Cloud Apps request failed: Get https://security.microsoft.com/apiproxy/mcas/missing returned request failure. The service returned an HTML portal error page.*'
        }
    }
}
