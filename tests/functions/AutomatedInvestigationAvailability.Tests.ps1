Describe 'Legacy automated investigation route availability' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{}
        }
        $global:__pester_data.LegacyCalls = 0
    }

    It 'preserves successful <Kind> results and cache writes' -ForEach @(
        @{ Kind = 'Advanced' }; @{ Kind = 'MemoryContent' }; @{ Kind = 'Folder' }
    ) {
        $global:__pester_data.LegacyResult = [pscustomobject]@{ data = [pscustomobject]@{ cloud_upload = $true }; count = 1; results = @([pscustomobject]@{ id = 'legacy' }) }
        Mock Invoke-RestMethod { $global:__pester_data.LegacyResult } -ModuleName XDRInternals
        $result = if ($Kind -eq 'Advanced') { Get-XdrEndpointConfigurationAutomatedInvestigation -Force } else { Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type $Kind -Force }
        [object]::ReferenceEquals($result, $global:__pester_data.LegacyResult) | Should -BeTrue
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Exactly -Times 1 -ParameterFilter {
            $TTLMinutes -eq 30 -and [object]::ReferenceEquals($Value, $global:__pester_data.LegacyResult)
        }
        Mock Get-XdrCache { [pscustomobject]@{ NotValidAfter = (Get-Date).AddMinutes(5); Value = $global:__pester_data.LegacyResult } } -ModuleName XDRInternals
        $cached = if ($Kind -eq 'Advanced') { Get-XdrEndpointConfigurationAutomatedInvestigation } else { Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type $Kind }
        [object]::ReferenceEquals($cached, $result) | Should -BeTrue
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Exactly -Times 1
    }

    It 'reports sanitized unavailable for <Kind> HTTP 410 at <Stage> without partial success' -ForEach @(
        @{ Kind = 'Advanced'; Stage = 'initial' }
        foreach ($kind in @('MemoryContent', 'Folder')) {
            foreach ($stage in @('initial', 'continuation')) { @{ Kind = $kind; Stage = $stage } }
        }
    ) {
        $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Gone)
        $response.Content = [System.Net.Http.StringContent]::new('secret-provider-body')
        $response.Headers.Add('X-Secret', 'secret-provider-header')
        $exception = [Microsoft.PowerShell.Commands.HttpResponseException]::new('secret-provider-exception', $response)
        $global:__pester_data.LegacyError = [System.Management.Automation.ErrorRecord]::new($exception, 'ProviderFailure', [System.Management.Automation.ErrorCategory]::InvalidOperation, 'secret-provider-target')
        $global:__pester_data.LegacyError.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('secret-provider-details')
        $global:__pester_data.LegacyStage = $Stage
        Mock Invoke-RestMethod {
            $global:__pester_data.LegacyCalls++
            if ($global:__pester_data.LegacyStage -eq 'initial' -or $global:__pester_data.LegacyCalls -eq 2) { throw $global:__pester_data.LegacyError }
            [pscustomobject]@{ count = 2; results = @([pscustomobject]@{ id = 'partial' }); next = '?scroll=secret-continuation' }
        } -ModuleName XDRInternals
        $captured = $null
        $result = @()
        try {
            $result = @(if ($Kind -eq 'Advanced') { Get-XdrEndpointConfigurationAutomatedInvestigation -Force -ErrorAction Stop }
                else { Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type $Kind -Force -ErrorAction Stop })
        } catch { $captured = $_ }
        $result | Should -HaveCount 0
        $expectedId = if ($Kind -eq 'Advanced') { 'XdrEndpointAutomatedInvestigationUnavailable' } else { 'XdrEndpointAutomatedInvestigationExclusionUnavailable' }
        $captured.FullyQualifiedErrorId | Should -BeLike "$expectedId,*"
        $captured.CategoryInfo.Category | Should -Be 'NotImplemented'
        $captured.TargetObject.Type | Should -Be $Kind
        $captured.TargetObject.StatusCode | Should -Be 410
        $expectedRoute = switch ($Kind) { Advanced { '/apiproxy/mtp/autoIr/ui/admin/advanced' }; Folder { '/apiproxy/mtp/autoIr/folder_exclusion/all' }; MemoryContent { '/apiproxy/mtp/autoIr/acl/all' } }
        $captured.TargetObject.Route | Should -Be $expectedRoute
        ($captured | Format-List * -Force | Out-String) | Should -Not -Match 'secret-'
        $captured.Exception.InnerException | Should -BeNullOrEmpty
        $captured.ErrorDetails | Should -BeNullOrEmpty
        $expectedCalls = if ($Stage -eq 'initial') { 1 } else { 2 }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Exactly -Times $expectedCalls
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Exactly -Times 0
    }

    It 'preserves typed HTTP <Status> errors for <Kind> at <Stage>' -ForEach @(
        foreach ($kind in @('Advanced', 'MemoryContent', 'Folder')) {
            foreach ($status in @(401, 403, 404, 500)) {
                foreach ($stage in $(if ($kind -eq 'Advanced') { @('initial') } else { @('initial', 'continuation') })) {
                    @{ Kind = $kind; Status = $status; Stage = $stage }
                }
            }
        }
    ) {
        $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$Status)
        $global:__pester_data.LegacyException = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Provider failed', $response)
        $global:__pester_data.LegacyStage = $Stage
        Mock Invoke-RestMethod {
            $global:__pester_data.LegacyCalls++
            if ($global:__pester_data.LegacyStage -eq 'initial' -or $global:__pester_data.LegacyCalls -eq 2) { throw $global:__pester_data.LegacyException }
            [pscustomobject]@{ count = 2; results = @([pscustomobject]@{ id = 'partial' }); next = '?scroll=synthetic' }
        } -ModuleName XDRInternals
        $captured = try {
            if ($Kind -eq 'Advanced') { Get-XdrEndpointConfigurationAutomatedInvestigation -ErrorAction Stop }
            else { Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type $Kind -ErrorAction Stop }
        } catch { $_ }
        $captured.Exception.Response.StatusCode | Should -Be $Status
        [object]::ReferenceEquals($captured.Exception, $global:__pester_data.LegacyException) | Should -BeTrue
        $captured.FullyQualifiedErrorId | Should -Not -BeLike '*Unavailable*'
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Exactly -Times 0
    }

    It 'does not classify untyped text mentioning 410 for <Kind>' -ForEach @(
        @{ Kind = 'Advanced' }; @{ Kind = 'MemoryContent' }; @{ Kind = 'Folder' }
    ) {
        Mock Invoke-RestMethod { throw 'Synthetic failure mentioning HTTP 410' } -ModuleName XDRInternals
        $captured = try {
            if ($Kind -eq 'Advanced') { Get-XdrEndpointConfigurationAutomatedInvestigation -ErrorAction Stop }
            else { Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type $Kind -ErrorAction Stop }
        } catch { $_ }
        $captured.FullyQualifiedErrorId | Should -Not -BeLike '*Unavailable*'
        $captured.CategoryInfo.Category | Should -Not -Be 'NotImplemented'
        $captured.Exception.Message | Should -BeLike '*mentioning HTTP 410*'
    }

    It 'keeps Folder independent after MemoryContent is unavailable' {
        Mock Invoke-RestMethod {
            if ($Uri -like '*acl/all*') {
                $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Gone)
                throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Gone', $response)
            }
            [pscustomobject]@{ count = 1; results = @([pscustomobject]@{ folder = 'synthetic-folder' }) }
        } -ModuleName XDRInternals
        { Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type MemoryContent -ErrorAction Stop } | Should -Throw -ErrorId 'XdrEndpointAutomatedInvestigationExclusionUnavailable,*'
        (Get-XdrEndpointConfigurationAutomatedInvestigationExclusion -Type Folder).results.folder | Should -Be 'synthetic-folder'
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Exactly -Times 1 -ParameterFilter { $CacheKey -eq 'GetXdrEndpointConfigurationAutomatedInvestigationExclusionFolder' }
    }
}
