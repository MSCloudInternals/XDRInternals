$helperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
. $helperPath

$reportCases = InModuleScope XDRInternals {
    Get-XdrReportCatalog | Where-Object { -not $_.Binary } | ForEach-Object {
        $query = @{}
        foreach ($key in $_.RequiredParameters) { $query[$key] = 'example.org' }
        @{ Name = $_.Name; Path = $_.Path; Method = $_.Method; Query = $query }
    }
}

Describe 'Discovered report catalog' -Tag 'Functions', 'Reports' {
    BeforeEach {
        InModuleScope XDRInternals { $script:headers = @{ 'x-tid' = '00000000-0000-0000-0000-000000000001' } }
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { [pscustomobject]@{ sample = 'report' } } -ModuleName XDRInternals
    }

    It 'requests <Name> using its discovered endpoint' -ForEach $reportCases {
        $expectedMethod = $Method
        (Get-XdrReport -Name $Name -Parameters $Query).sample | Should -Be 'report'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            ([uri]$Uri).AbsolutePath -eq $Path -and $Method -eq $expectedMethod
        }
    }

    It 'rejects unknown report names and query parameters before connecting' {
        { Get-XdrReport -Name 'Missing' } | Should -Throw '*Unknown report*'
        { Get-XdrReport -Name 'Hunting.Quota' -Parameters @{ unexpected = 'value' } } | Should -Throw '*Unknown query*'
        Should -Invoke Update-XdrConnectionSettings -ModuleName XDRInternals -Times 0
    }

    It 'discovers report definitions offline with name and family filters' {
        @(Get-XdrReportDefinition -Family 'Cloud').Count | Should -Be 44
        @(Get-XdrReportDefinition -Name @('Identity.*.Download', 'Missing') -Family 'Identity').Count | Should -Be 4
        @(Get-XdrReportDefinition -Name 'Missing').Count | Should -Be 0
        Should -Invoke Update-XdrConnectionSettings -ModuleName XDRInternals -Times 0
    }

    It 'encodes query overrides without allowing query injection' {
        $null = Get-XdrReport -Name 'Hunting.Quota' -Parameters @{ aggregationType = 'Average&unexpected=true' }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Uri -like '*aggregationType=Average%26unexpected%3Dtrue*'
        }
    }

    It 'uses the captured TVM API version without modifying session headers' {
        $null = Get-XdrReport -Name 'AntivirusHealth.avsignature'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Headers['api-version'] -eq '1.0'
        }
        InModuleScope XDRInternals { $script:headers.ContainsKey('api-version') | Should -BeFalse }
    }

    It 'uses the observed Data Insights search content type with a JSON body' {
        $null = Get-XdrReport -Name 'Email.AdminSubmissions.Detail'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $ContentType -eq 'multipart/form-data' -and ($Body | ConvertFrom-Json).QueryFilter.Filter.Value -eq 2
        }
    }

    It 'requests Cloud chart rows with the observed schema and numeric paging size' {
        $null = Get-XdrReport -Name 'Cloud.CoverageByPlan' -Top 25
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Body -and ($Body | ConvertFrom-Json).schemaId -eq 'dashboardsAndReports_CoverageByPlan' -and
            ($Body | ConvertFrom-Json).paging.pageSize -eq 25 -and ($Body | ConvertFrom-Json).paging.pageSize -is [long] -and
            ($Body | ConvertFrom-Json).filters.Count -eq 0
        }
    }

    It 'uses the correct secure-score route and preserves Cloud metric dimensions' {
        $null = Get-XdrReport -Name 'Cloud.SecureScoreByWorkload'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter { ([uri]$Uri).AbsolutePath -eq '/apiproxy/mdc/views/secureScore/items' }
        $null = Get-XdrReport -Name 'Cloud.SecureScore.Compute.Trend' -FromDate '2026-09-01T00:00:00Z'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            ([uri]$Uri).AbsolutePath -eq '/apiproxy/mdc/views/dashboards/overtimeData' -and $Body -and
            ($Body | ConvertFrom-Json).metricsProperties[0].requestOption -eq 'All' -and
            ($Body | ConvertFrom-Json).metricsProperties[0].dimensionsFilters[0].value -eq 'compute' -and
            $Body.Contains('"startDateTime":"2026-09-01T00:00:00.000Z"')
        }
    }

    It 'rejects missing required drilldown targets before connecting' {
        { Get-XdrReport -Name 'WebThreat.urls' } | Should -Throw '*id*required*'
        Should -Invoke Update-XdrConnectionSettings -ModuleName XDRInternals -Times 0
    }

    It 'rejects invalid dates and invalid body or file combinations before connecting' {
        { Get-XdrReport -Name 'Hunting.Quota' -FromDate '2026-09-30' -ToDate '2026-09-01' } | Should -Throw '*FromDate*'
        { Get-XdrReport -Name 'Hunting.Quota' -Body @{} } | Should -Throw '*Body*'
        { Get-XdrReport -Name 'Hunting.Quota' -OutFile 'report.zip' } | Should -Throw '*OutFile*'
        { Get-XdrReport -Name 'Identity.Summary.Download' } | Should -Throw '*OutFile*'
        { Get-XdrReport -Name 'Identity.Summary.Download' -OutFile 'report.zip' -All } | Should -Throw '*All*'
        Should -Invoke Update-XdrConnectionSettings -ModuleName XDRInternals -Times 0
    }

    It 'substitutes dates, tenant, and numeric body tokens' {
        $null = Get-XdrReport -Name 'Email.MailLatencyData' -FromDate '2026-09-01T00:00:00Z' -ToDate '2026-09-02T00:00:00Z'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Uri -like '*StartTime=2026-09-01T00%3A00%3A00.000Z*' -and $Uri -like '*tenantid=00000000-0000-0000-0000-000000000001*'
        }
        $null = Get-XdrReport -Name 'Hunting.UserHistory' -Top 10
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Body -and ($Body | ConvertFrom-Json).maxResults -eq 10 -and ($Body | ConvertFrom-Json).maxResults -is [long]
        }
    }

    It 'allows an explicit empty JSON body without restoring the default' {
        $null = Get-XdrReport -Name 'Hunting.QueryResources' -Body @{}
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter { $Body -eq '{}' }
    }

    It 'keeps default date request URIs stable within a cache interval' {
        Mock Get-Date { [datetime]'2026-09-30T12:17:23Z' } -ModuleName XDRInternals
        $null = Get-XdrReport -Name 'Hunting.Quota'
        $null = Get-XdrReport -Name 'Hunting.Quota'
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2 -ParameterFilter {
            $Uri -like '*endTime=2026-09-30T12%3A00%3A00.000Z*'
        }
    }

    It 'validates Identity exports before attempting a binary download' {
        Mock Invoke-XdrReportRequest { [pscustomobject]@{ Result = 'Success' } } -ModuleName XDRInternals -ParameterFilter { $Uri -like '*validate*' }
        Mock Invoke-XdrReportRequest { [pscustomobject]@{ Length = 3 } } -ModuleName XDRInternals -ParameterFilter { $OutFile }
        (Get-XdrReport -Name 'Identity.Summary.Download' -OutFile 'report.zip').Length | Should -Be 3
        Should -Invoke Invoke-XdrReportRequest -ModuleName XDRInternals -Times 1 -ParameterFilter { $Uri -like '*validate*' -and $Uri -notlike '*localeId*' }
        Should -Invoke Invoke-XdrReportRequest -ModuleName XDRInternals -Times 1 -ParameterFilter { $OutFile -eq 'report.zip' }
    }

    It 'reports unavailable Identity exports without downloading' -ForEach @(
        @{ State = 'NoResults' }
        @{ State = 'TooManyResults' }
    ) {
        Mock Invoke-XdrReportRequest { [pscustomobject]@{ Result = $State } } -ModuleName XDRInternals
        { Get-XdrReport -Name 'Identity.Summary.Download' -OutFile 'report.zip' } | Should -Throw "*cannot be downloaded: $State*"
        Should -Invoke Invoke-XdrReportRequest -ModuleName XDRInternals -Times 0 -ParameterFilter { $OutFile }
    }
}

Describe 'Shared report request handling' -Tag 'Functions', 'Reports' {
    BeforeEach {
        InModuleScope XDRInternals {
            $script:session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
            $script:headers = @{ 'x-tid' = '00000000-0000-0000-0000-000000000001' }
        }
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { [pscustomobject]@{ value = @('sample') } } -ModuleName XDRInternals
    }

    It 'preserves report envelopes' {
        InModuleScope XDRInternals {
            $result = Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data'
            $result.value[0] | Should -Be 'sample'
        }
    }

    It 'rejects external endpoints before sending credentials' {
        InModuleScope XDRInternals {
            { Invoke-XdrReportRequest -Uri 'https://example.com/apiproxy/report/data' } | Should -Throw '*Defender portal*'
        }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0
    }

    It 'preserves structured request errors' {
        Mock Invoke-RestMethod { throw 'Read failed' } -ModuleName XDRInternals
        InModuleScope XDRInternals {
            { Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' } | Should -Throw '*Read failed*'
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0
    }

    It 'returns valid cached data and refreshes expired or forced reads' {
        Mock Get-XdrCache { [pscustomobject]@{ NotValidAfter = (Get-Date).AddMinutes(10); Value = 'cached' } } -ModuleName XDRInternals
        InModuleScope XDRInternals {
            Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' | Should -Be 'cached'
        }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0
        InModuleScope XDRInternals { $null = Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' -Force }
        Should -Invoke Clear-XdrCache -ModuleName XDRInternals -Times 1
        Mock Get-XdrCache { [pscustomobject]@{ NotValidAfter = (Get-Date).AddMinutes(-1); Value = 'expired' } } -ModuleName XDRInternals
        InModuleScope XDRInternals { $null = Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2
    }

    It 'separates cache keys by query, method, body, pagination, and tenant' {
        InModuleScope XDRInternals {
            $script:reportCacheKeys = [System.Collections.Generic.List[string]]::new()
            Mock Set-XdrCache { $script:reportCacheKeys.Add($CacheKey) }
            $Uri = 'https://security.microsoft.com/apiproxy/report/data'
            $null = Invoke-XdrReportRequest -Uri $Uri
            $null = Invoke-XdrReportRequest -Uri "${Uri}?filter=other"
            $null = Invoke-XdrReportRequest -Uri $Uri -Method Post
            $null = Invoke-XdrReportRequest -Uri $Uri -Body '{"filter":"other"}'
            $null = Invoke-XdrReportRequest -Uri $Uri -All
            $script:headers['x-tid'] = '00000000-0000-0000-0000-000000000002'
            $null = Invoke-XdrReportRequest -Uri $Uri
            @($script:reportCacheKeys | Select-Object -Unique).Count | Should -Be 6
        }
    }

    It 'isolates authenticated sessions and scopes without invalidating on XSRF rotation' {
        InModuleScope XDRInternals {
            $script:reportCacheKeys = [System.Collections.Generic.List[string]]::new()
            Mock Set-XdrCache { $script:reportCacheKeys.Add($CacheKey) }
            $Uri = 'https://security.microsoft.com/apiproxy/report/data'
            $script:session.Cookies.Add([System.Net.Cookie]::new('sccauth', 'first-session', '/', 'security.microsoft.com'))
            $null = Invoke-XdrReportRequest -Uri $Uri
            $script:session.Cookies.Add([System.Net.Cookie]::new('sccauth', 'second-session', '/', 'security.microsoft.com'))
            $null = Invoke-XdrReportRequest -Uri $Uri
            $script:headers['m-native-scopes'] = '["scope-a"]'
            $null = Invoke-XdrReportRequest -Uri $Uri
            $script:headers['m-scopes'] = '["scope-b"]'
            $null = Invoke-XdrReportRequest -Uri $Uri
            $script:headers['X-XSRF-TOKEN'] = 'rotated-token'
            $null = Invoke-XdrReportRequest -Uri $Uri
            @($script:reportCacheKeys | Select-Object -Unique).Count | Should -Be 4
            $script:reportCacheKeys[3] | Should -Be $script:reportCacheKeys[4]
        }
    }

    It 'follows safe relative OData links while preserving envelopes' {
        Mock Invoke-RestMethod {
            if ($Uri -like '*page=2') { [pscustomobject]@{ value = @('second') } } else {
                [pscustomobject]@{ value = @('first'); '@odata.nextLink' = '?page=2' }
            }
        } -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $pages = @(Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' -All)
            $pages.Count | Should -Be 2
            $pages[0].value[0] | Should -Be 'first'
            $pages[1].value[0] | Should -Be 'second'
        }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 2
    }

    It 'resolves relative continuations against the page that returned them' {
        Mock Invoke-RestMethod {
            switch (([uri]$Uri).AbsolutePath) {
                '/apiproxy/report/data' { [pscustomobject]@{ value = @('first'); '@odata.nextLink' = '/apiproxy/report/pages/second' } }
                '/apiproxy/report/pages/second' { [pscustomobject]@{ value = @('second'); '@odata.nextLink' = 'third' } }
                '/apiproxy/report/pages/third' { [pscustomobject]@{ value = @('third') } }
                default { throw 'Unexpected continuation path' }
            }
        } -ModuleName XDRInternals
        InModuleScope XDRInternals {
            $pages = @(Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' -All)
            $pages.Count | Should -Be 3
            $pages[2].value[0] | Should -Be 'third'
        }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 3
    }

    It 'follows Device Control continuation headers without changing session headers' {
        Mock Invoke-RestMethod {
            if ($Headers['Continuation-Token']) { [pscustomobject]@{ currentPage = @('second'); morePagesAvailable = $false } } else {
                [pscustomobject]@{ currentPage = @('first'); morePagesAvailable = $true; pagingContext = 'next-page' }
            }
        } -ModuleName XDRInternals
        InModuleScope XDRInternals {
            @(Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' -All).Count | Should -Be 2
            $script:headers.ContainsKey('Continuation-Token') | Should -BeFalse
        }
    }

    It 'rejects unsafe, repeated, or missing continuations without caching partial results' -ForEach @(
        @{ Response = @{ '@odata.nextLink' = 'https://example.com/apiproxy/report/data' }; Error = '*unsafe*' }
        @{ Response = @{ '@odata.nextLink' = 'https://security.microsoft.com/apiproxy/report/data' }; Error = '*repeated*' }
        @{ Response = @{ morePagesAvailable = $true; pagingContext = '' }; Error = '*no continuation*' }
    ) {
        Mock Invoke-RestMethod { [pscustomobject]$Response } -ModuleName XDRInternals
        InModuleScope XDRInternals -Parameters @{ ExpectedError = $Error } {
            { Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' -All } | Should -Throw $ExpectedError
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0
    }

    It 'downloads binary reports without caching them' {
        Mock Invoke-WebRequest { [IO.File]::WriteAllBytes($OutFile, [byte[]]@(1, 2, 3)) } -ModuleName XDRInternals
        InModuleScope XDRInternals -Parameters @{ Destination = (Join-Path $TestDrive 'report.bin') } {
            (Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' -OutFile $Destination).Length | Should -Be 3
        }
        Should -Invoke Get-XdrCache -ModuleName XDRInternals -Times 0
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0
    }

    It 'refuses to overwrite existing download files' {
        Mock Invoke-WebRequest {} -ModuleName XDRInternals
        $destination = Join-Path $TestDrive 'existing.bin'
        [IO.File]::WriteAllBytes($destination, [byte[]]@(1))
        InModuleScope XDRInternals -Parameters @{ Destination = $destination } {
            { Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' -OutFile $Destination } | Should -Throw '*already exists*'
        }
        Should -Invoke Invoke-WebRequest -ModuleName XDRInternals -Times 0
    }

    It 'preserves a competing destination and cleans only its own download' -ForEach @(
        @{ RequestFails = $false }
        @{ RequestFails = $true }
    ) {
        InModuleScope XDRInternals -Parameters @{ Destination = (Join-Path $TestDrive 'competing.bin'); RequestFails = $RequestFails } {
            $script:reportRaceDestination = $Destination
            $script:reportRaceFails = $RequestFails
            Mock Invoke-WebRequest {
                [IO.File]::WriteAllBytes($script:reportRaceDestination, [byte[]]@(9))
                [IO.File]::WriteAllBytes($OutFile, [byte[]]@(1, 2, 3))
                if ($script:reportRaceFails) { throw 'Download failed' }
            }
            { Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' -OutFile $Destination } | Should -Throw
            [IO.File]::ReadAllBytes($Destination)[0] | Should -Be 9
            @(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($Destination)) -Filter '.xdr-report-*.tmp' -Force).Count | Should -Be 0
        }
    }

    It 'removes partial downloads after a failed request' {
        Mock Invoke-WebRequest {
            [IO.File]::WriteAllBytes($OutFile, [byte[]]@(1))
            throw 'Download failed'
        } -ModuleName XDRInternals
        $destination = Join-Path $TestDrive 'partial.bin'
        InModuleScope XDRInternals -Parameters @{ Destination = $destination } {
            { Invoke-XdrReportRequest -Uri 'https://security.microsoft.com/apiproxy/report/data' -OutFile $Destination } | Should -Throw '*Download failed*'
        }
        Test-Path -LiteralPath $destination | Should -BeFalse
    }
}

Describe 'Endpoint Device Control report' -Tag 'Functions', 'Endpoint' {
    BeforeEach {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Get-XdrCache { $null } -ModuleName XDRInternals
        Mock Set-XdrCache {} -ModuleName XDRInternals
        Mock Clear-XdrCache {} -ModuleName XDRInternals
        Mock Invoke-RestMethod {
            @([pscustomobject]@{
                    latestCookTime  = '2026-09-30T00:00:00Z'
                    actionTypeName  = 'DeviceControlRemovableStoragePolicyTriggered'
                    classStatistics = @([pscustomobject]@{
                            date        = '2026-09-29'
                            totalCount  = 5
                            classCounts = [pscustomobject]@{ RemovableMediaDevices = 5 }
                            actionType  = 'DeviceControlRemovableStoragePolicyTriggered'
                        })
                })
        } -ModuleName XDRInternals
    }

    It 'requests the captured default lookback and preserves response fields' {
        $result = @(Get-XdrEndpointDeviceControlReport)

        $result.Count | Should -Be 1
        $result[0].latestCookTime | Should -Be '2026-09-30T00:00:00Z'
        $result[0].actionTypeName | Should -Be 'DeviceControlRemovableStoragePolicyTriggered'
        $result[0].classStatistics[0].totalCount | Should -Be 5
        $result[0].classStatistics[0].classCounts.RemovableMediaDevices | Should -Be 5
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Method -eq 'Get' -and $Uri -eq 'https://security.microsoft.com/apiproxy/mdepdevicecontrol/m365/devicecontrolservice/SummaryStatistics?lookbackInDays=180'
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -like 'XdrReport:*' -and $TTLMinutes -eq 30
        }
    }

    It 'uses a separate request and cache for a different lookback' {
        $null = Get-XdrEndpointDeviceControlReport -LookbackInDays 30

        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Uri -like '*SummaryStatistics?lookbackInDays=30'
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -like 'XdrReport:*'
        }
    }

    It 'returns a valid cached report without making a request' {
        Mock Get-XdrCache {
            [pscustomobject]@{ NotValidAfter = (Get-Date).AddMinutes(10); Value = @([pscustomobject]@{ Count = 8 }) }
        } -ModuleName XDRInternals

        (Get-XdrEndpointDeviceControlReport).Count | Should -Be 8
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0
    }

    It 'bypasses a valid cache with Force' {
        Mock Get-XdrCache {
            [pscustomobject]@{ NotValidAfter = (Get-Date).AddMinutes(10); Value = 'cached' }
        } -ModuleName XDRInternals

        $null = Get-XdrEndpointDeviceControlReport -LookbackInDays 30 -Force

        Should -Invoke Clear-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -like 'XdrReport:*'
        }
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1
    }

    It 'preserves request errors and does not cache failed responses' {
        Mock Invoke-RestMethod { throw 'Report unavailable' } -ModuleName XDRInternals

        { Get-XdrEndpointDeviceControlReport -ErrorAction Stop } | Should -Throw '*Report unavailable*'
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 0
    }

    It 'rejects lookbacks outside the supported range' {
        { Get-XdrEndpointDeviceControlReport -LookbackInDays 0 } | Should -Throw
        { Get-XdrEndpointDeviceControlReport -LookbackInDays 181 } | Should -Throw
        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 0
    }

    It 'retrieves <ReportType> without a lookback query' -ForEach @(
        @{ ReportType = 'Policies' }
        @{ ReportType = 'CookMark' }
    ) {
        $null = Get-XdrEndpointDeviceControlReport -ReportType $ReportType

        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $Uri -eq "https://security.microsoft.com/apiproxy/mdepdevicecontrol/m365/devicecontrolservice/$ReportType"
        }
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1 -ParameterFilter {
            $CacheKey -like 'XdrReport:*' -and $TTLMinutes -eq 30
        }
    }

    It 'rejects an explicit lookback for a non-summary report before connecting' {
        { Get-XdrEndpointDeviceControlReport -ReportType Policies -LookbackInDays 30 } | Should -Throw '*applies only*'
        Should -Invoke Update-XdrConnectionSettings -ModuleName XDRInternals -Times 0
    }

    It 'retrieves fresh data when the cache has expired' {
        Mock Get-XdrCache {
            [pscustomobject]@{ NotValidAfter = (Get-Date).AddMinutes(-1); Value = 'expired' }
        } -ModuleName XDRInternals

        $null = Get-XdrEndpointDeviceControlReport

        Should -Invoke Invoke-RestMethod -ModuleName XDRInternals -Times 1
    }

    It 'preserves an empty summary response' {
        Mock Invoke-RestMethod { , @() } -ModuleName XDRInternals

        @(Get-XdrEndpointDeviceControlReport).Count | Should -Be 0
        Should -Invoke Set-XdrCache -ModuleName XDRInternals -Times 1
    }
}