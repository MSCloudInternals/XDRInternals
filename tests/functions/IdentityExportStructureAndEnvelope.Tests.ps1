Describe 'Identity export structure and envelope regressions' {
    BeforeEach {
        $caseRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item $caseRoot -ItemType Directory
    }
    It 'preserves payload structure for <Case> with EventId <HasId>' -ForEach @(
        foreach ($hasId in @($true, $false)) {
            foreach ($case in @(
                @{ Case = 'empty versus null'; Left = '[]'; Right = 'null' }
                @{ Case = 'singleton versus scalar'; Left = '["x"]'; Right = '"x"' }
                @{ Case = 'nested versus flat'; Left = '[["x"]]'; Right = '["x"]' }
                @{ Case = 'null member versus empty'; Left = '[null]'; Right = '[]' }
            )) { @{ Case = $case.Case; Left = $case.Left; Right = $case.Right; HasId = $hasId } }
        }
    ) {
        InModuleScope XDRInternals -Parameters @{ Root = $caseRoot; Left = $Left; Right = $Right; HasId = $HasId } {
            $script:Rows = @(
                ('{"Timestamp":"2026-01-01T00:00:01Z","Payload":{"v":' + $Left + '}}') | ConvertFrom-Json
                ('{"Timestamp":"2026-01-01T00:00:01Z","Payload":{"v":' + $Right + '}}') | ConvertFrom-Json
            )
            if ($HasId) { foreach ($row in $script:Rows) { $row | Add-Member EventId 'same' } }
            Mock Invoke-RestMethod { [pscustomobject]@{ count = 2; data = $script:Rows; errors = [pscustomobject]@{} } }
            $chunk = [pscustomobject]@{ Index = 0; FromDate = [datetime]'2026-01-01Z'; ToDate = [datetime]'2026-01-02Z'; FileName = 'structure.ndjson' }
            $shared = @{ PartsPath = $Root; BaseUrl = 'https://security.microsoft.com'; UserIdentifiers = @{upn='u'}; CookieData=@(); HeadersData=@{}; PageSize=1000; MaxRetries=1; RequestTimeoutSeconds=30 }
            $result = & (New-XdrIdentityTimelineExportWorker) $chunk $shared ([Collections.Concurrent.ConcurrentDictionary[int,object]]::new())
            $result.Success | Should -BeTrue -Because $result.Error
            $result.EventCount | Should -Be 2
            $result.DuplicateRepresentationCount | Should -Be 0
            @(Get-Content $result.FilePath) | Should -HaveCount 2
        }
    }

    It 'deduplicates equivalent property orders while retaining volatile exclusions' {
        InModuleScope XDRInternals -Parameters @{ Root = $caseRoot } {
            $script:Rows = @(
                '{"Timestamp":"2026-01-01T00:00:01Z","EventId":"same","Payload":{"a":[{"x":1,"y":2}],"b":null},"Id":"a","Description":"a","RowNumber":1}' | ConvertFrom-Json
                '{"RowNumber":2,"Description":"b","Id":"b","Payload":{"b":null,"a":[{"y":2,"x":1}]},"EventId":"same","Timestamp":"2026-01-01T00:00:01Z"}' | ConvertFrom-Json
            )
            Mock Invoke-RestMethod { [pscustomobject]@{ count=2; data=$script:Rows; errors=[pscustomobject]@{} } }
            $chunk = [pscustomobject]@{ Index=0; FromDate=[datetime]'2026-01-01Z'; ToDate=[datetime]'2026-01-02Z'; FileName='equivalent.ndjson' }
            $shared = @{ PartsPath=$Root; BaseUrl='https://security.microsoft.com'; UserIdentifiers=@{upn='u'}; CookieData=@(); HeadersData=@{}; PageSize=1000; MaxRetries=1; RequestTimeoutSeconds=30 }
            $result = & (New-XdrIdentityTimelineExportWorker) $chunk $shared ([Collections.Concurrent.ConcurrentDictionary[int,object]]::new())
            $result.Success | Should -BeTrue -Because $result.Error
            $result.EventCount | Should -Be 1
            $result.DuplicateRepresentationCount | Should -Be 1
        }
    }

    It 'validates raw pages and filters exact logical bounds for <Case>' -ForEach @(
        @{ Case='short page with both margins and exact boundaries'; Times=@(@('03.8','03.5','03.4999999','01.5','01.4999999')); Size=10; Expected=@('03.4999999','01.5'); Success=$true; Pages=1 }
        @{ Case='full mixed page with withheld oldest second'; Times=@(@('03.8','03.5','02.8','01.7'),@('01.7','01.5','01.2')); Size=4; Expected=@('02.8','01.7','01.5'); Success=$true; Pages=2 }
        @{ Case='padding-only full page keeps raw progress'; Times=@(@('03.9','03.8','01.4','01.3'),@('01.4','01.3')); Size=4; Expected=@(); Success=$true; Pages=2 }
        @{ Case='padding-only full single second is unpageable'; Times=@(@('03.9','03.8','03.7','03.6')); Size=4; Expected=@(); Success=$false; Error='*cannot prove completeness*' }
        @{ Case='below API lower bound'; Times=@(@('00.9999999')); Size=10; Expected=@(); Success=$false; Error='*exclusive interval*' }
        @{ Case='API exclusive upper bound'; Times=@(@('04.0')); Size=10; Expected=@(); Success=$false; Error='*exclusive interval*' }
        @{ Case='ascending padding is invalid'; Times=@(@('03.6','03.8')); Size=10; Expected=@(); Success=$false; Error='*descending timestamp order*' }
    ) {
        InModuleScope XDRInternals -Parameters @{ Root=$caseRoot; Times=$Times; Size=$Size; Expected=$Expected; Success=$Success; Pages=$Pages; ErrorPattern=$Error } {
            $script:Pages = [Collections.Generic.List[object]]::new()
            if ($Times[0] -is [string]) { $script:Pages.Add($Times) } else { foreach ($page in $Times) { $script:Pages.Add($page) } }
            $script:PageIndex=0; $script:Bodies=[Collections.Generic.List[object]]::new()
            Mock Invoke-RestMethod {
                param($Body)
                $script:Bodies.Add(($Body | ConvertFrom-Json))
                $rows = @($script:Pages[$script:PageIndex++] | ForEach-Object { [pscustomobject]@{ Timestamp="2026-01-01T00:00:${_}Z"; EventId=$_ } })
                [pscustomobject]@{ count=$rows.Count; data=$rows; errors=[pscustomobject]@{} }
            }
            $chunk = [pscustomobject]@{ Index=0; FromDate=[datetime]'2026-01-01T00:00:01.5Z'; ToDate=[datetime]'2026-01-01T00:00:03.5Z'; FileName='envelope.ndjson' }
            $shared = @{ PartsPath=$Root; BaseUrl='https://security.microsoft.com'; UserIdentifiers=@{upn='u'}; CookieData=@(); HeadersData=@{}; PageSize=$Size; MaxRetries=1; RequestTimeoutSeconds=30 }
            $result = & (New-XdrIdentityTimelineExportWorker) $chunk $shared ([Collections.Concurrent.ConcurrentDictionary[int,object]]::new())
            $result.Success | Should -Be $Success -Because $result.Error
            $script:Bodies[0].filters.Timeframe.between[0] | Should -Be 1767225601
            $script:Bodies[0].filters.Timeframe.between[1] | Should -Be 1767225604
            if ($Success) {
                $result.EventCount | Should -Be $Expected.Count
                $result.PageCount | Should -Be $Pages
                $actual = @(Get-Content $result.FilePath | ForEach-Object { ($_ | ConvertFrom-Json).EventId })
                ($actual -join ',') | Should -BeExactly ($Expected -join ',')
                if ($Pages -eq 2) { $script:Bodies[1].filters.Timeframe.between[1] | Should -Be 1767225602 }
            } else {
                $result.Error | Should -BeLike $ErrorPattern
                Test-Path (Join-Path $Root 'envelope.ndjson') | Should -BeFalse
            }
        }
    }

    It 'fingerprints the complete identifier JSON structure including armIds arrays' {
        InModuleScope XDRInternals -Parameters @{ Root=$caseRoot } {
            Mock Update-XdrConnectionSettings {}
            Mock Get-XdrIdentityHeaders { @{} }
            Mock Get-XdrIdentityUser { [pscustomobject]@{ ids=[pscustomobject]@{upn='u'} } }
            Mock ConvertTo-XdrIdentityUserIdentifiers { @{ armIds=@('x'); upn='u' } }
            $script:session=[Microsoft.PowerShell.Commands.WebRequestSession]::new(); $script:headers=@{}
            Mock New-XdrIdentityTimelineExportWorker {
                return {
                    param($chunk,$sharedParameters,$statusMap)
                    $part=Join-Path $sharedParameters.PartsPath $chunk.FileName
                    [IO.File]::WriteAllText($part,'')
                    [pscustomobject]@{ Success=$true; ChunkIndex=$chunk.Index; EventCount=0; PageCount=1; RetryCount=0; RewindCount=0; FileBytes=0; FileSha256=(Get-FileHash $part).Hash; MissingTimestampCount=0; BoundaryTimestampCount=0; DuplicateRepresentationCount=0; ElapsedSeconds=0 }
                }
            }
            $output=Join-Path $Root 'identifiers.ndjson'
            $null=Export-XdrIdentityUserTimeline -Upn 'u@contoso.com' -FromDate ([datetime]'2026-01-01Z') -ToDate ([datetime]'2026-01-01T01:00:00Z') -Path $output
            $manifest=Get-Content "$output.manifest.json" -Raw | ConvertFrom-Json
            $expected=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes('{"armIds":["x"],"upn":"u"}'))).ToLowerInvariant()
            $manifest.IdentityFingerprint | Should -Be $expected
            $manifest.CanonicalizationVersion | Should -Be 2
            # Retain deliberately synthetic legacy recovery state and ensure it is
            # refused intact even when its identifier fingerprint still matches.
            $manifest.PSObject.Properties.Remove('CanonicalizationVersion')
            $manifest.State = 'Failed'
            $null = New-Item "$output.parts" -ItemType Directory
            $legacyPart = Join-Path "$output.parts" 'legacy.ndjson'
            [IO.File]::WriteAllText($legacyPart, '{"legacy":"possibly collapsed"}')
            $manifest | ConvertTo-Json -Depth 20 | Set-Content "$output.manifest.json"
            $manifestBefore = [IO.File]::ReadAllText("$output.manifest.json")
            $outputHash = (Get-FileHash $output).Hash
            { Export-XdrIdentityUserTimeline -Upn 'u@contoso.com' -FromDate ([datetime]'2026-01-01Z') -ToDate ([datetime]'2026-01-01T01:00:00Z') -Path $output } | Should -Throw '*does not match this request*'
            [IO.File]::ReadAllText($legacyPart) | Should -BeExactly '{"legacy":"possibly collapsed"}'
            [IO.File]::ReadAllText("$output.manifest.json") | Should -BeExactly $manifestBefore
            (Get-FileHash $output).Hash | Should -Be $outputHash
            $manifest | Add-Member CanonicalizationVersion 2
            # Older manifests flattened singleton identifier arrays. Reject their
            # incompatible fingerprint instead of reusing another identity shape.
            $manifest.IdentityFingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes('{"armIds":"x","upn":"u"}'))).ToLowerInvariant()
            $manifest | ConvertTo-Json -Depth 20 | Set-Content "$output.manifest.json"
            { Export-XdrIdentityUserTimeline -Upn 'u@contoso.com' -FromDate ([datetime]'2026-01-01Z') -ToDate ([datetime]'2026-01-01T01:00:00Z') -Path $output } | Should -Throw '*does not match this request*'
        }
    }
}
