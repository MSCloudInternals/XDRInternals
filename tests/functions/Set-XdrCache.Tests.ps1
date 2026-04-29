$helperPath = Join-Path $PSScriptRoot '..\helpers\Xdr.TestHelpers.ps1'
. $helperPath

Describe 'Set-XdrCache behavior' -Tag 'Functions', 'Cache' {
    BeforeEach {
        InModuleScope XDRInternals {
            $script:XdrCacheStore = @{}
        }
    }

    It 'skips caching null values' {
        InModuleScope XDRInternals {
            Set-XdrCache -CacheKey 'NullValue' -Value $null -TTLMinutes 5 -TenantId 'test-tenant'

            Get-XdrCache -CacheKey 'NullValue' -TenantId 'test-tenant' | Should -BeNullOrEmpty
        }
    }

    It 'caches empty arrays because they are valid results' {
        InModuleScope XDRInternals {
            Set-XdrCache -CacheKey 'EmptyArray' -Value @() -TTLMinutes 5 -TenantId 'test-tenant'
            $cacheEntry = Get-XdrCache -CacheKey 'EmptyArray' -TenantId 'test-tenant'

            @($cacheEntry.Value) | Should -HaveCount 0
        }
    }

    It 'caches zero values because they are valid results' {
        InModuleScope XDRInternals {
            Set-XdrCache -CacheKey 'ZeroValue' -Value 0 -TTLMinutes 5 -TenantId 'test-tenant'
            $cacheEntry = Get-XdrCache -CacheKey 'ZeroValue' -TenantId 'test-tenant'

            $cacheEntry.Value | Should -Be 0
        }
    }
}
