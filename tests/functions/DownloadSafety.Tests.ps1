Describe 'Download destination safety' {
    It 'uses an existing directory and rejects an existing file by default' {
        InModuleScope XDRInternals {
            $destinationDirectory = Join-Path $TestDrive 'downloads'
            $null = New-Item -ItemType Directory -Path $destinationDirectory

            $resolved = Resolve-XdrDownloadOutputPath -SuggestedFileName 'result.zip' -OutputPath $destinationDirectory
            $resolved | Should -Be (Join-Path $destinationDirectory 'result.zip')

            [System.IO.File]::WriteAllText($resolved, 'existing')
            { Resolve-XdrDownloadOutputPath -SuggestedFileName 'result.zip' -OutputPath $destinationDirectory } |
                Should -Throw '*already exists*Specify -Force*'
        }
    }

    It 'allows an existing destination only when Force is supplied' {
        InModuleScope XDRInternals {
            $destination = Join-Path $TestDrive 'existing.zip'
            [System.IO.File]::WriteAllText($destination, 'existing')

            Resolve-XdrDownloadOutputPath -SuggestedFileName 'result.zip' -OutputPath $destination -Force |
                Should -Be $destination
        }
    }

    It 'exposes OutputPath and Force only on action-result download parameter sets' {
        $command = Get-Command Get-XdrEndpointDeviceActionResult

        $command.ParameterSets.Where({ $_.Name -like 'Download*' }).Parameters.Name | Should -Contain 'OutputPath'
        $command.ParameterSets.Where({ $_.Name -like 'Download*' }).Parameters.Name | Should -Contain 'Force'
        $command.ParameterSets.Where({ $_.Name -eq 'List' }).Parameters.Name | Should -Not -Contain 'OutputPath'
        $command.ParameterSets.Where({ $_.Name -eq 'List' }).Parameters.Name | Should -Not -Contain 'Force'
    }

    It 'requires Force before overwriting an action-result download' {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Invoke-RestMethod { 'https://download.example/package.zip?sig=secret' } -ModuleName XDRInternals
        Mock Invoke-WebRequest {
            [System.IO.File]::WriteAllText($OutFile, 'new package')
        } -ModuleName XDRInternals
        $destination = Join-Path $TestDrive 'package.zip'
        [System.IO.File]::WriteAllText($destination, 'existing package')

        {
            Get-XdrEndpointDeviceActionResult -DownloadInvestigationPackage -RequestGuid 'request-id' -OutputPath $destination -ErrorAction Stop
        } | Should -Throw '*already exists*Specify -Force*'
        [System.IO.File]::ReadAllText($destination) | Should -Be 'existing package'

        $result = Get-XdrEndpointDeviceActionResult -DownloadInvestigationPackage -RequestGuid 'request-id' -OutputPath $destination -Force
        $result.FullName | Should -Be $destination
        [System.IO.File]::ReadAllText($destination) | Should -Be 'new package'
    }

    It 'requires Force before overwriting a Live Response library download' {
        Mock Update-XdrConnectionSettings {} -ModuleName XDRInternals
        Mock Invoke-WebRequest {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes('new content')
            [pscustomobject]@{ RawContentStream = [System.IO.MemoryStream]::new($bytes) }
        } -ModuleName XDRInternals
        $destination = Join-Path $TestDrive 'library-file.ps1'
        [System.IO.File]::WriteAllText($destination, 'existing content')

        {
            Get-XdrEndpointDeviceLiveResponseLibraryFile -FileName 'library-file.ps1' -OutputPath $destination -ErrorAction Stop
        } | Should -Throw '*already exists*Specify -Force*'
        [System.IO.File]::ReadAllText($destination) | Should -Be 'existing content'

        Get-XdrEndpointDeviceLiveResponseLibraryFile -FileName 'library-file.ps1' -OutputPath $destination -Force
        [System.IO.File]::ReadAllText($destination) | Should -Be 'new content'
    }
}
