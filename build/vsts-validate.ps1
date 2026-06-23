# Run internal pester tests
& "$PSScriptRoot\..\tests\pester.ps1" `
    -Exclude @('CmdletOutputAndCaching.Tests.ps1', 'Xdr.TestHelpers.Tests.ps1') `
    -ExcludeTag @('Live', 'ReviewRegression')