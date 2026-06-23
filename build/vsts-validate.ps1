# Run internal pester tests
& "$PSScriptRoot\..\tests\pester.ps1" `
    -Exclude @('Pr111.Cmdlets.Tests.ps1', 'Xdr.TestHelpers.Tests.ps1') `
    -ExcludeTag @('Live', 'ReviewRegression')