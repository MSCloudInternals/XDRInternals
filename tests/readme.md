# Description

This is the folder, where all the tests go.

Those are subdivided in two categories:

 - General
 - Function

## General Tests

General tests are function generic and test for general policies.

These test scan answer questions such as:

 - Is my module following my style guides?
 - Does any of my scripts have a syntax error?
 - Do my scripts use commands I do not want them to use?
 - Do my commands follow best practices?
 - Do my commands have proper help?

Basically, these allow a general module health check.

These tests are already provided as part of the template.

## Function Tests

A healthy module should provide unit and integration tests for the commands & components it ships.
Only then can be guaranteed, that they will actually perform as promised.

However, as each such test must be specific to the function it tests, there cannot be much in the way of templates.

## Live public-cmdlet validation

This repository now includes an automated public-surface validation suite:

- `tests/functions/PublicCmdlets.Metadata.Tests.ps1`
- `tests/live/PublicCmdlets.Live.Tests.ps1`
- `tests/helpers/Xdr.TestHelpers.ps1`
- `tests/pester.live.ps1`

The live suite authenticates once with `Connect-XdrBySoftwarePasskey`, then exercises exported cmdlets with:

- Auto-generated smoke scenarios for safe parameter sets
- Config-driven scenarios for cmdlets that need real tenant fixtures such as user UPNs, incident IDs, or mutation inputs

### Setup

1. Copy `tests/live.settings.sample.json` to `tests/live.settings.json`
2. Set `"liveTests.enabled": true`
3. Point `"authentication.keyFilePath"` to your local passkey JSON file
4. Fill in any tenant-specific fixtures or scenarios you want covered

### Run

The default repository runner stays authentication-free:

```powershell
pwsh .\tests\pester.ps1 -TestFunctions -Output Detailed
```

Run the authenticated live smoke suite separately with PowerShell 7:

```powershell
pwsh .\tests\pester.live.ps1 -LiveConfigurationPath .\tests\live.settings.json -EnableLiveTests -Output Detailed
```

If you want mutating cmdlets to run for real in a lab tenant, enable them deliberately:

```powershell
pwsh .\tests\pester.live.ps1 -LiveConfigurationPath .\tests\live.settings.json -EnableLiveTests -EnableMutationTests -Output Detailed
```

When mutation tests are not enabled, cmdlets that support `-WhatIf` are exercised in `WhatIf` mode by default.
