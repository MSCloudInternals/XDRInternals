# Browser Auth Implementation Notes

This document captures the current browser authentication design, the macOS validation work completed for Chromium-based browsers, and the Safari-specific findings that led to deferring Safari support for now.

## Scope

This note covers:

- `Connect-XdrByBrowser`
- `Connect-XdrBySSO`
- `Invoke-XdrBrowserAuthentication`
- `Invoke-XdrSsoAuthentication`
- `Connect-XdrByEstsCookie`

Relevant files:

- `XDRInternals/functions/Connect-XdrByBrowser.ps1`
- `XDRInternals/functions/Connect-XdrBySSO.ps1`
- `XDRInternals/internal/functions/Invoke-XdrBrowserAuthentication.ps1`
- `XDRInternals/internal/functions/Invoke-XdrSsoAuthentication.ps1`
- `XDRInternals/functions/Connect-XdrByEstsCookie.ps1`
- `XDRInternals/internal/functions/Connect-XdrAuthArtifacts.ps1`

## Current Implementation Model

### Chromium path

The current browser automation path is Chromium-based across Windows, macOS, and Linux.

Core design:

- Launch a supported Chromium-based browser directly.
- Start it with a dedicated profile or temporary private profile.
- Enable a local DevTools endpoint with `--remote-debugging-port`.
- Poll the browser for page targets and cookies through the DevTools protocol.
- Prefer Defender portal cookies when available.
- Use ESTS cookies as a bootstrap path only when necessary.

### Why portal cookies matter

`ESTSAUTH` can appear before the browser reaches the final Defender portal session state. In several tested scenarios, attempting `Connect-XdrByEstsCookie` too early failed even though the browser later produced the Defender portal cookies required for a successful session.

The practical rule is:

- `ESTSAUTH` appearing first does not mean the browser flow is finished.
- The helpers should wait briefly for `security.microsoft.com` cookies before falling back to ESTS-only bootstrap.

This is now implemented in both browser and SSO helpers.

## Validated macOS Findings

### Browser support

Validated target class on macOS:

- Microsoft Edge
- Google Chrome
- Brave Browser
- Chromium

The implementation supports:

- application bundle paths such as `/Applications/Microsoft Edge.app`
- direct executable paths inside `.app` bundles
- auto-discovery from `/Applications`
- auto-discovery from `~/Applications`

### Browser auth behavior on macOS

`Connect-XdrByBrowser` remains interactive on macOS.

Important behavior:

- The user must complete any Entra prompts, account pickers, consent prompts, and Defender landing transitions.
- Some failures observed during testing were caused by the browser flow not being fully completed before the helper decided the session state was insufficient.
- A dedicated secondary profile works on macOS when the user completes the interactive flow fully.

Validated successful pattern:

- Launch clean dedicated Edge profile.
- Complete the interactive sign-in prompts.
- Wait for Defender portal cookies to appear.
- If ESTS bootstrap is still insufficient, fall back to captured portal cookies.

### SSO behavior on macOS

`Connect-XdrBySSO` now works on macOS with Chromium-based browsers.

Validated outcomes:

- `Connect-XdrBySSO -Visible` succeeded.
- `Connect-XdrBySSO` default silent path also succeeded after aligning the cookie polling logic with the browser helper.

Key fix:

- The SSO helper originally exited too early as soon as `ESTSAUTH` appeared.
- The helper now waits for Defender portal cookies after ESTS appears, matching the browser flow.

## macOS-Specific Improvements Already Implemented

The following improvements were made during this work:

1. macOS browser auto-discovery includes user-scoped app installs.
2. `.app` bundle paths are accepted and resolved to the actual executable.
3. Process arguments containing spaces are quoted correctly.
4. Browser auth waits for portal cookies after ESTS appears.
5. SSO now uses the same grace-period logic instead of failing immediately on ESTS-only state.
6. Browser target diagnostics now record the last observed page for timeouts and early exits.

## Why Safari Was Deferred

Safari is not a small extension of the Chromium implementation.

### What is different

The current implementation depends on Chromium DevTools Protocol features:

- remote debugging port
- target enumeration
- WebSocket debugging URL selection
- DevTools cookie APIs

Safari does not fit that model. A Safari implementation would need a separate backend based on Safari WebDriver instead of Chromium DevTools.

### Local findings

During investigation:

- `safaridriver` was present on this macOS machine.
- Starting `safaridriver` itself worked.
- Creating a Safari WebDriver session failed with:

  `You must enable 'Allow remote automation' in the Developer section of Safari Settings to control Safari via WebDriver.`

### Practical requirements for Safari support

Safari support would require at minimum:

1. Safari installed.
2. `safaridriver` available.
3. Safari Remote Automation enabled.
4. A new Safari-specific automation and cookie-capture implementation.

### Why this was judged too expensive right now

Safari support introduces both technical and operational cost:

- a separate backend to maintain
- extra user setup before the feature can work
- interactive Safari automation prerequisites
- less alignment with the existing Chromium implementation

### Current decision

Do not pursue Safari support at this time.

Rationale:

- Chromium support is now working on macOS.
- Safari would require separate implementation and separate user setup.
- Safari should not be an automatic fallback browser.

If Safari is revisited later, it should be:

- explicit
- opt-in
- clearly documented
- never a silent fallback path

## Important Design Decisions

### Do not auto-fallback to Safari

Even if Safari is the default browser, do not silently switch to Safari when Chromium browsers are unavailable.

Reasons:

- Safari needs separate setup.
- Safari is not compatible with the current CDP-based implementation.
- Silent fallback would create confusing support behavior.

### Keep the Chromium path aligned across platforms

The preferred design is still one shared Chromium implementation with only narrow platform-specific differences where necessary.

Examples of acceptable platform-specific differences:

- browser discovery paths
- profile directory defaults
- process launch quirks

Examples of differences to avoid unless necessary:

- completely separate auth logic for macOS/Linux Chromium
- platform-specific cookie semantics when a shared approach works

## Troubleshooting Notes

### Browser auth appears stuck

Check the last observed browser page in verbose output or failure text.

Interpretation:

- still on `login.microsoftonline.com`: user flow likely not complete yet
- reached `security.microsoft.com`: portal cookies should appear soon
- ESTS appears without portal cookies: wait for the grace period or inspect whether the browser really reached Defender

### ESTS cookie captured but ESTS bootstrap fails

This usually means the browser reached an intermediate authenticated state, but not the final Defender portal session state required by `Connect-XdrByEstsCookie`.

Preferred resolution:

- keep polling for Defender portal cookies
- if portal cookies arrive, fall back to portal-cookie connection settings

### SSO works with `-Visible` but not silently

This was previously caused by the SSO helper ending too early when ESTS first appeared.

If this regresses, inspect:

- whether the silent path waited long enough after ESTS appeared
- whether the last observed browser page reached Defender
- whether portal cookies were captured before the helper exited

## Future Work Checklist

If more work is needed later, use this order:

1. Re-run macOS browser and SSO validation with verbose logging.
2. Check the last observed browser page emitted by the helpers.
3. Confirm whether ESTS appears before portal cookies.
4. Prefer extending shared Chromium behavior over adding platform-specific branches.
5. Only revisit Safari if there is a strong product reason to carry a second automation backend.

## Safari Revisit Checklist

If Safari support is reconsidered in the future:

1. Confirm whether `safaridriver` is available on supported target machines.
2. Confirm whether enabling Remote Automation is acceptable as a user prerequisite.
3. Prototype a minimal Safari WebDriver session.
4. Verify that cookies needed for XDR auth can be read reliably through Safari automation.
5. Decide whether Safari support remains opt-in only.

## Testing Commands Used During This Investigation

Representative local validation commands:

```powershell
Import-Module ./XDRInternals/XDRInternals.psd1 -Force
Invoke-Pester ./tests/functions/Connect.Tests.ps1 -Output Normal
```

```powershell
Connect-XdrByBrowser -Username 'user@contoso.com' -BrowserPath '/Applications/Microsoft Edge.app' -ResetProfile -TimeoutSeconds 300 -Verbose
```

```powershell
Connect-XdrBySSO -BrowserPath '/Applications/Microsoft Edge.app' -Visible -TimeoutSeconds 300 -Verbose
Connect-XdrBySSO -BrowserPath '/Applications/Microsoft Edge.app' -TimeoutSeconds 300 -Verbose
```

Safari capability probe used during investigation:

```powershell
$body = @{ capabilities = @{ alwaysMatch = @{ browserName = 'Safari'; platformName = 'macOS'; 'safari:diagnose' = $true } } } | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri 'http://127.0.0.1:5555/session' -Method Post -ContentType 'application/json' -Body $body
```

Observed result:

- Safari session creation failed until Safari Remote Automation is enabled.