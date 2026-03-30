# Browser Auth Implementation Notes

This document captures the current browser authentication design, the macOS validation work completed for Chromium-based browsers, and the Safari and Firefox findings that led to deferring non-Chromium browser support for now.

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

## Why Firefox Was Deferred

Firefox is more promising than Safari for Linux, but it is still not a drop-in extension of the current Chromium implementation.

### What is different

The current implementation assumes Chromium-style startup and protocol behavior:

- `--user-data-dir`
- Chromium-style DevTools discovery endpoints
- `/json/version`
- `/json/list`
- target records that expose `webSocketDebuggerUrl`
- CDP cookie methods such as `Network.getAllCookies`, `Network.getCookies`, and `Storage.getCookies`

Firefox does not match that model when launched directly with the current helper design.

### Local findings

During investigation on macOS:

- Firefox was installed and launchable.
- Firefox accepted useful launch flags including:
  - `--profile`
  - `--new-instance`
  - `--new-window`
  - `--private-window`
  - `--headless`
  - `--remote-debugging-port`
- Launching Firefox directly with `--remote-debugging-port` did start a local listener.
- A direct probe to `http://127.0.0.1:<port>/json/version` returned `404 Not Found`.
- A direct probe to `http://127.0.0.1:<port>/json/list` returned `404 Not Found`.
- Firefox log output indicated WebDriver BiDi was listening on the selected local port.

The practical conclusion is that the current raw Chromium-style CDP bootstrap cannot simply be pointed at Firefox and expected to work.

### Mozilla documentation findings

Mozilla documentation indicates two realistic automation paths:

1. Firefox Remote Agent / WebDriver BiDi
2. `geckodriver` with `moz:firefoxOptions`

Important documented details:

- Firefox Remote Agent is enabled through `--remote-debugging-port`.
- The Remote Agent is loopback-only by default.
- WebDriver BiDi includes a `storage.getCookies` capability in the protocol.
- `geckodriver` can manage Firefox launch, profile selection, headless mode, and binary selection.
- `moz:debuggerAddress` is documented as the supported path for exposing `/json/version` and `/json/list` when Firefox is started through `geckodriver`.

### Linux-specific implications

Firefox is a realistic browser to care about on Linux because it is often preinstalled or treated as the default browser.

However, Linux also makes Firefox support more operationally sensitive:

- Firefox is commonly packaged as a Snap or other containerized package.
- Mozilla documents that containerized packaging can affect profile access and startup behavior.
- `geckodriver` may need `--profile-root` or a matching container-local binary path in those environments.

That means Firefox support is not only a protocol problem. It also has packaging and dependency implications that do not exist in the same way for the current Chromium path.

### Recommended architecture if Firefox is added later

Do not create a separate public cmdlet just for Firefox.

Instead:

- keep `Connect-XdrByBrowser` and `Connect-XdrBySSO` as the public entry points
- keep the shared auth orchestration logic
- add a Firefox-specific internal backend for browser launch, target inspection, and cookie retrieval

Recommended internal split:

- shared auth flow
  - start URL construction
  - profile selection and cleanup policy
  - ESTS grace-period behavior
  - portal-cookie fallback rules
  - timeout and diagnostics behavior
- browser backend
  - Chromium backend using the current CDP approach
  - Firefox backend using `geckodriver` first, not direct raw BiDi first

This preserves the current design strengths while isolating the protocol-specific work.

### Why `geckodriver` is the better first backend

If Firefox is implemented later, `geckodriver` is the more practical first route because it provides:

- a stable process/session manager for Firefox
- documented support for `moz:firefoxOptions`
- documented support for profile and binary selection
- a clearer story for headless mode
- a documented path for exposing debugger metadata through `moz:debuggerAddress`

Using raw BiDi directly would be possible in principle, but it would require more custom session setup and more protocol-specific plumbing inside the module.

### Current decision

Do not pursue Firefox support right now.

Rationale:

- Firefox support is materially more work than adding another Chromium browser.
- The current helpers are CDP-centric, not browser-generic.
- A correct Firefox implementation likely needs `geckodriver` as an explicit dependency.
- Linux packaging differences add support complexity beyond protocol differences.

### Practical conclusion for Linux browser support

For current Linux support, the lowest-cost path remains Chromium-based browsers.

If Firefox becomes necessary later, treat it as:

- supported through a separate internal backend
- likely dependent on `geckodriver`
- explicitly documented, especially for Snap or other containerized Linux installs

## Important Design Decisions

### Do not auto-fallback to Safari

Even if Safari is the default browser, do not silently switch to Safari when Chromium browsers are unavailable.

Reasons:

- Safari needs separate setup.
- Safari is not compatible with the current CDP-based implementation.
- Silent fallback would create confusing support behavior.

### Do not auto-fallback to Firefox until a real backend exists

Even though Firefox is common on Linux, do not silently select it with the current implementation.

Reasons:

- direct launch with the existing Chromium assumptions does not provide the expected debugging endpoints
- Firefox support likely needs different transport and startup handling
- Linux packaging differences would make silent fallback hard to reason about and support

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
5. Only revisit Safari or Firefox if there is a strong product reason to carry a second automation backend.

## Safari Revisit Checklist

If Safari support is reconsidered in the future:

1. Confirm whether `safaridriver` is available on supported target machines.
2. Confirm whether enabling Remote Automation is acceptable as a user prerequisite.
3. Prototype a minimal Safari WebDriver session.
4. Verify that cookies needed for XDR auth can be read reliably through Safari automation.
5. Decide whether Safari support remains opt-in only.

## Firefox Revisit Checklist

If Firefox support is reconsidered in the future:

1. Decide whether `geckodriver` is an acceptable dependency for supported environments.
2. Prototype Firefox launch through `geckodriver` using `moz:firefoxOptions` rather than the raw Chromium launch path.
3. Verify that the required XDR cookies can be captured reliably through the Firefox automation backend.
4. Test Linux packaging variants, especially non-containerized installs versus Snap or other containerized builds.
5. Keep Firefox support explicit and documented until the operational model is proven stable.

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