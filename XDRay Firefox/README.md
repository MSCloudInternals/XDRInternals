# XDRay (Firefox)

A Firefox-compatible build of the XDRay DevTools extension.

## Install (Temporary)
1. Open `about:debugging` in Firefox
2. Click `This Firefox`
3. Click `Load Temporary Add-on...`
4. Select `manifest.json` from the `XDRay Firefox` folder

Open DevTools and the `XDRay` panel will be available.

## Notes
- Uses Manifest v2 (background scripts) for compatibility.
- Icons in DevTools use `images/icon.svg`. Manifest icons are omitted.
- Update `browser_specific_settings.gecko.id` if publishing to AMO.
