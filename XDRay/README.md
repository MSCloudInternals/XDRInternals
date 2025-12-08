# ⚠️ Disclaimer: Vibe Coded ⚠️

> This project was **vibe coded**. It may contain traces of chaos, brilliance, and questionable architectural decisions. Use at your own risk and enjoy the vibes.

# XDRay - XDR Network Analyzer

XDRay is a browser extension for Microsoft Defender XDR (security.microsoft.com) that bridges the gap between the web portal and automation. It analyzes network traffic in real-time and automatically generates `XDRInternals` PowerShell commands for the actions you perform in the UI.

## Features

- **Real-time Traffic Analysis**: Intercepts API calls to `security.microsoft.com/apiproxy`.
- **Cmdlet Mapping**: Automatically maps REST API calls to their corresponding `XDRInternals` cmdlets.
- **Code Generation**: Generates ready-to-run PowerShell code with correct parameters and payloads.
- **Sensitive Data Handling**: Extracts and copies `sccauth` and `XSRF-TOKEN` cookies for authentication.
- **Danger Zone**: A protected area for handling sensitive tokens with explicit user acknowledgement.

## Installation (Developer Mode)

Since this is a developer tool, it is installed as an "unpacked" extension.

### Google Chrome / Microsoft Edge

1.  Clone or download this repository to your local machine.
2.  Open your browser and navigate to the Extensions management page:
    *   **Chrome**: `chrome://extensions`
    *   **Edge**: `edge://extensions`
3.  Enable **Developer mode** (usually a toggle switch in the top right corner).
4.  Click the **Load unpacked** button.
5.  Select the `XDRay` folder inside the repository (e.g., `C:\path\to\XDRInternals\XDRay`).
6.  The extension should now appear in your list of installed extensions.

## Usage

1.  Navigate to [security.microsoft.com](https://security.microsoft.com).
2.  Open Developer Tools (**F12** or **Ctrl+Shift+I**).
3.  Look for the **XDRay** tab in the Developer Tools window (you might need to click the `>>` overflow menu if it's not visible).
4.  Browse the portal and perform actions (e.g., search for a device, view an incident).
5.  XDRay will capture the requests and display them in the list.
6.  Click on a request to expand it and view the generated PowerShell code.
7.  Use the **Copy Code** button to copy the snippet to your clipboard.

## Danger Zone & Session Security

The extension includes a "Danger Zone" that provides access to sensitive session cookies (`sccauth` and `XSRF-TOKEN`). These features are hidden by default and require explicit confirmation to access.

### ⚠️ Security Warning

**The `sccauth` cookie and `XSRF-TOKEN` are highly sensitive.** They represent your active authenticated session.

*   **Do not share** these values with anyone.
*   **Do not post** screenshots containing these values.
*   **Do not commit** scripts containing these values to version control.

Possession of these tokens allows an attacker to impersonate you and perform actions in the Microsoft Defender portal with your privileges.

### Usage

These tokens are required by `Connect-XdrByEstsCookie` or `Set-XdrConnectionSettings` to authenticate the `XDRInternals` module against the undocumented APIs. The extension provides a convenient way to copy them for **local, temporary use** in your PowerShell session.

## Security Note

This extension requires permissions to read network traffic on `security.microsoft.com` and access cookies. This is necessary to capture the API calls and authentication tokens required for the `XDRInternals` module to function. The data is processed locally within your browser and is not sent to any third-party servers.
