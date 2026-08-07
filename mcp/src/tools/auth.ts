import { z } from "zod";
import { bridge, XdrBridgeError } from "../bridge.js";
import { config } from "../config.js";
import {
  LOGIN_HINT,
  maxItemsField,
  params,
  responseFormatField,
  runQuery,
  textResult,
  toolError,
  type XdrTool,
} from "../toolkit.js";

interface TenantContextSummary {
  tenantId?: string;
  account?: string;
  raw?: unknown;
}

/** Reads the portal tenant context, which doubles as a proof-of-session check. */
async function readTenantContext(force = false): Promise<TenantContextSummary> {
  const result = await bridge.invoke({
    command: "Get-XdrTenantContext",
    params: force ? { Force: true } : {},
    maxItems: 1,
    timeoutSeconds: 120,
    depth: 6,
  });

  if (result.items.length === 0) {
    throw new XdrBridgeError(
      result.errors.join(" | ") || "Get-XdrTenantContext returned nothing; the session is not usable.",
    );
  }

  const context = result.items[0] as Record<string, any>;
  const authInfo = (context?.AuthInfo ?? {}) as Record<string, any>;
  return {
    tenantId: authInfo.TenantId ?? undefined,
    account: authInfo.UserName ?? undefined,
    raw: context,
  };
}

async function afterLogin(method: string, information: string[]): Promise<string> {
  bridge.markConnected(method);
  const lines = [`Signed in to Microsoft Defender XDR using ${method}.`];

  try {
    const context = await readTenantContext();
    bridge.updateSessionDetails({
      ...(context.tenantId ? { tenantId: context.tenantId } : {}),
      ...(context.account ? { account: context.account } : {}),
    });
    if (context.account) lines.push(`Account: ${context.account}`);
    if (context.tenantId) lines.push(`Tenant: ${context.tenantId}`);
  } catch (error) {
    lines.push(
      `The session was created but the tenant context could not be read: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  const relevant = information.filter((entry) => entry && !/^\s*$/.test(entry)).slice(-5);
  if (relevant.length > 0) lines.push("", ...relevant.map((entry) => `- ${entry}`));
  lines.push("", "The session lives in this MCP server's PowerShell process and is reused by every other tool.");
  return lines.join("\n");
}

async function login(
  command: string,
  method: string,
  cmdletParams: Record<string, unknown>,
  timeoutSeconds: number,
) {
  try {
    const result = await bridge.invoke({
      command,
      params: cmdletParams,
      maxItems: 5,
      timeoutSeconds,
      depth: 4,
    });

    if (result.errors.length > 0) {
      return toolError(
        `${method} sign-in failed: ${result.errors.join(" | ")}` +
          (result.warnings.length > 0 ? `\nWarnings: ${result.warnings.join(" | ")}` : ""),
      );
    }

    return textResult(await afterLogin(method, result.information));
  } catch (error) {
    return toolError(error instanceof Error ? error.message : String(error));
  }
}

export const authTools: XdrTool[] = [
  {
    name: "xdr_auth_status",
    title: "XDR sign-in status",
    description:
      "Reports whether this server holds an authenticated Microsoft Defender XDR portal session, " +
      "which sign-in method created it, and the tenant and account it belongs to. Call this first " +
      "when a tool reports an authentication problem.",
    inputSchema: {
      refresh: z
        .boolean()
        .optional()
        .describe("Bypass the tenant-context cache and re-read it from the portal."),
      response_format: responseFormatField,
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ refresh, response_format }) => {
      const session = bridge.getSession();
      if (!session.connected) {
        return textResult(
          [
            "## Defender XDR session",
            "",
            "**Not signed in.** No portal cookies are held by this server.",
            "",
            LOGIN_HINT,
            "",
            `Module: ${config.modulePath}`,
            `Read-only mode: ${config.readOnly ? "on (response and incident-change tools are hidden)" : "off"}`,
          ].join("\n"),
        );
      }

      try {
        const context = await readTenantContext(Boolean(refresh));
        bridge.updateSessionDetails({
          ...(context.tenantId ? { tenantId: context.tenantId } : {}),
          ...(context.account ? { account: context.account } : {}),
        });

        if (response_format === "json") {
          return textResult(
            ["## Defender XDR session", "", "```json", JSON.stringify(context.raw, null, 2), "```"].join("\n"),
          );
        }

        return textResult(
          [
            "## Defender XDR session",
            "",
            `- Signed in: yes (via ${session.method ?? "unknown method"} at ${session.connectedAt ?? "unknown time"})`,
            `- Account: ${context.account ?? "unknown"}`,
            `- Tenant: ${context.tenantId ?? "unknown"}`,
            `- Read-only mode: ${config.readOnly ? "on" : "off"}`,
            "",
            "> Use `response_format: \"json\"` for the full tenant context payload.",
          ].join("\n"),
        );
      } catch (error) {
        return toolError(
          `A session was established via ${session.method ?? "an earlier login"} but it no longer works: ` +
            (error instanceof Error ? error.message : String(error)),
        );
      }
    },
  },
  {
    name: "xdr_auth_login_sso",
    title: "Sign in with single sign-on",
    description:
      "Signs in to Microsoft Defender XDR as the account already signed in on this machine, using " +
      "browser/OS single sign-on with no credential prompt. This is the default login path: it " +
      "reuses the current user's session and captures the resulting portal cookies. Runs headless " +
      "unless visible is set. Use xdr_auth_login_browser when SSO cannot complete silently.",
    inputSchema: {
      tenant_id: z
        .string()
        .regex(/^[0-9a-fA-F-]{36}$/, "tenant_id must be a GUID")
        .optional()
        .describe("Tenant GUID to select. Required in practice for multi-tenant (MTO) accounts."),
      visible: z
        .boolean()
        .optional()
        .describe("Show the browser window instead of running headless. Useful for troubleshooting."),
      timeout_seconds: z
        .number()
        .int()
        .min(30)
        .max(1800)
        .optional()
        .describe("How long to wait for the SSO flow. Defaults to 180."),
      browser_path: z.string().optional().describe("Full path to a Chromium-based browser executable."),
      profile_path: z.string().optional().describe("Persistent browser profile directory to reuse."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    handler: async ({ tenant_id, visible, timeout_seconds, browser_path, profile_path }) =>
      login(
        "Connect-XdrBySSO",
        "single sign-on",
        params({
          TenantId: tenant_id,
          Visible: visible,
          // Tenant selection would otherwise prompt on the console, which is impossible here.
          SkipTenantSelection: true,
          TimeoutSeconds: timeout_seconds,
          BrowserPath: browser_path,
          ProfilePath: profile_path,
        }),
        (timeout_seconds ?? 180) + 120,
      ),
  },
  {
    name: "xdr_auth_login_browser",
    title: "Sign in interactively in a browser",
    description:
      "Opens an interactive Microsoft sign-in in a dedicated browser profile and captures the " +
      "Defender XDR session once sign-in completes. Use this when single sign-on is unavailable or " +
      "when the account needs MFA, a passkey, or a Temporary Access Pass. The person at the keyboard " +
      "must finish the prompts in the browser window before this returns.",
    inputSchema: {
      username: z.string().optional().describe("UPN to pre-fill, for example admin@contoso.com."),
      tenant_id: z.string().optional().describe("Tenant GUID to sign in to."),
      timeout_seconds: z
        .number()
        .int()
        .min(60)
        .max(1800)
        .optional()
        .describe("How long to wait for the person to complete sign-in."),
      private_session: z.boolean().optional().describe("Use a private/incognito window."),
      reset_profile: z.boolean().optional().describe("Discard the dedicated browser profile first."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    handler: async ({ username, tenant_id, timeout_seconds, private_session, reset_profile }) =>
      login(
        "Connect-XdrByBrowser",
        "interactive browser sign-in",
        params({
          Username: username,
          TenantId: tenant_id,
          TimeoutSeconds: timeout_seconds,
          PrivateSession: private_session,
          ResetProfile: reset_profile,
        }),
        (timeout_seconds ?? config.loginTimeoutSeconds) + 120,
      ),
  },
  {
    name: "xdr_auth_connect_with_token",
    title: "Sign in with a supplied cookie",
    description:
      "Establishes the Defender XDR session from a cookie the operator supplies: an sccauth portal " +
      "cookie (default) or an ESTSAUTH cookie. Use this when the operator pastes their own session " +
      "token, or when the token is provided through the XDR_SCCAUTH / XDR_ESTSAUTH environment " +
      "variables (omit the token argument to use those). The cookie value is never echoed back.",
    inputSchema: {
      token: z
        .string()
        .optional()
        .describe(
          "Cookie value. Omit to read XDR_SCCAUTH or XDR_ESTSAUTH from the server environment. " +
            "Treat this as a credential: anything passed here is stored in the conversation.",
        ),
      token_type: z
        .enum(["sccauth", "estsauth"])
        .default("sccauth")
        .describe("sccauth is the security.microsoft.com portal cookie; estsauth is the Entra ID cookie."),
      xsrf: z
        .string()
        .optional()
        .describe("XSRF-TOKEN cookie value for sccauth sign-in. Fetched automatically when omitted."),
      tenant_id: z.string().optional().describe("Tenant GUID. Detected automatically when omitted."),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    handler: async ({ token, token_type, xsrf, tenant_id }) => {
      const type = (token_type ?? "sccauth") as "sccauth" | "estsauth";
      const fromEnv = type === "sccauth" ? config.sccauth : config.estsauth;
      const value = token?.trim() || fromEnv;

      if (!value) {
        return toolError(
          `No ${type} value was supplied and the ${
            type === "sccauth" ? "XDR_SCCAUTH" : "XDR_ESTSAUTH"
          } environment variable is not set. Pass the cookie in the token argument, or use xdr_auth_login_sso to sign in without one.`,
        );
      }

      const source = token?.trim() ? "supplied value" : "server environment";

      if (type === "estsauth") {
        return login(
          "Connect-XdrByEstsCookie",
          `ESTSAUTH cookie (${source})`,
          params({ EstsAuthCookieValue: value, TenantId: tenant_id ?? config.tenantId }),
          180,
        );
      }

      return login(
        "Set-XdrConnectionSettings",
        `sccauth cookie (${source})`,
        params({
          SccAuth: value,
          Xsrf: xsrf ?? config.xsrf,
          TenantId: tenant_id ?? config.tenantId,
        }),
        180,
      );
    },
  },
  {
    name: "xdr_auth_logout",
    title: "Sign out",
    description:
      "Discards the Defender XDR session held by this server by recreating the PowerShell runspace, " +
      "which drops the portal cookies, XSRF token, cached tenant data, and any open Live Response " +
      "sessions. Every later tool call needs a new sign-in.",
    inputSchema: {},
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    handler: async () => {
      try {
        await bridge.reset();
        return textResult(
          "Signed out. The PowerShell runspace was recreated, so all portal cookies, cached tenant data and Live Response sessions are gone.",
        );
      } catch (error) {
        bridge.restart();
        return textResult(
          "Signed out by terminating the PowerShell session (the clean reset failed: " +
            `${error instanceof Error ? error.message : String(error)}). All session state is gone.`,
        );
      }
    },
  },
  {
    name: "xdr_list_tenants",
    title: "List accessible tenants",
    description:
      "Lists the tenants reachable from the current Defender XDR sign-in (multi-tenant organization " +
      "view). Use it to find the tenant GUID for cross-tenant hunting or for a tenant-scoped login.",
    inputSchema: {
      response_format: responseFormatField,
      max_items: maxItemsField,
      refresh: z.boolean().optional().describe("Bypass the module cache."),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    handler: async ({ response_format, max_items, refresh }) =>
      runQuery({
        command: "Get-XdrMtoTenantList",
        params: params({ Force: refresh }),
        title: "Accessible tenants",
        format: response_format,
        maxItems: max_items,
        summaryFields: ["name", "tenantId", "displayName", "defaultDomain", "isPrimary"],
        emptyMessage:
          "No tenants were returned. The account may not be onboarded to the multi-tenant view; single-tenant hunting still works.",
      }),
  },
];
