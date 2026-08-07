import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { config } from "./config.js";

function userMessage(text: string) {
  return { messages: [{ role: "user" as const, content: { type: "text" as const, text } }] };
}

/**
 * Prompts surface as slash commands in MCP clients (in Claude Code as
 * /mcp__<server>__<prompt>), which is how an operator drives sign-in and the standard
 * investigation workflows without remembering tool names.
 */
export function registerPrompts(server: McpServer): string[] {
  const registered: string[] = [];

  // The SDK infers prompt argument types from argsSchema; this wrapper keeps registration terse,
  // so each handler declares the argument shape it expects itself.
  const add = (
    name: string,
    definition: Record<string, unknown>,
    handler: (args: any) => ReturnType<typeof userMessage>,
  ) => {
    server.registerPrompt(name, definition as never, handler as never);
    registered.push(name);
  };

  add(
    "login",
    {
      title: "Sign in to Defender XDR",
      description:
        "Sign in to Microsoft Defender XDR as the current user (single sign-on, falling back to an interactive browser sign-in).",
      argsSchema: {
        tenant_id: z.string().optional().describe("Tenant GUID to sign in to. Optional for single-tenant accounts."),
      },
    },
    ({ tenant_id }: { tenant_id?: string }) =>
      userMessage(
        [
          "Sign me in to Microsoft Defender XDR through the XDR MCP server, then confirm who I am signed in as.",
          "",
          "Steps:",
          "1. Call `xdr_auth_status`. If it already reports a working session, report the account and tenant and stop.",
          `2. Otherwise call \`xdr_auth_login_sso\`${tenant_id ? ` with tenant_id \`${tenant_id}\`` : ""}, which reuses my current Windows/browser sign-in.`,
          "3. If single sign-on fails, call `xdr_auth_login_browser` so I can complete MFA, a passkey or a Temporary Access Pass in the browser window, and tell me to watch for it.",
          "4. If both fail, tell me the exact error and offer `xdr_auth_connect_with_token` so I can paste an sccauth cookie instead.",
          "",
          "Finish by reporting the signed-in account, the tenant, and that the session is now shared by every XDR tool.",
        ].join("\n"),
      ),
  );

  add(
    "use-token",
    {
      title: "Sign in with a cookie I provide",
      description: "Establish the Defender XDR session from an sccauth or ESTSAUTH cookie value.",
      argsSchema: {
        token: z
          .string()
          .optional()
          .describe("Cookie value. Leave empty to use the XDR_SCCAUTH / XDR_ESTSAUTH environment variables."),
        token_type: z.string().optional().describe("sccauth (default) or estsauth."),
      },
    },
    ({ token, token_type }: { token?: string; token_type?: string }) =>
      userMessage(
        [
          token
            ? "Sign in to Microsoft Defender XDR with the session cookie I am providing."
            : "Sign in to Microsoft Defender XDR using the session cookie configured in the server environment.",
          "",
          `Call \`xdr_auth_connect_with_token\` with token_type \`${token_type?.trim() || "sccauth"}\`${
            token ? " and the token value below" : " and no token argument, so it reads XDR_SCCAUTH or XDR_ESTSAUTH"
          }, then call \`xdr_auth_status\` and report the account and tenant.`,
          "",
          "Never repeat the cookie value back to me, and do not put it in any file or command output.",
          ...(token ? ["", "Token:", token] : []),
        ].join("\n"),
      ),
  );

  add(
    "status",
    {
      title: "Defender XDR session status",
      description: "Report the current Defender XDR sign-in, tenant and server mode.",
      argsSchema: {},
    },
    () =>
      userMessage(
        "Call `xdr_auth_status` and tell me whether the XDR MCP server holds a working Defender XDR session, " +
          "which account and tenant it belongs to, and how it was established. If it is not signed in, tell me the fastest way to fix that.",
      ),
  );

  add(
    "logout",
    {
      title: "Sign out of Defender XDR",
      description: "Drop the Defender XDR session held by the MCP server.",
      argsSchema: {},
    },
    () =>
      userMessage(
        "Call `xdr_auth_logout` to discard the Defender XDR session held by the MCP server, then confirm that the cookies, cached tenant data and any Live Response sessions are gone.",
      ),
  );

  add(
    "investigate-incident",
    {
      title: "Investigate an incident",
      description: "Work an incident end to end: alerts, entities, timelines and a written assessment.",
      argsSchema: {
        incident_id: z.string().describe("Numeric incident ID."),
      },
    },
    ({ incident_id }: { incident_id: string }) =>
      userMessage(
        [
          `Investigate Microsoft Defender XDR incident ${incident_id} and write up what happened.`,
          "",
          "Work in this order, using the XDR tools:",
          `1. \`xdr_get_incident\` for ${incident_id}, then \`xdr_get_incident_alerts\` to see what it is built from.`,
          "2. Extract the involved entities (devices, accounts, files, IPs, URLs) from the alerts.",
          "3. For each involved device use `xdr_get_device` and a tightly scoped `xdr_get_device_timeline` around the alert times; for each account use `xdr_get_identity` and `xdr_get_identity_timeline`. Add `xdr_get_cloudapps_activity` when SaaS or mail activity is implicated.",
          "4. Pivot with `xdr_run_hunting_query` to check whether the same indicators appear on other devices or accounts, and to establish first-seen and last-seen times.",
          "5. Check `xdr_list_pending_actions` and `xdr_list_action_history` for automated remediation that already happened.",
          "",
          "Then give me: a timeline of what happened, the likely initial access and impact, the blast radius, whether this looks true or false positive with your confidence, and the specific containment steps you would take.",
          "Do not run any containment, isolation or Live Response action without asking me first.",
        ].join("\n"),
      ),
  );

  add(
    "hunt",
    {
      title: "Threat hunt",
      description: "Run a structured threat hunt against Defender XDR data from a hypothesis.",
      argsSchema: {
        hypothesis: z.string().describe("What to hunt for, e.g. 'lsass access from unsigned binaries'."),
        days: z.string().optional().describe("Look-back window in days. Defaults to 7."),
      },
    },
    ({ hypothesis, days }: { hypothesis: string; days?: string }) =>
      userMessage(
        [
          `Run a threat hunt in Microsoft Defender XDR for this hypothesis: ${hypothesis}`,
          "",
          `Look back ${days?.trim() || "7"} days.`,
          "",
          "Approach:",
          "1. State the hypothesis as concrete, observable behaviour, and name the tables you expect to hold that evidence.",
          "2. Confirm column names with `xdr_get_hunting_schema` before writing KQL, and check the query with `xdr_validate_hunting_query` if it is non-trivial.",
          "3. Run bounded queries with `xdr_run_hunting_query` - always summarize or limit, and start narrow before widening.",
          "4. Triage the hits: separate expected administrative activity from suspicious activity, and pivot on the survivors (device, account, parent process, remote address) with follow-up queries and the timeline tools.",
          "5. Check `xdr_list_detection_rules` to see whether existing detections already cover confirmed findings.",
          "",
          "Report: the queries you ran, what you found, which hits are benign and why, which need investigation, and a detection rule proposal for anything worth alerting on.",
        ].join("\n"),
      ),
  );

  add(
    "triage-queue",
    {
      title: "Triage the alert queue",
      description: "Review open incidents and alerts and propose a prioritized triage order.",
      argsSchema: {
        days: z.string().optional().describe("Look-back window in days. Defaults to 3."),
      },
    },
    ({ days }: { days?: string }) =>
      userMessage(
        [
          `Triage the Microsoft Defender XDR queue for the last ${days?.trim() || "3"} day(s).`,
          "",
          "1. `xdr_list_incidents` sorted by TopRisk, and `xdr_list_alerts` filtered to New and InProgress.",
          "2. Group what you see: which incidents look like the same activity, which are single-alert noise, which involve critical assets or privileged accounts.",
          "3. For the top items, pull just enough context (incident alerts, device or identity lookup) to judge severity honestly.",
          "4. Check `xdr_list_pending_actions` for remediation waiting on a human.",
          "",
          `Give me a ranked triage list: incident ID, one-line assessment, why it ranks there, and the single next action for each. Flag anything that needs immediate containment, but do not act on it without my approval.${
            config.readOnly ? " Note: this server runs in read-only mode, so response actions are unavailable." : ""
          }`,
        ].join("\n"),
      ),
  );

  return registered;
}
