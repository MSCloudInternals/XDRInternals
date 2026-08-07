import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const moduleDir = dirname(fileURLToPath(import.meta.url));

/** Root of the MCP server package (the `mcp` folder), whether running from `src` or `dist`. */
export const packageRoot = resolve(moduleDir, "..");

/** Root of the XDRInternals repository checkout. */
export const repoRoot = resolve(packageRoot, "..");

function readFlag(name: string, fallback = false): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  return ["1", "true", "yes", "on"].includes(raw.trim().toLowerCase());
}

function readNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function readText(name: string): string | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return undefined;
  return raw.trim();
}

/**
 * Resolves the XDRInternals module to import into the bridge runspace.
 *
 * Priority: XDR_MODULE_PATH, then the checkout this server ships inside, then the module name
 * (resolved through PSModulePath, i.e. a PowerShell Gallery install).
 */
function resolveModulePath(): string {
  const explicit = readText("XDR_MODULE_PATH");
  if (explicit) return explicit;

  const local = join(repoRoot, "XDRInternals", "XDRInternals.psd1");
  if (existsSync(local)) return local;

  return "XDRInternals";
}

export const config = {
  /** PowerShell 7 executable used to host the XDRInternals session. */
  pwsh: readText("XDR_MCP_PWSH") ?? "pwsh",
  /** Bridge script that keeps one authenticated XDRInternals session alive. */
  hostScript: join(packageRoot, "bridge", "XdrMcpHost.ps1"),
  modulePath: resolveModulePath(),

  /** When true, no incident-modifying, response-action or live-response tool is registered. */
  readOnly: readFlag("XDR_MCP_READONLY"),
  /** When true, xdr_invoke_rest_method may use verbs other than GET. */
  allowRestWrite: readFlag("XDR_MCP_ALLOW_REST_WRITE"),

  /** Character budget for a single tool response before results are trimmed. */
  maxChars: readNumber("XDR_MCP_MAX_CHARS", 45_000),
  /** Default number of records returned per tool call. */
  defaultMaxItems: readNumber("XDR_MCP_MAX_ITEMS", 50),
  /** Default cmdlet timeout. */
  timeoutSeconds: readNumber("XDR_MCP_TIMEOUT_SECONDS", 300),
  /** Timeout for interactive sign-in cmdlets, which wait on a browser. */
  loginTimeoutSeconds: readNumber("XDR_MCP_LOGIN_TIMEOUT_SECONDS", 600),
  /** Timeout for hunting queries and timeline pulls. */
  longTimeoutSeconds: readNumber("XDR_MCP_LONG_TIMEOUT_SECONDS", 900),

  /** Optional pre-supplied session material, used by xdr_auth_connect_with_token. */
  sccauth: readText("XDR_SCCAUTH"),
  xsrf: readText("XDR_XSRF"),
  estsauth: readText("XDR_ESTSAUTH"),
  tenantId: readText("XDR_TENANT_ID"),
  /** When true and a token is present in the environment, connect on the first tool call. */
  autoConnect: readFlag("XDR_MCP_AUTO_CONNECT"),
} as const;

export type XdrMcpConfig = typeof config;
