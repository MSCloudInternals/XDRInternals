import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { createInterface, type Interface } from "node:readline";
import { config } from "./config.js";

export interface InvokeOptions {
  /** XDRInternals cmdlet name. Only cmdlets exported by the module are accepted. */
  command: string;
  params?: Record<string, unknown>;
  timeoutSeconds?: number;
  /** Trim the returned record set to this many items (the untrimmed count is still reported). */
  maxItems?: number;
  /** Project each record down to these properties before serialization. */
  properties?: string[];
  /** JSON serialization depth for record content. */
  depth?: number;
}

export interface InvokeResult {
  items: unknown[];
  totalCount: number;
  truncated: boolean;
  warnings: string[];
  information: string[];
  errors: string[];
}

export interface CommandSummary {
  name: string;
  verb: string | null;
  noun: string | null;
  parameters: string[];
}

interface BridgeResponse {
  id?: string;
  ok: boolean;
  error?: string;
  data?: unknown;
}

interface Pending {
  resolve: (value: BridgeResponse) => void;
  reject: (reason: Error) => void;
  timer: NodeJS.Timeout;
}

/** Error raised for a failed cmdlet or bridge operation, already phrased for the model. */
export class XdrBridgeError extends Error {
  constructor(
    message: string,
    readonly detail?: { warnings?: string[]; information?: string[] },
  ) {
    super(message);
    this.name = "XdrBridgeError";
  }
}

export interface SessionState {
  connected: boolean;
  method?: string;
  connectedAt?: string;
  tenantId?: string;
  account?: string;
}

/**
 * Owns the long-lived PowerShell process that holds the XDRInternals session.
 *
 * The XDRInternals module keeps its portal cookies and XSRF token in module scope, so every tool
 * call has to reach the same PowerShell session. Requests are therefore serialized: the runspace
 * runs one pipeline at a time.
 */
class PowerShellBridge {
  private child?: ChildProcess;
  private reader?: Interface;
  private readonly pending = new Map<string, Pending>();
  private queue: Promise<unknown> = Promise.resolve();
  private nextId = 1;
  private stderrTail: string[] = [];
  private session: SessionState = { connected: false };

  getSession(): SessionState {
    return { ...this.session };
  }

  markConnected(method: string, details?: { tenantId?: string; account?: string }): void {
    this.session = {
      connected: true,
      method,
      connectedAt: new Date().toISOString(),
      ...(details?.tenantId ? { tenantId: details.tenantId } : {}),
      ...(details?.account ? { account: details.account } : {}),
    };
  }

  updateSessionDetails(details: { tenantId?: string; account?: string }): void {
    if (!this.session.connected) return;
    this.session = { ...this.session, ...details };
  }

  private start(): void {
    if (this.child && !this.child.killed && this.child.exitCode === null) return;

    if (!existsSync(config.hostScript)) {
      throw new XdrBridgeError(
        `The PowerShell bridge script is missing at ${config.hostScript}. Reinstall the MCP server package.`,
      );
    }

    const child = spawn(
      config.pwsh,
      [
        "-NoProfile",
        "-NoLogo",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        config.hostScript,
        "-ModulePath",
        config.modulePath,
      ],
      { stdio: ["pipe", "pipe", "pipe"], windowsHide: true },
    );

    child.on("error", (error) => {
      this.failAll(
        new XdrBridgeError(
          `Could not start PowerShell ('${config.pwsh}'): ${error.message}. Install PowerShell 7 or set XDR_MCP_PWSH to its full path.`,
        ),
      );
    });

    child.on("exit", (code, signal) => {
      const tail = this.stderrTail.join("\n").trim();
      this.failAll(
        new XdrBridgeError(
          `The PowerShell session ended unexpectedly (code ${code ?? "null"}, signal ${signal ?? "none"}).` +
            (tail ? ` Last output: ${tail}` : "") +
            " The XDR sign-in was lost; authenticate again before retrying.",
        ),
      );
      this.child = undefined;
      this.reader?.close();
      this.reader = undefined;
      this.session = { connected: false };
    });

    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => {
      for (const line of chunk.split(/\r?\n/)) {
        if (!line.trim()) continue;
        this.stderrTail.push(line);
        if (this.stderrTail.length > 40) this.stderrTail.shift();
        process.stderr.write(`[xdr-bridge] ${line}\n`);
      }
    });

    child.stdout?.setEncoding("utf8");
    this.reader = createInterface({ input: child.stdout! });
    this.reader.on("line", (line) => this.handleLine(line));

    this.child = child;
  }

  private handleLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) {
      if (trimmed) process.stderr.write(`[xdr-bridge] non-protocol output ignored: ${trimmed}\n`);
      return;
    }

    let response: BridgeResponse;
    try {
      response = JSON.parse(trimmed) as BridgeResponse;
    } catch {
      process.stderr.write(`[xdr-bridge] unparsable response ignored: ${trimmed.slice(0, 400)}\n`);
      return;
    }

    const id = response.id;
    if (!id) return;
    const pending = this.pending.get(id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pending.delete(id);
    pending.resolve(response);
  }

  private failAll(error: Error): void {
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  /** Sends one request, waiting for every earlier request to finish first. */
  private send(payload: Record<string, unknown>, timeoutSeconds: number): Promise<BridgeResponse> {
    const run = async (): Promise<BridgeResponse> => {
      this.start();
      const child = this.child;
      if (!child?.stdin) {
        throw new XdrBridgeError("The PowerShell session is not available. Retry the operation.");
      }

      const id = String(this.nextId++);
      const request = JSON.stringify({ ...payload, id });

      return await new Promise<BridgeResponse>((resolve, reject) => {
        const timer = setTimeout(() => {
          this.pending.delete(id);
          // The runspace may still be stuck on the abandoned pipeline; recycle the process.
          this.restart();
          reject(
            new XdrBridgeError(
              `The operation did not return within ${timeoutSeconds + 30}s and the PowerShell session was restarted. Narrow the time range, lower the page size, or raise XDR_MCP_TIMEOUT_SECONDS. You will need to sign in again.`,
            ),
          );
        }, (timeoutSeconds + 30) * 1000);

        this.pending.set(id, { resolve, reject, timer });
        child.stdin!.write(`${request}\n`, (error) => {
          if (!error) return;
          clearTimeout(timer);
          this.pending.delete(id);
          reject(new XdrBridgeError(`Failed to reach the PowerShell session: ${error.message}`));
        });
      });
    };

    const result = this.queue.then(run, run);
    // Keep the chain alive regardless of individual failures.
    this.queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  restart(): void {
    const child = this.child;
    this.child = undefined;
    this.reader?.close();
    this.reader = undefined;
    this.session = { connected: false };
    if (child && child.exitCode === null) {
      try {
        child.kill();
      } catch {
        // Already gone.
      }
    }
  }

  /** Drops all XDR session state by recreating the runspace inside the same process. */
  async reset(): Promise<void> {
    const response = await this.send({ op: "reset" }, 180);
    if (!response.ok) {
      throw new XdrBridgeError(response.error ?? "Failed to reset the PowerShell session.");
    }
    this.session = { connected: false };
  }

  async ping(): Promise<{ runspaceReady: boolean; module: string; pwshVersion: string }> {
    const response = await this.send({ op: "ping" }, 30);
    if (!response.ok) {
      throw new XdrBridgeError(response.error ?? "The PowerShell session did not answer.");
    }
    return response.data as { runspaceReady: boolean; module: string; pwshVersion: string };
  }

  async listCommands(): Promise<{ module: string; items: CommandSummary[]; totalCount: number }> {
    const response = await this.send({ op: "commands" }, 120);
    if (!response.ok) {
      throw new XdrBridgeError(response.error ?? "Failed to list XDRInternals cmdlets.");
    }
    return response.data as { module: string; items: CommandSummary[]; totalCount: number };
  }

  async help(command: string): Promise<InvokeResult> {
    const response = await this.send({ op: "help", command }, 90);
    if (!response.ok) {
      throw new XdrBridgeError(response.error ?? `Failed to read help for '${command}'.`);
    }
    return response.data as InvokeResult;
  }

  async invoke(options: InvokeOptions): Promise<InvokeResult> {
    const timeoutSeconds = options.timeoutSeconds ?? config.timeoutSeconds;
    const response = await this.send(
      {
        op: "invoke",
        command: options.command,
        params: options.params ?? {},
        timeoutSeconds,
        maxItems: options.maxItems ?? 0,
        properties: options.properties ?? [],
        depth: options.depth ?? 8,
      },
      timeoutSeconds,
    );

    if (!response.ok) {
      throw new XdrBridgeError(response.error ?? `'${options.command}' failed without a message.`);
    }

    const data = response.data as InvokeResult;
    return {
      items: data.items ?? [],
      totalCount: data.totalCount ?? 0,
      truncated: data.truncated ?? false,
      warnings: data.warnings ?? [],
      information: data.information ?? [],
      errors: data.errors ?? [],
    };
  }
}

export const bridge = new PowerShellBridge();
