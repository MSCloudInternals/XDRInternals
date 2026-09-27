import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { fileURLToPath } from "node:url";

export type Operation = "list_incidents" | "get_incident" | "list_incident_alerts" | "list_alerts" | "list_devices" | "get_device" | "list_identities" | "get_identity" | "list_pending_actions" | "list_action_history" | "list_cloud_policies";

type Response = { id: string; ok: boolean; data?: unknown; error?: string };

export class BridgeError extends Error {
    constructor(readonly code: string) {
        super(code);
    }
}

export class ReadOnlyBridge {
    private child?: ChildProcessWithoutNullStreams;
    private closed = false;
    private outstanding = 0;
    private nextId = 0;
    private queue: Promise<void> = Promise.resolve();
    private pending = new Map<string, { resolve: (response: Response) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>();

    constructor(private readonly childEnv: NodeJS.ProcessEnv = process.env) { }

    private start(): ChildProcessWithoutNullStreams {
        if (this.closed) throw new BridgeError("session_lost");
        if (this.child) return this.child;
        const host = fileURLToPath(new URL("../bridge/ReadOnlyHost.ps1", import.meta.url));
        const child = spawn("pwsh", ["-NoProfile", "-NonInteractive", "-File", host], {
            stdio: ["pipe", "pipe", "pipe"],
            windowsHide: true,
            env: this.childEnv,
        });
        this.child = child;
        let buffer = "";
        const handleLine = (line: string) => {
            let response: Response;
            try {
                response = JSON.parse(line) as Response;
            } catch {
                return;
            }
            if (!response || typeof response !== "object" || typeof response.id !== "string" || typeof response.ok !== "boolean") return;
            const pending = this.pending.get(response.id);
            if (!pending) return;
            clearTimeout(pending.timer);
            this.pending.delete(response.id);
            pending.resolve(response);
        };
        child.stdout.setEncoding("utf8");
        child.stdout.on("data", (chunk: string) => {
            buffer += chunk;
            if (Buffer.byteLength(buffer, "utf8") > 256 * 1024) {
                this.stop(child);
                return;
            }
            let newline: number;
            while ((newline = buffer.indexOf("\n")) !== -1) {
                handleLine(buffer.slice(0, newline));
                buffer = buffer.slice(newline + 1);
            }
        });
        child.stderr.resume();
        child.stdin.on("error", () => this.stop(child));
        child.on("error", () => this.stop(child));
        child.on("exit", () => this.stop(child));
        return child;
    }

    private stop(child: ChildProcessWithoutNullStreams): void {
        if (this.child !== child) return;
        this.closed = true;
        this.child = undefined;
        child.kill();
        for (const pending of this.pending.values()) {
            clearTimeout(pending.timer);
            pending.reject(new BridgeError("session_lost"));
        }
        this.pending.clear();
    }

    async invoke(operation: Operation, args: Record<string, number | string>, signal?: AbortSignal): Promise<unknown> {
        if (this.closed) throw new BridgeError("session_lost");
        if (signal?.aborted) throw new BridgeError("request_cancelled");
        if (this.outstanding >= 8) throw new BridgeError("server_busy");
        const login = this.outstanding === 0 && ["browser", "software-passkey"].includes(this.childEnv.XDR_MCP_AUTH ?? "");
        const deadline = Date.now() + (login ? 360_000 : 60_000);
        this.outstanding++;
        const run = async (): Promise<unknown> => {
            if (signal?.aborted) throw new BridgeError("request_cancelled");
            if (this.closed) throw new BridgeError("session_lost");
            const remaining = deadline - Date.now();
            if (remaining <= 0) throw new BridgeError("session_timed_out");
            const child = this.start();
            const id = String(++this.nextId);
            const cancel = () => this.stop(child);
            signal?.addEventListener("abort", cancel, { once: true });
            try {
                const response = await new Promise<Response>((resolve, reject) => {
                    const timer = setTimeout(() => {
                        this.pending.delete(id);
                        this.stop(child);
                        reject(new BridgeError("session_timed_out"));
                    }, remaining);
                    this.pending.set(id, { resolve, reject, timer });
                    child.stdin.write(`${JSON.stringify({ id, operation, args })}\n`, (error) => {
                        if (error) this.stop(child);
                    });
                });
                if (!response.ok) throw new BridgeError(response.error ?? "operation_failed");
                return response.data;
            } finally {
                signal?.removeEventListener("abort", cancel);
            }
        };
        const result = this.queue.then(run);
        this.queue = result.then(() => { }, () => { });
        return result.finally(() => { this.outstanding--; });
    }

    close(): void {
        this.closed = true;
        if (this.child) this.stop(this.child);
    }
}