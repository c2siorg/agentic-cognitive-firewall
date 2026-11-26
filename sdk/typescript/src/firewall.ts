/**
 * Firewall: the policy enforcement point for a Node agent. Each hook builds a
 * RiskContext, signs it, sends it to the sidecar, and returns its decision.
 * The payload shapes match sdk/python/acf/firewall.py, so both SDKs talk to the
 * same sidecar and policies.
 *
 *   onPrompt(text)               the user's request
 *   onContext(chunks)            retrieved documents, one decision per chunk
 *   onToolCall(name, params)     before a tool runs
 *   onToolResult(tool, result)   before the model reads a tool's output
 *   onMemory(key, value, op)     memory reads and writes
 *   session(scope?)              a sequence of calls the sidecar treats as one run
 */
import { Session } from "./session";
import { DEFAULT_SOCKET_PATH, Transport } from "./transport";
import {
  BlockInfo,
  ChunkResult,
  Decision,
  decisionFromByte,
  FirewallError,
  HookResult,
  isSanitised,
  parseBlockInfo,
  SanitiseResult,
  TaskScope,
} from "./models";

export interface FirewallOptions {
  /** Socket or pipe path. Default: ACF_SOCKET_PATH, else /tmp/acf.sock or \\.\pipe\acf. */
  socketPath?: string;
  /** HMAC key bytes. Default: ACF_HMAC_KEY, hex-encoded. */
  hmacKey?: Buffer;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
}

export class Firewall {
  private readonly transport: Transport;
  private _lastBlock: BlockInfo | null = null;

  /** Structured reason for the most recent BLOCK decision, or null. */
  get lastBlock(): BlockInfo | null {
    return this._lastBlock;
  }

  constructor(options: FirewallOptions = {}) {
    let key = options.hmacKey;
    if (!key) {
      const raw = process.env.ACF_HMAC_KEY ?? "";
      if (!raw) throw new FirewallError("No HMAC key provided. Pass hmacKey or set ACF_HMAC_KEY (hex).");
      if (!/^([0-9a-fA-F]{2})+$/.test(raw)) throw new FirewallError("ACF_HMAC_KEY is not valid hex");
      key = Buffer.from(raw, "hex");
    }
    const path = options.socketPath ?? process.env.ACF_SOCKET_PATH ?? DEFAULT_SOCKET_PATH;
    this.transport = new Transport(path, key, options.timeoutMs);
  }

  /** Start a session. With a scope, the sidecar enforces it for every call in the session. */
  async session(scope?: TaskScope, sessionId?: string): Promise<Session> {
    return Session.open(this, scope, sessionId);
  }

  onPrompt(text: string): Promise<HookResult> {
    return this.call("on_prompt", text, "user", "");
  }

  onContext(chunks: string[]): Promise<ChunkResult[]> {
    return this.context(chunks, "");
  }

  onToolCall(name: string, params: Record<string, unknown>): Promise<HookResult> {
    return this.call("on_tool_call", { name, params }, "agent", "");
  }

  onToolResult(tool: string, result: unknown): Promise<HookResult> {
    return this.toolResult(tool, result, "");
  }

  onMemory(key: string, value: string, op: "read" | "write" = "write"): Promise<HookResult> {
    return this.call("on_memory", { key, value, op }, "agent", "");
  }

  // ── shared with Session ─────────────────────────────────────────────────

  /** @internal */
  async context(chunks: string[], sessionId: string): Promise<ChunkResult[]> {
    const results: ChunkResult[] = [];
    for (const chunk of chunks) {
      const result = await this.call("on_context", chunk, "rag", sessionId);
      results.push(
        isSanitised(result)
          ? { original: chunk, decision: Decision.SANITISE, sanitisedText: result.sanitisedText }
          : { original: chunk, decision: result, sanitisedText: null },
      );
    }
    return results;
  }

  /** @internal */
  async toolResult(tool: string, result: unknown, sessionId: string): Promise<HookResult> {
    const text = typeof result === "string" ? result : JSON.stringify(result);
    const decision = await this.call("on_tool_result", { tool, result: text }, "tool_output", sessionId);
    if (isSanitised(decision) && decision.sanitisedText) {
      // The sidecar wraps a sanitised object payload as {"sanitised": text}.
      try {
        const wrapped = JSON.parse(decision.sanitisedText);
        if (wrapped && typeof wrapped.sanitised === "string") decision.sanitisedText = wrapped.sanitised;
      } catch {
        // Not wrapped: keep the text as it is.
      }
    }
    return decision;
  }

  /** @internal Send one hook request and decode the decision. */
  async call(hookType: string, payload: unknown, provenance: string, sessionId: string): Promise<HookResult> {
    const context = {
      score: 0.0,
      signals: [],
      provenance,
      session_id: sessionId,
      hook_type: hookType,
      payload,
      state: null,
    };
    const response = await this.transport.send(Buffer.from(JSON.stringify(context), "utf8"));
    const decision = decisionFromByte(response.decision);
    if (decision !== Decision.SANITISE) {
      this._lastBlock = decision === Decision.BLOCK ? parseBlockInfo(response.sanitisedPayload) : null;
      return decision;
    }
    this._lastBlock = null;
    const result: SanitiseResult = {
      decision: Decision.SANITISE,
      sanitisedPayload: response.sanitisedPayload,
      sanitisedText: response.sanitisedPayload.length ? response.sanitisedPayload.toString("utf8") : null,
    };
    return result;
  }
}
