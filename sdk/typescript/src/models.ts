/**
 * Data models for the ACF TypeScript SDK. They mirror sdk/python/acf/models.py.
 */

/** The three enforcement outcomes, with their wire values. */
export enum Decision {
  ALLOW = 0x00,
  SANITISE = 0x01,
  BLOCK = 0x02,
}

/** Map a response byte to a Decision; throws on an unknown byte. */
export function decisionFromByte(byte: number): Decision {
  if (byte === Decision.ALLOW || byte === Decision.SANITISE || byte === Decision.BLOCK) {
    return byte;
  }
  throw new FrameError(`unknown decision byte: 0x${byte.toString(16).padStart(2, "0")}`);
}

/** Returned when the sidecar decides SANITISE: use `sanitisedText` in place of the input. */
export interface SanitiseResult {
  decision: Decision.SANITISE;
  sanitisedPayload: Buffer;
  sanitisedText: string | null;
}

/** Where an untrusted value was read before reaching a tool argument. */
export interface TaintSource {
  hook: string;
  tool?: string;
}

/** One policy gate or validation failure behind a BLOCK decision. */
export interface BlockReason {
  code: string;
  stage?: string;
  tool?: string;
  param?: string;
  kind?: string;
  value?: string;
  sources?: TaintSource[];
  signal?: string;
  detail?: string;
}

/** Structured explanation attached to a BLOCK decision from the sidecar. */
export interface BlockInfo {
  hook: string;
  confirmable: boolean;
  reasons: BlockReason[];
  untrustedValues: string[];
}

/** Decode structured BlockInfo JSON from a BLOCK response payload. */
export function parseBlockInfo(raw: Buffer): BlockInfo | null {
  if (!raw || raw.length === 0) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const obj = parsed as Record<string, unknown>;
  const reasons: BlockReason[] = [];
  if (Array.isArray(obj.reasons)) {
    for (const item of obj.reasons) {
      if (!item || typeof item !== "object") continue;
      const r = item as Record<string, unknown>;
      if (typeof r.code !== "string" || !r.code) continue;
      const reason: BlockReason = { code: r.code };
      if (typeof r.stage === "string" && r.stage) reason.stage = r.stage;
      if (typeof r.tool === "string" && r.tool) reason.tool = r.tool;
      if (typeof r.param === "string" && r.param) reason.param = r.param;
      if (typeof r.kind === "string" && r.kind) reason.kind = r.kind;
      if (typeof r.value === "string" && r.value) reason.value = r.value;
      if (typeof r.signal === "string" && r.signal) reason.signal = r.signal;
      if (typeof r.detail === "string" && r.detail) reason.detail = r.detail;
      if (Array.isArray(r.sources)) {
        const sources: TaintSource[] = [];
        for (const s of r.sources) {
          if (s && typeof s === "object" && typeof (s as Record<string, unknown>).hook === "string") {
            const srcObj = s as Record<string, unknown>;
            const src: TaintSource = { hook: srcObj.hook as string };
            if (typeof srcObj.tool === "string" && srcObj.tool) src.tool = srcObj.tool;
            sources.push(src);
          }
        }
        if (sources.length > 0) reason.sources = sources;
      }
      reasons.push(reason);
    }
  }
  const accounts = reasons
    .filter((r) => r.code === "argument_taint" && (r.kind === "iban" || r.kind === "account") && r.value)
    .map((r) => r.value as string);
  const seen = new Set<string>();
  const untrustedValues: string[] = [];
  for (const r of reasons) {
    if (r.code !== "argument_taint" || !r.value) continue;
    if (r.kind === "number" && accounts.some((acct) => acct.includes(r.value as string))) continue;
    if (!seen.has(r.value)) {
      seen.add(r.value);
      untrustedValues.push(r.value);
    }
  }
  return {
    hook: typeof obj.hook === "string" ? obj.hook : "",
    confirmable: Boolean(obj.confirmable),
    reasons,
    untrustedValues,
  };
}

/** What a hook returns: a decision, or the sanitised replacement. */
export type HookResult = Decision.ALLOW | Decision.BLOCK | SanitiseResult;

/** Per-chunk result of `onContext`. */
export interface ChunkResult {
  original: string;
  decision: Decision;
  sanitisedText: string | null;
}

/** True when a hook result is a SanitiseResult. */
export function isSanitised(result: HookResult | Decision): result is SanitiseResult {
  return typeof result === "object" && result !== null && result.decision === Decision.SANITISE;
}

/** The Decision of any hook result. */
export function decisionOf(result: HookResult | Decision): Decision {
  return isSanitised(result) ? Decision.SANITISE : (result as Decision);
}

/** A declared task scope; see `Firewall.session`. */
export interface TaskScope {
  /** Tools the task may call. Must be within the sidecar's global allowlist. */
  allowedTools: string[];
  /** Values the user or developer vouches for; they are never treated as untrusted. */
  trustedValues?: string[];
  /** Per tool, per argument: `allowed` values, a `pattern`, and/or a numeric `max`. */
  toolConstraints?: Record<string, Record<string, { allowed?: unknown[]; pattern?: string; max?: number }>>;
}

/** Base class for SDK errors. */
export class FirewallError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The sidecar could not be reached after every retry. */
export class FirewallConnectionError extends FirewallError {}

/** A malformed frame was received. */
export class FrameError extends FirewallError {}

/** Thrown by adapters when a hook returns BLOCK. */
export class FirewallBlocked extends FirewallError {
  constructor(
    message: string,
    readonly hook?: string,
    readonly blockInfo?: BlockInfo | null,
  ) {
    super(message);
  }
}
