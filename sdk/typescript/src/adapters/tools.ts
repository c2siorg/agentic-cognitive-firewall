/**
 * Guard any async tool function with ACF.
 *
 * `guardTool` returns a function with the same signature that calls
 * `onToolCall` before the tool runs and `onToolResult` on its output before the
 * agent reads it. A blocked call never runs and resolves to a refusal the agent
 * can read; a sanitised result replaces the output. It works with LangChain.js
 * `tool(...)` definitions, the Vercel AI SDK, or a hand-written agent loop:
 *
 *   const sendMoney = guardTool(session, "send_money", rawSendMoney);
 */
import type { Firewall } from "../firewall";
import type { Session } from "../session";
import { BlockInfo, Decision, FirewallBlocked, isSanitised } from "../models";

export const BLOCKED_CALL = (tool: string) => `Blocked by policy: ${tool} may not run with these arguments.`;
export const WITHHELD_RESULT = (tool: string) => `[The result of ${tool} was withheld by policy.]`;

export interface GuardToolOptions {
  /** Throw FirewallBlocked instead of returning a refusal when a call is blocked. */
  throwOnBlock?: boolean;
  /**
   * Optional confirmation handler called only when onToolCall blocks solely
   * on confirmable argument taint (`info.confirmable === true`). Returning
   * true approves `info.untrustedValues` via `session.confirm` and retries
   * the tool call once.
   */
  confirm?: (info: BlockInfo) => Promise<boolean> | boolean;
}

export function guardTool<Args extends Record<string, unknown>, Out>(
  guard: Firewall | Session,
  name: string,
  fn: (args: Args) => Promise<Out> | Out,
  options: GuardToolOptions = {},
): (args: Args) => Promise<Out | string> {
  return async (args: Args) => {
    const allowedAfterConfirm = async (): Promise<boolean> => {
      const info = guard.lastBlock ?? null;
      if (
        !options.confirm ||
        !("confirm" in guard) ||
        typeof guard.confirm !== "function" ||
        !info?.confirmable ||
        info.untrustedValues.length === 0
      ) {
        return false;
      }
      if (!(await options.confirm(info))) return false;
      if ((await guard.confirm(info.untrustedValues)) !== Decision.ALLOW) return false;
      return (await guard.onToolCall(name, args)) !== Decision.BLOCK;
    };

    if ((await guard.onToolCall(name, args)) === Decision.BLOCK && !(await allowedAfterConfirm())) {
      if (options.throwOnBlock) {
        throw new FirewallBlocked(`ACF blocked ${name}`, "on_tool_call", guard.lastBlock ?? null);
      }
      return BLOCKED_CALL(name);
    }
    const output = await fn(args);
    const screened = await guard.onToolResult(name, output);
    if (isSanitised(screened)) return screened.sanitisedText ?? "";
    if (screened === Decision.BLOCK) return WITHHELD_RESULT(name);
    return output;
  };
}
