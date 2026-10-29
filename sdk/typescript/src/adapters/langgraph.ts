/**
 * LangGraph.js adapter: a node function that runs one hook on a value in state.
 *
 * LangGraph.js is not a dependency: the node is a plain async function from
 * state to a state update, which is what `graph.addNode` accepts.
 *
 *   graph.addNode("promptGuard", firewallNode(fw, "onPrompt", "userMessage"));
 *
 * On BLOCK the node throws FirewallBlocked, stopping the run. On SANITISE it
 * writes the cleaned value to `outputKey` (default: the input key). Pass a
 * Session instead of a Firewall to enforce its task scope and provenance rule.
 *
 * To guard the tools an agent calls, use `guardTool` from ./tools instead.
 */
import type { Firewall } from "../firewall";
import type { Session } from "../session";
import { Decision, FirewallBlocked, FirewallError, isSanitised } from "../models";

export type Guard = Firewall | Session;
export type NodeHook = "onPrompt" | "onContext" | "onToolResult";

export function firewallNode<State extends Record<string, unknown>>(
  guard: Guard,
  hook: NodeHook,
  inputKey: keyof State & string,
  outputKey: keyof State & string = inputKey,
): (state: State) => Promise<Partial<State>> {
  return async (state: State) => {
    if (!(inputKey in state)) {
      throw new FirewallError(`firewallNode: state is missing required key "${inputKey}"`);
    }
    const value = state[inputKey];
    if (hook === "onContext") {
      if (!Array.isArray(value)) throw new TypeError(`${inputKey} must be a list of strings`);
      const results = await guard.onContext(value as string[]);
      if (results.some((r) => r.decision === Decision.BLOCK)) {
        throw new FirewallBlocked(`firewall node blocked ${inputKey} at onContext`, "on_context");
      }
      return { [outputKey]: results.map((r) => r.sanitisedText ?? r.original) } as Partial<State>;
    }
    if (hook === "onPrompt" && typeof value !== "string") {
      throw new TypeError(`${inputKey} must be a string`);
    }
    const result =
      hook === "onPrompt"
        ? await guard.onPrompt(value as string)
        : await guard.onToolResult(String((state as Record<string, unknown>).tool ?? "tool"), value);
    if (result === Decision.BLOCK) {
      throw new FirewallBlocked(`firewall node blocked ${inputKey} at ${hook}`, hook);
    }
    if (isSanitised(result)) return { [outputKey]: result.sanitisedText } as Partial<State>;
    return {};
  };
}
