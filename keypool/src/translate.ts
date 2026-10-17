// @estate/keypool — OpenAI chat-completions <-> Gemini EAP Interactions.
//
// Port of keypool/translate.py. Implements the official Gemini Tool Retrieval
// (EAP) protocol:
//   - server-side retrieval via {"type":"tool_search"} + defer_loading:true
//   - OpenAI tools[].function unwrapped to Interactions function declarations
//   - tool results sent back as {"type":"function_result"} inputs
//   - Interactions steps (function_call / mcp_server_tool_call) returned as
//     OpenAI tool_calls
//
// The Python original survived the Bun cutover but nothing called it, so a pool
// declaring `protocol: gemini-interactions` silently forwarded an OpenAI body
// to /v1beta/interactions and every request 404'd. This is that translation,
// in the language the daemon actually runs.

type Json = Record<string, unknown>;

function isObj(v: unknown): v is Json {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Roost provider aliases -> real Gemini model IDs.
 * Source of truth for the alias side: ranch/mesh/catalog/src/data.ts
 * modelAliases (google.*). The Interactions API 404s unknown model names,
 * and the translation used to pass the alias straight through, so a caller
 * sending `gemini-eap` died with an upstream 404. Native Google IDs
 * (already `models/...`) pass through untouched.
 */
const GEMINI_ALIASES: Record<string, string> = {
	"gemini-eap": "models/gemini-flash-tool-retrieval",
	"gemini-3.8-flash": "models/gemini-3.8-flash",
	"gemini-3.7-flash": "models/gemini-3.7-flash",
	"gemini-3.6-flash": "models/gemini-3.6-flash",
	"gemini-3.5-flash": "models/gemini-3.5-flash",
	"gemini-3.1-pro": "models/gemini-3.1-pro-preview",
	"gemini-3-flash": "models/gemini-3-flash-preview",
	"gemini-2.5-flash": "models/gemini-2.5-flash",
};

export function resolveGeminiModel(model: unknown): unknown {
	if (typeof model !== "string") return model;
	return GEMINI_ALIASES[model] ?? model;
}

/**
 * OpenAI chat-completions request -> Gemini Interactions request.
 *
 * A body that already speaks Interactions (`input` present, `messages` absent)
 * passes through untouched, so a native client can hit the pool directly.
 */
export function openaiToInteractions(doc: unknown): unknown {
	if (!isObj(doc)) return doc;
	if ("input" in doc && !("messages" in doc)) return doc;

	const out: Json = { model: resolveGeminiModel(doc["model"]) };
	const messages = Array.isArray(doc["messages"]) ? (doc["messages"] as unknown[]) : [];

	// Tools: seed with tool_search, then defer every function declaration.
	const tools = doc["tools"];
	if (Array.isArray(tools) && tools.length > 0) {
		const eapTools: Json[] = [{ type: "tool_search" }];
		let hasFunctions = false;
		for (const raw of tools) {
			if (!isObj(raw)) continue;
			const ttype = raw["type"];
			if (ttype === "function") {
				const fn = isObj(raw["function"]) ? (raw["function"] as Json) : {};
				const name = (fn["name"] ?? raw["name"] ?? "") as string;
				const description = (fn["description"] ?? raw["description"] ?? "") as string;
				const parameters =
					fn["parameters"] ?? raw["parameters"] ?? { type: "object", properties: {} };
				eapTools.push({ type: "function", name, description, defer_loading: true, parameters });
				hasFunctions = true;
			} else if (ttype === "tool_search" || ttype === "mcp_server") {
				eapTools.push(raw);
			}
		}
		if (hasFunctions || eapTools.length > 1) out["tools"] = eapTools;
	}

	// Tool responses (turn 2+) become function_result inputs; otherwise the
	// conversation flattens to a role-prefixed string.
	const toolResults: Json[] = [];
	for (const raw of messages) {
		if (!isObj(raw) || raw["role"] !== "tool") continue;
		const rawContent = raw["content"];
		let result: unknown;
		if (typeof rawContent === "string") {
			try {
				result = JSON.parse(rawContent);
			} catch {
				result = { content: rawContent };
			}
		} else {
			result = rawContent;
		}
		toolResults.push({
			type: "function_result",
			name: raw["name"] ?? "",
			call_id: raw["tool_call_id"] ?? raw["id"] ?? "",
			result,
		});
	}

	if (toolResults.length > 0) {
		out["input"] = toolResults;
	} else {
		const parts: string[] = [];
		for (const raw of messages) {
			if (!isObj(raw)) continue;
			const role = (raw["role"] ?? "user") as string;
			let content = raw["content"];
			if (Array.isArray(content)) {
				content = (content as unknown[])
					.filter(isObj)
					.map(p => (typeof p["text"] === "string" ? p["text"] : ""))
					.join("");
			}
			parts.push(`${role}: ${content ?? ""}`);
		}
		out["input"] = parts.join("\n");
	}

	for (const k of ["previous_interaction_id", "stream"]) {
		if (k in doc) out[k] = doc[k];
	}
	return out;
}

/** Gemini Interactions response -> OpenAI chat-completions response. */
export function interactionsToOpenai(doc: unknown, model: string): unknown {
	if (!isObj(doc)) return doc;

	const steps = Array.isArray(doc["steps"]) ? (doc["steps"] as unknown[]) : [];
	const toolCalls: Json[] = [];
	const textChunks: string[] = [];

	steps.forEach((raw, idx) => {
		if (!isObj(raw)) return;
		const stype = raw["type"];
		if (stype === "function_call") {
			const args = raw["arguments"];
			toolCalls.push({
				id: (raw["id"] as string) ?? `call_eap_${idx}_${(raw["name"] as string) ?? "fn"}`,
				type: "function",
				function: {
					name: raw["name"] ?? "",
					arguments: JSON.stringify(args ?? {}),
				},
			});
		} else if (stype === "mcp_server_tool_call") {
			const server = (raw["server_name"] as string) ?? "mcp";
			const tname = (raw["name"] as string) ?? "";
			toolCalls.push({
				id: (raw["id"] as string) ?? `mcp_eap_${idx}`,
				type: "function",
				function: {
					name: server ? `${server}:${tname}` : tname,
					arguments: JSON.stringify(raw["arguments"] ?? {}),
				},
			});
		} else if (
			stype === "message" ||
			stype === "model_output" ||
			stype === "text" ||
			stype === "output_text"
		) {
			const c = raw["content"];
			if (typeof c === "string") textChunks.push(c);
			else if (Array.isArray(c)) {
				for (const part of c as unknown[]) {
					if (isObj(part) && typeof part["text"] === "string") textChunks.push(part["text"]);
				}
			}
		}
	});

	let message: Json;
	let finishReason: string;
	if (toolCalls.length > 0) {
		finishReason = "tool_calls";
		message = {
			role: "assistant",
			content: textChunks.length > 0 ? textChunks.join("") : null,
			tool_calls: toolCalls,
		};
	} else {
		finishReason = "stop";
		let text = textChunks.join("");
		if (!text) {
			text = typeof doc["output"] === "string" ? doc["output"] : "";
			if (!text && "error" in doc) text = JSON.stringify(doc["error"]);
		}
		message = { role: "assistant", content: text };
	}

	return {
		id: doc["id"] ?? "eap_interaction",
		object: "chat.completion",
		model,
		choices: [{ index: 0, message, finish_reason: finishReason }],
		usage: doc["usage"] ?? {},
		_eap_status: doc["status"],
		_eap_steps: steps.filter(isObj).map(s => s["type"]),
	};
}