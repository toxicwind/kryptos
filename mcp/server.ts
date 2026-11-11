#!/usr/bin/env bun
// kryptos-mcp — the ONLY sanctioned agent surface into the kryptos keyring.
//
// Doctrine (RULES.md 2026-11-08): kryptos/keypool/secretsmith CLIs are banned
// in agent bash/eval shells. Agents read secrets through THIS MCP server,
// federated by the thresher gateway (tau + kappa both point at :25127).
// Services (mimetite serve.sh, aiostreams serve.sh, thresher-serve) keep
// sourcing `kryptos --json env` directly — that lane is daemon-only.
//
// Stdio MCP (JSON-RPC 2.0, newline-delimited) — zero deps, spawns `kryptos`
// as a subprocess per call (the subprocess is the daemon's own lane, not the
// agent's shell, so the bash ban stays intact while the keyring stays
// reachable).
//
// Tools:
//   kryptos_get(label, attr?)          -> one item's secret (label match, no fuzzy by default)
//   kryptos_search(query, schema?)     -> matching labels/attrs, NEVER values
//   kryptos_env(app?)                  -> env exports (k=v map); values included (this is the sanctioned read)

import { spawn } from "node:child_process";

const KRYPTOS = "kryptos";

function kryptosJson(args: string[]): Promise<any> {
	return new Promise((resolve, reject) => {
		const p = spawn(KRYPTOS, args, { stdio: ["ignore", "pipe", "pipe"] });
		let out = "";
		let err = "";
		p.stdout.on("data", (d) => (out += d));
		p.stderr.on("data", (d) => (err += d));
		p.on("close", (code) => {
			if (code !== 0) return reject(new Error(err.trim() || `kryptos exited ${code}`));
			try {
				resolve(JSON.parse(out));
			} catch {
				reject(new Error(`kryptos --json produced non-JSON output: ${out.slice(0, 200)}`));
			}
		});
		p.on("error", reject);
	});
}

const TOOLS = [
	{
		name: "kryptos_get",
		description:
			"Fetch ONE secret from the kryptos keyring by label (exact match; add --no-fuzzy off via attrs). Prefer kryptos_env for a whole service's exports.",
		inputSchema: {
			type: "object",
			properties: {
				label: { type: "string", description: "Keyring label, e.g. FREEINFERENCE_API_KEY" },
				attr: { type: "string", description: "Optional k=v attribute filter, e.g. app=aiostreams" },
			},
			required: ["label"],
		},
	},
	{
		name: "kryptos_search",
		description:
			"Search keyring LABELS/ATTRIBUTES matching a query. Returns labels + attrs only — never secret values.",
		inputSchema: {
			type: "object",
			properties: {
				query: { type: "string", description: "Label substring, e.g. GITHUB" },
			},
			required: ["query"],
		},
	},
	{
		name: "kryptos_env",
		description:
			"Get the env exports map (KEY=value) for the whole keyring or one app (service attribute). The sanctioned bulk read for wiring a service.",
		inputSchema: {
			type: "object",
			properties: {
				app: { type: "string", description: "Optional app/service attribute filter, e.g. mimetite" },
			},
		},
	},
	{
		name: "kryptos_set",
		description:
			"Create or replace ONE keyring item (label + value). The sanctioned write surface — spawns the kryptos CLI as the daemon lane, never the agent shell. Add attrs like app=<service> for kryptos_env filtering.",
		inputSchema: {
			type: "object",
			properties: {
				label: { type: "string", description: "Keyring label, e.g. CLOUDFLARE_API_TOKEN" },
				value: { type: "string", description: "Secret value (single-line; use secret_file for multiline)" },
				attr: { type: "string", description: "Optional k=v attribute, repeat via comma, e.g. app=dedicated,service=cloudflare" },
				secret_file: { type: "string", description: "Optional path to a file for multiline/binary secrets (overrides value)" },
			},
			required: ["label"],
		},
	},
	{
		name: "kryptos_delete",
		description:
			"Delete ONE keyring item by label (+ optional attr filter). For cleanup of stale/rotated entries. Returns the deleted item path.",
		inputSchema: {
			type: "object",
			properties: {
				label: { type: "string", description: "Keyring label, e.g. CLOUDFLARE_API_TOKEN" },
				attr: { type: "string", description: "Optional k=v attribute, repeat via comma — narrows which item is deleted when labels collide" },
			},
			required: ["label"],
		},
	},
] as const;

async function callTool(name: string, args: any): Promise<unknown> {
	switch (name) {
		case "kryptos_get": {
			const a = ["get", String(args.label), "--json"];
			if (args.attr) a.push("--attr", String(args.attr));
			const out = await kryptosJson(a);
			return out;
		}
		case "kryptos_search": {
			const out = await kryptosJson(["search", String(args.query), "--json"]);
			// Labels + attrs only: strip secret values defensively.
			const items = Array.isArray(out) ? out : (out.items ?? out.results ?? []);
			const safe = (Array.isArray(items) ? items : []).map((it: any) => ({
				label: it.label ?? it.attributes?.label,
				attrs: it.attributes ?? it.attrs,
			}));
			return safe;
		}
		case "kryptos_env": {
			const out = await kryptosJson(["--json", "env"]);
			const exports = out.exports ?? {};
			if (!args.app) return exports;
			const filtered = Object.fromEntries(
				Object.entries(exports).filter(([k]) => k.startsWith(String(args.app).toUpperCase().replace(/-/g, "_"))),
			);
			return filtered;
		}
		case "kryptos_set": {
			const a = ["set", "--label", String(args.label), "--replace", "--json"];
			if (args.secret_file) a.push("--secret-file", String(args.secret_file));
			else {
				if (args.value === undefined) throw new Error("kryptos_set requires value or secret_file");
				a.push("--value", String(args.value));
			}
			for (const pair of String(args.attr ?? "").split(",").map((s) => s.trim()).filter(Boolean))
				a.push("--attr", pair);
			return await kryptosJson(a);
		}
		case "kryptos_delete": {
			const a = ["delete", String(args.label), "--yes", "--json"];
			for (const pair of String(args.attr ?? "").split(",").map((s) => s.trim()).filter(Boolean))
				a.push("--attr", pair);
			return await kryptosJson(a);
		}
		default:
			throw new Error(`unknown tool ${name}`);
	}
}

function reply(id: number | string, result: unknown): void {
	process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}

function replyErr(id: number | string, code: number, message: string): void {
	process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n");
}

interface Msg {
	jsonrpc?: string;
	id?: number | string;
	method?: string;
	params?: any;
}

async function handle(msg: Msg): Promise<void> {
	if (msg.id === undefined || msg.method === undefined) return;
	const { id, method, params } = msg;
	if (method === "initialize") {
		reply(id, {
			protocolVersion: params?.protocolVersion ?? "2024-11-05",
			capabilities: { tools: {} },
			serverInfo: { name: "kryptos-mcp", version: "1.0.0" },
		});
		return;
	}
	if (method === "tools/list") {
		reply(id, { tools: TOOLS });
		return;
	}
	if (method === "tools/call") {
		const name = params?.name as string;
		try {
			const result = await callTool(name, params?.arguments ?? {});
			reply(id, { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] });
		} catch (e) {
			reply(id, { content: [{ type: "text", text: `kryptos error: ${String(e)}` }], isError: true });
		}
		return;
	}
	replyErr(id, -32601, `method not found: ${method}`);
}

const bufs: Buffer[] = [];
process.stdin.on("data", (d: Buffer) => {
	bufs.push(d);
	let s = Buffer.concat(bufs).toString("utf8");
	let idx: number;
	while ((idx = s.indexOf("\n")) >= 0) {
		const line = s.slice(0, idx).trim();
		s = s.slice(idx + 1);
		bufs.length = 0;
		bufs.push(Buffer.from(s));
		if (!line) continue;
		try {
			const msg = JSON.parse(line) as Msg;
			void handle(msg).catch((e) => msg.id !== undefined && replyErr(msg.id, -32603, String(e)));
		} catch {
			/* non-JSON line: ignore */
		}
	}
});
process.stdin.on("end", () => process.exit(0));
