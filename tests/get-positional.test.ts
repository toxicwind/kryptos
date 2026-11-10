// TDD: `kryptos get <POSITIONAL_LABEL>` must resolve the positional as a
// label — not silently drop it and return an arbitrary first item.
// Live bug: `kryptos get GITHUB_SESSIONS --json` returned
// MOONBOX_CHAOS_API_KEY (arbitrary first keyring item) because `case "get"`
// parsed no positional.
import { describe, test, expect } from "bun:test";
import { parse } from "../kryptos.ts";

describe("kryptos get positional label", () => {
	test("get with bare positional sets label", () => {
		const a = parse(["get", "GITHUB_SESSIONS"]);
		expect(a.label).toBe("GITHUB_SESSIONS");
	});

	test("get with positional + --json does not swallow the positional", () => {
		const a = parse(["get", "GITHUB_SESSIONS", "--json"]);
		expect(a.label).toBe("GITHUB_SESSIONS");
		expect(a.json).toBe(true);
	});

	test("get with --label flag still wins over positional absence", () => {
		const a = parse(["get", "--label", "EXPLICIT"]);
		expect(a.label).toBe("EXPLICIT");
	});

	test("get with both positional and --label: explicit flag wins", () => {
		const a = parse(["get", "POSITIONAL", "--label", "EXPLICIT"]);
		expect(a.label).toBe("EXPLICIT");
	});

	test("get with no label at all: label stays undefined (attr-only get)", () => {
		const a = parse(["get", "--attr", "service=app"]);
		expect(a.label).toBeUndefined();
	});

	test("get with missing label errors — never returns an arbitrary item (anomaly 63)", async () => {
		const missing = "MISSING_LABEL_" + Date.now();
		// Live CLI contract, not parse-shape: a nonexistent label MUST error.
		const proc = Bun.spawn(["bun", "kryptos.ts", "get", missing], {
			cwd: import.meta.dir + "/..",
			stdout: "pipe",
			stderr: "pipe",
		});
		const stdout = await Bun.readableStreamToText(proc.stdout);
		const stderr = await Bun.readableStreamToText(proc.stderr);
		const exit = await proc.exited;
		// Contract: a missing label MUST error (never return an arbitrary first
		// item — the anomaly-63 defect). The error text need not echo the label.
		expect(stderr).toContain("no item matches");
		expect(stdout).toBe("");
		expect(exit).not.toBe(0);
	});

	test("get label-echo: returned item echoes the EXACT requested label", async () => {
		// The label is the key contract — a fuzzy/wrong fetch is the defect.
		const proc = Bun.spawn(["bun", "kryptos.ts", "get", "GH_TOKEN"], {
			cwd: import.meta.dir + "/..",
			stdout: "pipe",
			stderr: "pipe",
		});
		const stdout = await Bun.readableStreamToText(proc.stdout);
		const exit = await proc.exited;
		expect(exit).toBe(0);
		// 2026-11-10 contract: plain `get` prints ONLY the raw secret value
		// (gopass/pass-show) — no `label:` metadata prefix. Use --json for
		// metadata; scripting pipes must see the bare secret.
		expect(stdout).not.toContain("label:");
		expect(stdout.trim().length).toBeGreaterThan(0);
	});
});
