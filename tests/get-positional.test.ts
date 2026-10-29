// TDD: `secretsmith get <POSITIONAL_LABEL>` must resolve the positional as a
// label — not silently drop it and return an arbitrary first item.
// Live bug: `secretsmith get GITHUB_SESSIONS --json` returned
// MOONBOX_CHAOS_API_KEY (arbitrary first keyring item) because `case "get"`
// parsed no positional.
import { describe, test, expect } from "bun:test";
import { parse } from "../secretsmith.ts";

describe("secretsmith get positional label", () => {
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
});
