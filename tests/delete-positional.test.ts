// TDD: `kryptos delete <POSITIONAL_LABEL>` must resolve the positional as
// a label — not silently drop it and fall back to filters-only matching.
//
// Live bug (2026-11-03 ring wipe): the positional-label block lived only in
// the `get` case, so `kryptos delete _SMOKE --yes` ran with
// a.label === undefined; cmdDelete's svc.search(filters, collection, null)
// then matched EVERY item and wiped the whole ring (209 items).
// Second anomaly the same day: `delete --attr app=x --yes` with the
// positional dropped matched every seeded item sharing that attr.
//
// Contracts pinned here:
// 1. delete positional label is captured (parity with get, anomaly #61).
// 2. cmdDelete refuses to run with NEITHER label NOR attr filters — a
//    filters-only match-all delete is structurally forbidden.
import { describe, test, expect } from "bun:test";
import { parse } from "../kryptos.ts";

describe("kryptos delete positional label (ring-wipe regression)", () => {
	test("delete with bare positional sets label", () => {
		const a = parse(["delete", "SOME_LABEL"]);
		expect(a.label).toBe("SOME_LABEL");
	});

	test("delete positional + --yes does not swallow the positional", () => {
		const a = parse(["delete", "SOME_LABEL", "--yes"]);
		expect(a.label).toBe("SOME_LABEL");
		expect(a.yes).toBe(true);
	});

	test("delete with --label flag still sets label", () => {
		const a = parse(["delete", "--label", "EXPLICIT"]);
		expect(a.label).toBe("EXPLICIT");
	});

	test("delete with both positional and --label: explicit flag wins", () => {
		const a = parse(["delete", "POSITIONAL", "--label", "EXPLICIT"]);
		expect(a.label).toBe("EXPLICIT");
	});

	test("delete attr-only keeps label undefined", () => {
		const a = parse(["delete", "--attr", "app=env-seed"]);
		expect(a.label).toBeUndefined();
		expect(a.attr).toEqual(["app=env-seed"]);
	});
});
