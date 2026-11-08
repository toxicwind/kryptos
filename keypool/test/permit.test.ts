// @estate/keypool — permit client contract tests (TDD RED→GREEN).
// Pins: coordinator-unreachable degrades to permit-less forwarding;
// coordinator {ok:false} sheds with 503; release never throws.

import { describe, test, expect } from "bun:test";
import { makePermitClient, isConnRefused } from "../src/permit.ts";

function refusedFetcher(): typeof fetch {
	return ((_input, _init) => {
		const e = new TypeError("fetch failed");
		(e as Error & { cause?: unknown }).cause = new Error(
			"ECONNREFUSED: Unable to connect. Is the computer able to access the url?",
		);
		return Promise.reject(e);
	}) as unknown as typeof fetch;
}

describe("permit client", () => {
	test("connection-refused coordinator degrades to null permit (no throw)", async () => {
		const client = makePermitClient("http://127.0.0.1:1", refusedFetcher());
		const permit = await client.acquire("deepseek-v4-flash", "sess-1");
		expect(permit).toBeNull();
	});

	test("coordinator {ok:false} sheds with 503 + retryAfter (deliberate, not outage)", async () => {
		const shedFetcher = ((_input, _init) =>
			Promise.resolve(
				new Response(JSON.stringify({ ok: false, error: "model saturated" }), {
					status: 429,
					headers: { "content-type": "application/json" },
				}),
			)) as unknown as typeof fetch;
		const client = makePermitClient("http://coord", shedFetcher);
		let err: unknown = null;
		try {
			await client.acquire("deepseek-v4-flash", null);
		} catch (e) {
			err = e;
		}
		expect(err).not.toBeNull();
		expect((err as { status?: number }).status).toBe(503);
		expect((err as { retryAfter?: number }).retryAfter).toBe(1000);
	});

	test("coordinator {ok:true} returns requestId", async () => {
		const okFetcher = ((_input, _init) =>
			Promise.resolve(
				new Response(JSON.stringify({ ok: true, requestId: "perm-7" }), {
					status: 200,
					headers: { "content-type": "application/json" },
				}),
			)) as unknown as typeof fetch;
		const client = makePermitClient("http://coord", okFetcher);
		expect(await client.acquire("glm-5.3-flash", null)).toBe("perm-7");
	});

	test("release never throws even when coordinator is dead", async () => {
		const client = makePermitClient("http://127.0.0.1:1", refusedFetcher());
		expect(() => client.release("perm-7", "deepseek-v4-flash")).not.toThrow();
	});

	test("isConnRefused classifies transport failures, not HTTP statuses", () => {
		const refused = new TypeError("fetch failed");
		(refused as Error & { cause?: unknown }).cause = new Error("ECONNREFUSED");
		expect(isConnRefused(refused)).toBe(true);
		expect(isConnRefused(new Error("HTTP 500"))).toBe(false);
	});
});
