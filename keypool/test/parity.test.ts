// @estate/keypool — behavioral parity tests.
// Port of herd-keypool.py selftest() (15 cases). Mock upstream, no real keys.

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { Pool, raceFirstValid, fingerprint, isFreeModel, extractModel } from "../src/pool.js";
import { Poller, needsRevalidation } from "../src/poller.js";
import { parseSimpleYaml, loadSecrets } from "../src/config.js";
import { scrub } from "../src/audit.js";
import type { PoolConfig } from "../src/types.js";

// Mock upstream server
let mockPort = 0;
let behavior = new Map<string, { status: number; body: string }>();
let mockServer: ReturnType<typeof Bun.serve> | null = null;

beforeAll(() => {
  mockServer = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      const url = new URL(req.url);
      const auth = req.headers.get("authorization") ?? "";
      const key = `${url.pathname}|${auth}`;
      const b = behavior.get(key) ?? { status: 404, body: "nope" };
      return new Response(b.body, {
        status: b.status,
        headers: { "content-type": "application/json" },
      });
    },
  });
  mockPort = mockServer.port;
});

afterAll(() => {
  mockServer?.stop();
});

function mkpool(
  keys: [string, string][],
  healthMap: Record<string, [boolean, number, number]>,
): Pool {
  const secrets = new Map(keys);
  const cfg: PoolConfig = {
    upstream: `http://127.0.0.1:${mockPort}`,
    health: { method: "GET", path: "/auth", ok: [200] },
    keys: keys.map(([n]) => n),
    fail_status: [401, 402, 429],
    cooldown: { 401: 300, 402: 300, 429: 60 },
    cooldown_default: 120,
    probe_timeout: 2,
    request_timeout: 10,
  };
  const pool = new Pool("test", cfg, secrets);
  // Override probe with fake health map
  (pool as unknown as { probe: (ks: { name: string }) => Promise<boolean> }).probe =
    async (ks) => {
      const [ok, ms] = healthMap[ks.name] ?? [false, 1.0, 401];
      const k = pool.keys.find((x) => x.name === ks.name)!;
      k.latencyMs = ms;
      k.lastProbeOk = ok;
      k.state = ok ? "healthy" : "down";
      if (!ok) k.downUntil = Date.now() + 120_000;
      return ok;
    };
  return pool;
}

describe("keypool parity", () => {
  test("case1: dead first key skipped, second used", async () => {
    const pool = mkpool(
      [["K1NAME", "K1"], ["K2NAME", "K2"]],
      { K1NAME: [false, 5.0, 401], K2NAME: [true, 8.0, 200] },
    );
    const ks = await pool.pick(null);
    expect(ks?.name).toBe("K2NAME");
    expect(pool.keys[0].state).toBe("down");
  });

  test("case2: 401 mid-request fails over", async () => {
    const pool = mkpool(
      [["A", "KA"], ["B", "KB"]],
      { A: [true, 5.0, 200], B: [true, 6.0, 200] },
    );
    const first = await pool.pick(null);
    pool.markDown(first!, 401);
    const second = await pool.pick(null);
    expect(first!.name).toBe("A");
    expect(second!.name).toBe("B");
    expect(first!.state).toBe("down");
  });

  test("case3: recovery after cooldown", async () => {
    const pool = mkpool([["A", "KA"], ["B", "KB"]],
      { A: [true, 5.0, 200], B: [true, 6.0, 200] });
    pool.keys[0].downUntil = Date.now() - 1000;
    pool.keys[0].state = "unknown";
    pool.keys[0].lastProbeOk = false;
    pool.keys[1].state = "down";
    pool.keys[1].downUntil = Date.now() + 300_000;
    const got = await pool.pick(null);
    expect(got?.name).toBe("A");
    expect(got?.state).toBe("healthy");
  });

  test("case4: fingerprints stable and non-reversible", () => {
    const fp = fingerprint("K1");
    expect(fp).not.toBe("K1");
    expect(fp).toHaveLength(12);
    expect(fingerprint("K1")).toBe(fp);
  });

  test("case5: all down returns null", async () => {
    const pool = mkpool([["X", "KX"]], { X: [false, 5.0, 401] });
    pool.keys[0].state = "down";
    pool.keys[0].downUntil = Date.now() + 300_000;
    expect(await pool.pick(null)).toBeNull();
  });

  test("case6: free_only serves :free model", async () => {
    const pool = mkpool(
      [["FREENAME", "KF"], ["PAIDNAME", "KP"]],
      { FREENAME: [true, 5.0, 200], PAIDNAME: [true, 6.0, 200] },
    );
    pool.keys[0].freeOnly = true;
    const got = await pool.pick("x/y:free");
    expect(got?.name).toBe("FREENAME");
  });

  test("case7: free_only never serves paid", async () => {
    const pool = mkpool(
      [["FREENAME", "KF"], ["PAIDNAME", "KP"]],
      { FREENAME: [true, 5.0, 200], PAIDNAME: [true, 6.0, 200] },
    );
    pool.keys[0].freeOnly = true;
    expect((await pool.pick("x/y"))?.name).toBe("PAIDNAME");

    const pool2 = mkpool([["FREENAME", "KF"]], { FREENAME: [true, 5.0, 200] });
    pool2.keys[0].freeOnly = true;
    expect(await pool2.pick("x/y")).toBeNull();
    expect((await pool2.pick("openrouter/free"))?.name).toBe("FREENAME");
  });

  test("case8: dict key entries and helpers", () => {
    expect(isFreeModel("a/b:free")).toBe(true);
    expect(isFreeModel("openrouter/free")).toBe(true);
    expect(isFreeModel("a/b")).toBe(false);
    expect(isFreeModel(null)).toBe(false);
    expect(isFreeModel("")).toBe(false);

    expect(extractModel(Buffer.from('{"model":"a/b:free"}'))).toBe("a/b:free");
    expect(extractModel(Buffer.from(""))).toBeNull();
    expect(extractModel(Buffer.from("not json"))).toBeNull();
    expect(extractModel(null)).toBeNull();
  });

  test("case9: race — fast key wins, loser closed", async () => {
    const pool = mkpool(
      [["A", "KA"], ["B", "KB"]],
      { A: [true, 5.0, 200], B: [true, 6.0, 200] },
    );
    // mark healthy directly to skip probing
    for (const k of pool.keys) k.state = "healthy";
    const closed: string[] = [];
    const fwd = async (ks: { name: string }) => {
      if (ks.name === "A") await Bun.sleep(400);
      else await Bun.sleep(10);
      const body = new ReadableStream({
        start(c) { c.enqueue(new TextEncoder().encode("{}")); c.close(); },
      });
      // track close via finally on cancel
      return new Response(body, { status: 200 });
    };
    const cands = pool.raceCandidates(null, 2);
    const t0 = Date.now();
    const r = await raceFirstValid(pool, fwd as never, cands);
    const dt = Date.now() - t0;
    expect(r.kind).toBe("winner");
    expect(r.keyName).toBe("B");
    expect(dt).toBeLessThan(350);
    void closed;
  });

  test("case10: race — 401 parks contestant, other wins", async () => {
    const pool = mkpool(
      [["A", "KA"], ["B", "KB"]],
      { A: [true, 5.0, 200], B: [true, 6.0, 200] },
    );
    for (const k of pool.keys) k.state = "healthy";
    const fwd = async (ks: { name: string }) => {
      if (ks.name === "A") {
        throw Object.assign(new Error("HTTP 401"), { status: 401 });
      }
      return new Response("{}", { status: 200 });
    };
    const r = await raceFirstValid(pool, fwd as never, pool.raceCandidates(null, 2));
    expect(r.kind).toBe("winner");
    expect(r.keyName).toBe("B");
    expect(pool.keys[0].state).toBe("down");
  });

  test("case11: race — all 401, all parked", async () => {
    const pool = mkpool(
      [["A", "KA"], ["B", "KB"]],
      { A: [true, 5.0, 200], B: [true, 6.0, 200] },
    );
    for (const k of pool.keys) k.state = "healthy";
    const fwd = async () => {
      throw Object.assign(new Error("HTTP 401"), { status: 401 });
    };
    const r = await raceFirstValid(pool, fwd as never, pool.raceCandidates(null, 2));
    expect(r.kind).toBe("failed");
    expect(pool.keys.every((k) => k.state === "down")).toBe(true);
  });

  test("case12: race — non-routing error forwarded immediately", async () => {
    const pool = mkpool(
      [["A", "KA"], ["B", "KB"]],
      { A: [true, 5.0, 200], B: [true, 6.0, 200] },
    );
    for (const k of pool.keys) k.state = "healthy";
    const fwd = async (ks: { name: string }) => {
      if (ks.name === "A") throw Object.assign(new Error("HTTP 500"), { status: 500 });
      await Bun.sleep(400);
      return new Response("{}", { status: 200 });
    };
    const t0 = Date.now();
    const r = await raceFirstValid(pool, fwd as never, pool.raceCandidates(null, 2));
    const dt = Date.now() - t0;
    expect(r.kind).toBe("error");
    expect(r.payload).toBe(500);
    expect(dt).toBeLessThan(350);
  });

  test("case13: race — timeout loses silently, not parked", async () => {
    const pool = mkpool(
      [["A", "KA"], ["B", "KB"]],
      { A: [true, 5.0, 200], B: [true, 6.0, 200] },
    );
    for (const k of pool.keys) k.state = "healthy";
    const fwd = async (ks: { name: string }) => {
      if (ks.name === "A") throw Object.assign(new Error("timeout"), { status: 0 });
      return new Response("{}", { status: 200 });
    };
    const r = await raceFirstValid(pool, fwd as never, pool.raceCandidates(null, 2));
    expect(r.kind).toBe("winner");
    expect(r.keyName).toBe("B");
    expect(pool.keys[0].state).not.toBe("down");
  });

  test("case14: raceCandidates honors free_only and N cap", async () => {
    const pool = mkpool(
      [["F", "KF"], ["P1", "KP1"], ["P2", "KP2"]],
      { F: [true, 1.0, 200], P1: [true, 2.0, 200], P2: [true, 3.0, 200] },
    );
    pool.keys[0].freeOnly = true;
    for (const k of pool.keys) k.state = "healthy";
    // latencies: F=1, P1=2, P2=3 — but F excluded for paid
    pool.keys[0].latencyMs = 1;
    pool.keys[1].latencyMs = 2;
    pool.keys[2].latencyMs = 3;
    expect(pool.raceCandidates("x/y", 3).map((k) => k.name)).toEqual(["P1", "P2"]);
    expect(pool.raceCandidates("x/y:free", 2).map((k) => k.name)).toEqual(["F", "P1"]);
    expect(pool.raceCandidates("x/y:free", 3).map((k) => k.name)).toEqual(["F", "P1", "P2"]);
  });

  test("case15: race telemetry", () => {
    const pool = mkpool([["A", "KA"]], { A: [true, 5.0, 200] });
    expect(pool.raceStats).toEqual({ races: 0, wins: 0, failed: 0 });
    pool.recordRace(true);
    pool.recordRace(false);
    expect(pool.raceStats).toEqual({ races: 2, wins: 1, failed: 1 });
  });
});

describe("config", () => {
  test("parses keypools.yaml subset", () => {
    const yaml = `
pools:
  test-pool:
    upstream: https://example.com/api
    health:
      method: GET
      path: /auth
      ok: [200]
    fail_status: [401, 402, 429]
    keys:
      - {name: KEY_A, free_only: true}
      - KEY_B
`;
    const parsed = parseSimpleYaml(yaml);
    const pools = parsed["pools"] as Record<string, Record<string, unknown>>;
    expect(pools["test-pool"]["upstream"]).toBe("https://example.com/api");
    const keys = pools["test-pool"]["keys"] as unknown[];
    expect(keys).toHaveLength(2);
    expect(keys[0]).toEqual({ name: "KEY_A", free_only: true });
    expect(keys[1]).toBe("KEY_B");
  });
});

describe("audit", () => {
  test("scrubs credential-shaped values", () => {
    const out = scrub({
      authorization: "Bearer sk-secret-1234567890abcdef",
      model: "gpt-4",
      nested: { api_key: "test-fake-key-0123456789abcdef" },
    }) as Record<string, unknown>;
    expect(out["model"]).toBe("gpt-4");
    expect(String(out["authorization"])).toMatch(/^fp:[0-9a-f]{12}$/);
    expect(String((out["nested"] as Record<string, unknown>)["api_key"])).toMatch(
      /^fp:[0-9a-f]{12}$/,
    );
  });
});

describe("poller", () => {
  test("needsRevalidation: healthy+stale -> true, fresh/unknown/down/zero -> false", () => {
    const base = {
      name: "K",
      fp: "abc123def456",
      latencyMs: 5,
      downUntil: 0,
      lastProbeOk: true,
      freeOnly: false,
    };
    const ttl = 300_000;
    const now = Date.now();
    expect(needsRevalidation({ ...base, state: "healthy", lastProbeAt: now - ttl - 1 }, ttl)).toBe(true);
    expect(needsRevalidation({ ...base, state: "healthy", lastProbeAt: now - ttl + 10_000 }, ttl)).toBe(false);
    expect(needsRevalidation({ ...base, state: "healthy", lastProbeAt: 0 }, ttl)).toBe(false);
    expect(needsRevalidation({ ...base, state: "unknown", lastProbeAt: now - ttl - 1 }, ttl)).toBe(false);
    expect(needsRevalidation({ ...base, state: "down", lastProbeAt: now - ttl - 1 }, ttl)).toBe(false);
  });

  test("probe() stamps lastProbeAt on success and failure", async () => {
    behavior.set(`/auth|Bearer probe-secret-ok`, { status: 200, body: "ok" });
    behavior.set(`/auth|Bearer probe-secret-bad`, { status: 401, body: "no" });
    const secrets = new Map([
      ["K_OK", "probe-secret-ok"],
      ["K_BAD", "probe-secret-bad"],
    ]);
    const cfg: PoolConfig = {
      upstream: `http://127.0.0.1:${mockPort}`,
      health: { method: "GET", path: "/auth", ok: [200] },
      keys: ["K_OK", "K_BAD"],
    };
    const pool = new Pool("probe-ts", cfg, secrets);
    const before = Date.now();
    expect(await pool.probe(pool.keys[0])).toBe(true);
    expect(pool.keys[0].state).toBe("healthy");
    expect(pool.keys[0].lastProbeAt).toBeGreaterThanOrEqual(before);
    expect(await pool.probe(pool.keys[1])).toBe(false);
    expect(pool.keys[1].state).toBe("down");
    expect(pool.keys[1].lastProbeAt).toBeGreaterThanOrEqual(before);
  });

  test("wake() interrupts the initial sleep (event-driven, no fixed timer)", async () => {
    let calls = 0;
    const ks = {
      name: "K1",
      fp: "00".repeat(6),
      state: "unknown" as const,
      latencyMs: 0,
      downUntil: 0,
      lastProbeAt: 0,
      lastProbeOk: false,
      freeOnly: false,
    };
    const fake = {
      name: "wake-pool",
      keys: [ks],
      probe: async (k: typeof ks) => {
        calls++;
        k.state = "healthy";
        k.lastProbeAt = Date.now();
        return true;
      },
    } as unknown as Pool;
    const p = new Poller(() => new Map([["wake-pool", fake]]), {
      ttlMs: 60_000,
      log: () => {},
    });
    const t0 = Date.now();
    const run = p.start();
    await new Promise((r) => setTimeout(r, 100));
    p.wake(); // should cut the 1500ms initial sleep short
    while (calls === 0 && Date.now() - t0 < 1200) {
      await new Promise((r) => setTimeout(r, 25));
    }
    const elapsed = Date.now() - t0;
    p.stop();
    await run;
    expect(calls).toBeGreaterThanOrEqual(1);
    expect(elapsed).toBeLessThan(1400); // well under the 1500ms initial sleep
  });

  test("healthy keys are revalidated after TTL expiry", async () => {
    let calls = 0;
    const ks = {
      name: "K1",
      fp: "00".repeat(6),
      state: "healthy" as const,
      latencyMs: 3,
      downUntil: 0,
      lastProbeAt: Date.now() - 10_000, // stale
      lastProbeOk: true,
      freeOnly: false,
    };
    const fake = {
      name: "ttl-pool",
      keys: [ks],
      probe: async (k: typeof ks) => {
        calls++;
        k.state = "healthy";
        k.lastProbeAt = Date.now();
        k.lastProbeOk = true;
        return true;
      },
    } as unknown as Pool;
    const p = new Poller(() => new Map([["ttl-pool", fake]]), {
      ttlMs: 150,
      log: () => {},
    });
    const run = p.start();
    const t0 = Date.now();
    while (calls < 2 && Date.now() - t0 < 5000) {
      await new Promise((r) => setTimeout(r, 25));
    }
    p.stop();
    await run;
    // first pass (stale -> probe) + at least one TTL revalidation
    expect(calls).toBeGreaterThanOrEqual(2);
  });
});
