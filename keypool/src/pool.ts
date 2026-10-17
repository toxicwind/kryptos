// @estate/keypool — Pool: key health, selection, failover, racing.
// Port of herd-keypool.py Pool/KeyState/race_first_valid. Parity contract:
// - states: unknown -> healthy -> down -> (cooldown) -> unknown
// - pick(): healthy first, then unknown, then down-if-cooldown-expired
// - fail_status (401/402/429) parks only that key with per-status cooldown
// - race: first-valid-wins, losers closed, routing errors park contestant

import type { KeyState, PoolConfig, RaceResult } from "./types.js";
import { createHash } from "node:crypto";

export function fingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 12);
}

export function isFreeModel(model: string | null | undefined): boolean {
  if (!model) return false;
  return model === "openrouter/free" || model.endsWith(":free");
}

export function extractModel(body: Uint8Array | null): string | null {
  if (!body || body.length === 0) return null;
  try {
    const parsed = JSON.parse(Buffer.from(body).toString("utf8"));
    const m = parsed?.model;
    return typeof m === "string" ? m : null;
  } catch {
    return null;
  }
}
/**
 * How a given upstream expects the pool's key to be presented.
 *
 * The probe path learned this by inspection (an upstream ending in `/openai`
 * takes a bearer token, Google AI takes `x-goog-api-key`). The forwarding path
 * did not: it always sent `Authorization: Bearer`, so every Google-native pool
 * answered 401 ACCESS_TOKEN_TYPE_UNSUPPORTED even though the same key passed
 * `probe()` moments earlier. A pool that probes healthy but 401s on every
 * request is the signature of that split.
 *
 * Both paths now resolve the header through this one function so a new
 * upstream cannot be half-wired again.
 */
export function upstreamAuthHeader(upstream: string, secret: string): [string, string] {
	if (upstream.endsWith("/openai")) {
		return ["Authorization", `Bearer ${secret}`];
	}
	if (upstream.includes("generativelanguage.googleapis.com")) {
		return ["x-goog-api-key", secret];
	}
	return ["Authorization", `Bearer ${secret}`];
}

export class Pool {
  readonly name: string;
  readonly upstream: string;
  readonly healthMethod: string;
  readonly healthPath: string;
  readonly healthOk: Set<number>;
  readonly failStatus: Set<number>;
  readonly probeTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly cooldown: Map<number, number>;
  /** Wire protocol. `gemini-interactions` rewrites the request body and posts
   *  to `interactionsPath` instead of forwarding to `upstream + rest`. */
  readonly protocol: "gemini-interactions" | undefined;
  readonly interactionsPath: string;
  readonly cooldownDefault: number;
  keys: KeyState[];
  private secrets: Map<string, string>;
  raceStats = { races: 0, wins: 0, failed: 0 };

  constructor(name: string, cfg: PoolConfig, secrets: Map<string, string>) {
    this.name = name;
    this.upstream = cfg.upstream.replace(/\/$/, "");
    this.healthMethod = cfg.health?.method ?? "GET";
    this.healthPath = cfg.health?.path ?? "/auth";
    this.healthOk = new Set(cfg.health?.ok ?? [200]);
    this.failStatus = new Set(cfg.fail_status ?? [401, 402, 429]);
    this.probeTimeoutMs = (cfg.probe_timeout ?? 2) * 1000;
    this.requestTimeoutMs = (cfg.request_timeout ?? 10) * 1000;
    this.cooldown = new Map(
      Object.entries(cfg.cooldown ?? { 401: 300, 402: 300, 429: 60 }).map(
        ([k, v]) => [Number(k), v],
      ),
    );
    this.protocol = cfg.protocol;
    this.interactionsPath = cfg.interactions_path ?? "/v1beta/interactions";
    this.cooldownDefault = cfg.cooldown_default ?? 120;
    this.secrets = secrets;
    this.keys = cfg.keys.map((k) => {
      const entry = typeof k === "string" ? { name: k } : k;
      const value = secrets.get(entry.name);
      if (!value) {
        throw new Error(
          `keypool '${name}': secret '${entry.name}' not found in secrets`,
        );
      }
      return {
        name: entry.name,
        fp: fingerprint(value),
        state: "unknown" as const,
        latencyMs: 0,
        downUntil: 0,
        lastProbeAt: 0,
        lastProbeOk: false,
        freeOnly: entry.free_only ?? false,
      };
    });
  }

  secretFor(name: string): string {
    const v = this.secrets.get(name);
    if (!v) throw new Error(`keypool '${this.name}': secret '${name}' missing`);
    return v;
  }

  async probe(ks: KeyState): Promise<boolean> {
    const url = this.upstream + this.healthPath;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.probeTimeoutMs);
    const t0 = Date.now();
    try {
      const secret = this.secretFor(ks.name);
      // Protocol-aware probe auth (parity with herd-keypool.py _probe):
      // Google AI endpoints take x-goog-api-key, OpenAI-compat takes Bearer.
      const headers: Record<string, string> = this.upstream.endsWith("/openai")
        ? { Authorization: `Bearer ${secret}` }
        : this.upstream.includes("generativelanguage.googleapis.com")
          ? { "x-goog-api-key": secret }
          : { Authorization: `Bearer ${secret}` };
      const resp = await fetch(url, {
        method: this.healthMethod,
        headers,
        signal: ctrl.signal,
      });
      const ms = Date.now() - t0;
      const ok = this.healthOk.has(resp.status);
      await resp.arrayBuffer().catch(() => {});
      ks.latencyMs = ms;
      ks.lastProbeOk = ok;
      ks.lastProbeAt = Date.now();
      ks.state = ok ? "healthy" : "down";
      if (!ok) ks.downUntil = Date.now() + this.cooldownDefault * 1000;
      return ok;
    } catch {
      ks.latencyMs = Date.now() - t0;
      ks.lastProbeOk = false;
      ks.lastProbeAt = Date.now();
      ks.state = "down";
      ks.downUntil = Date.now() + this.cooldownDefault * 1000;
      return false;
    } finally {
      clearTimeout(t);
    }
  }

  markDown(ks: KeyState, status: number): void {
    const secs = this.cooldown.get(status) ?? this.cooldownDefault;
    ks.state = "down";
    ks.downUntil = Date.now() + secs * 1000;
  }

  private eligible(model: string | null): KeyState[] {
    const now = Date.now();
    const free = isFreeModel(model);
    const out = this.keys.filter((ks) => {
      if (ks.freeOnly && !free) return false;
      if (ks.state === "down" && ks.downUntil > now) return false;
      return true;
    });
    out.sort((a, b) => {
      const rank = (s: string) => (s === "healthy" ? 0 : s === "unknown" ? 1 : 2);
      const r = rank(a.state) - rank(b.state);
      return r !== 0 ? r : a.latencyMs - b.latencyMs;
    });
    return out;
  }

  async pick(model: string | null): Promise<KeyState | null> {
    const now = Date.now();
    for (const ks of this.keys) {
      if (ks.state === "down" && ks.downUntil <= now) ks.state = "unknown";
    }
    for (const ks of this.eligible(model)) {
      if (ks.state === "unknown") {
        if (!(await this.probe(ks))) continue;
      }
      if (ks.state === "healthy") return ks;
    }
    return null;
  }

  raceCandidates(model: string | null, n: number): KeyState[] {
    return this.eligible(model).slice(0, n);
  }

  recordRace(won: boolean): void {
    this.raceStats.races++;
    if (won) this.raceStats.wins++;
    else this.raceStats.failed++;
  }
}

interface Settled {
  ks: KeyState;
  ok: boolean;
  resp?: Response;
  status?: number;
}

/**
 * Race first-valid-wins across candidates.
 * - winner: first 2xx response
 * - routing HTTP errors (fail_status): park that contestant, keep racing
 * - first non-routing HTTP error: returned immediately
 * - timeout/network: contestant loses silently
 * Loser responses are closed best-effort.
 */
export async function raceFirstValid(
  pool: Pool,
  forward: (ks: KeyState) => Promise<Response>,
  candidates: KeyState[],
): Promise<RaceResult> {
  const t0 = Date.now();

  const attempt = (ks: KeyState): Promise<Settled> =>
    forward(ks).then(
      (resp) => ({ ks, ok: true as const, resp }),
      (e: { status?: number }) => ({
        ks,
        ok: false as const,
        status: typeof e?.status === "number" ? e.status : 0,
      }),
    );

  const pending = new Map<KeyState, Promise<Settled>>();
  for (const ks of candidates) pending.set(ks, attempt(ks));

  const closeLosers = () => {
    for (const p of pending.values()) {
      p.then((s) => {
        if (s.ok && s.resp) s.resp.arrayBuffer().catch(() => {});
      }).catch(() => {});
    }
  };

  while (pending.size > 0) {
    const settled: Settled = await Promise.race([...pending.values()]);
    pending.delete(settled.ks);

    if (settled.ok && settled.resp) {
      closeLosers();
      return {
        kind: "winner",
        keyName: settled.ks.name,
        payload: settled.resp,
        ms: Date.now() - t0,
      };
    }

    const status = settled.status ?? 0;
    if (status !== 0 && !pool.failStatus.has(status)) {
      // Non-routing HTTP error: forward immediately
      closeLosers();
      return {
        kind: "error",
        keyName: settled.ks.name,
        payload: status,
        ms: Date.now() - t0,
      };
    }
    if (status !== 0) {
      // Routing error: park this contestant, keep racing
      pool.markDown(settled.ks, status);
    }
    // status 0 (timeout/network): contestant just loses
  }

  return { kind: "failed", keyName: null, payload: null, ms: Date.now() - t0 };
}
