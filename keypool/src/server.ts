// @estate/keypool — server: Bun.serve HTTP handler.
// Port of herd-keypool.py Handler. Routes /<pool>/... to upstream,
// strips caller auth, injects selected key, streams responses.

import { Pool, raceFirstValid, extractModel, upstreamAuthHeader } from "./pool.js";
import type { KeyState } from "./types.js";
import { Auditor } from "./audit.js";
import { openaiToInteractions, interactionsToOpenai } from "./translate.js";
import { QuotaTracker } from "./quota.js";
import { makePermitClient } from "./permit.js";
import { createHash } from "node:crypto";

const CACHE_MAX_ENTRIES = 1000;
const CACHE_TTL_MS = 5 * 60 * 1000;

// Freeinference concurrency-permit client (best-effort; see permit.ts).
const freeinferencePermit = makePermitClient("http://127.0.0.1:25250");

interface CacheEntry {
  body: Uint8Array;
  status: number;
  statusText: string;
  headers: Headers;
  timestamp: number;
  etag: string;
}

const freeinferenceCache = new Map<string, CacheEntry>();

function cacheKey(req: Request, body: Uint8Array): string {
  const hash = createHash("sha256");
  hash.update(req.method);
  hash.update(req.url);
  hash.update(body);
  return hash.digest("hex").slice(0, 32);
}

function getCached(key: string): Response | null {
  const entry = freeinferenceCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    freeinferenceCache.delete(key);
    return null;
  }
  return new Response(new Uint8Array(entry.body), {
    status: entry.status,
    statusText: entry.statusText,
    headers: entry.headers,
  });
}

async function setCache(key: string, response: Response): Promise<void> {
  if (freeinferenceCache.size >= CACHE_MAX_ENTRIES) {
    const firstKey = freeinferenceCache.keys().next().value;
    if (firstKey) freeinferenceCache.delete(firstKey);
  }
  const cloned = response.clone();
  const bodyArrayBuffer = await cloned.arrayBuffer();
  const body = new Uint8Array(bodyArrayBuffer);
  const etag = createHash("sha256").update(body).digest("hex").slice(0, 16);
  const headers = new Headers(response.headers);
  freeinferenceCache.set(key, {
    body,
    status: response.status,
    statusText: response.statusText,
    headers,
    timestamp: Date.now(),
    etag,
  });
}

// ---- Session/context isolation helpers ----

const SESSION_HEADER = "x-session-id";
const CHAT_ID_HEADER = "x-chat-id";

function getSessionId(req: Request): string | null {
  return req.headers.get(CHAT_ID_HEADER) || req.headers.get(SESSION_HEADER) || null;
}

function cacheKeyWithSession(req: Request, body: Uint8Array, sessionId: string | null): string {
  const hash = createHash("sha256");
  hash.update(req.method);
  hash.update(req.url);
  hash.update(body);
  if (sessionId) hash.update(sessionId);
  return hash.digest("hex").slice(0, 32);
}

const HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

const STRIP_AUTH = new Set(["authorization", "x-api-key", "api-key"]);

// reasoning-first model substrings -> token floor
const REASONING_MODELS = ["o1", "o3", "gpt-5", "deepseek-r", "qwq", "r1"];
const TOKEN_FLOOR = 512;

function adaptBody(poolName: string, model: string | null, raw: Uint8Array): Uint8Array {
  if (!raw.length || !model) return raw;
  try {
    const body = JSON.parse(Buffer.from(raw).toString("utf8"));
    const m = model.toLowerCase();
    if (REASONING_MODELS.some((s) => m.includes(s))) {
      if (typeof body.max_tokens === "number" && body.max_tokens < TOKEN_FLOOR) {
        body.max_tokens = TOKEN_FLOOR;
      }
    }
    if (m.includes("o1") || m.includes("o3") || m.includes("gpt-5")) {
      delete body.temperature;
      delete body.top_p;
      delete body.presence_penalty;
      delete body.frequency_penalty;
    }
    return Buffer.from(JSON.stringify(body));
  } catch {
    return raw;
  }
}

function decodeJson(raw: Uint8Array): unknown {
  if (!raw.length) return {};
  try {
    return JSON.parse(Buffer.from(raw).toString("utf8"));
  } catch {
    return {};
  }
}

const PREV_HEADER = "x-previous-interaction-id";
const ID_HEADER = "x-interaction-id";

interface Interaction {
  request: Record<string, unknown>;
  response: Record<string, unknown> | null;
}

const interactionStore = new Map<string, Interaction>();

function interactionsTurn(raw: Record<string, unknown>, prevId: string | null): { request: Record<string, unknown>; interactionId: string } {
  let interactionId = prevId;
  if (!interactionId) {
    interactionId = createHash("sha256").update(`${Date.now()}-${Math.random()}`).digest("hex").slice(0, 16);
    interactionStore.set(interactionId, { request: raw, response: null });
  } else {
    const existing = interactionStore.get(interactionId);
    if (existing) {
      existing.request = raw;
    }
  }
  return { request: raw, interactionId };
}

function decodeModel(raw: Uint8Array): string | null {
  if (!raw.length) return null;
  try {
    const body = JSON.parse(Buffer.from(raw).toString("utf8"));
    return typeof body.model === "string" ? body.model : null;
  } catch {
    return null;
  }
}

export interface ServerDeps {
  getPools: () => Map<string, Pool>;
  auditor: Auditor;
  raceKeys: number;
  quota: QuotaTracker;
}

export function createHandler(deps: ServerDeps) {
  const { getPools, auditor, raceKeys } = deps;

  return async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/health" && req.method === "GET") {
      return Response.json({ ok: true, service: "keypool" }, { headers: { "Access-Control-Allow-Origin": "*" } });
    }

    if (path === "/quota" && req.method === "GET") {
      return Response.json(deps.quota.snapshot(), { headers: { "Access-Control-Allow-Origin": "*" } });
    }

    if (path === "/status" && req.method === "GET") {
      const out: Record<string, unknown> = {};
      for (const [name, pool] of getPools()) {
        out[name] = {
          pool: name,
          upstream: pool.upstream,
          keys: pool.keys.map((k) => ({
            name: k.name,
            fp: k.fp,
            state: k.state,
            latency_ms: Math.round(k.latencyMs),
            down_until: k.downUntil > Date.now() ? new Date(k.downUntil).toISOString() : null,
            free_only: k.freeOnly,
          })),
          race_stats: pool.raceStats,
        };
      }
      return Response.json(out);
    }

    const m = path.match(/^\/([^/]+)(\/.*)?$/);
    if (!m) return Response.json({ error: "unknown keypool route" }, { status: 404 });
    const poolName = m[1];
    const rest = m[2] || "/";
    const pool = getPools().get(poolName);
    if (!pool) {
      return Response.json({ error: "unknown keypool route" }, { status: 404 });
    }

    if (
      pool.protocol === "gemini-interactions" &&
      req.method === "GET" &&
      (rest === "/models" || rest === "/v1/models")
    ) {
      return serveEapModels(pool);
    }

    const raw = new Uint8Array(await req.arrayBuffer());
    const model = extractModel(raw);
    const adapted = adaptBody(poolName, model, raw);

    const t0 = Date.now();
    let keyName = "none";
    let status = 502;

    try {
      if (raceKeys > 1) {
        const candidates = pool.raceCandidates(model, raceKeys);
        if (!candidates.length) {
          return Response.json(
            {
              error: `keypool '${poolName}': no healthy key`,
              tried: [],
              hint: "see /status for per-key states; keys revalidate on demand",
            },
            { status: 502 },
          );
        }
        const kind = await raceFirstValid(
          pool,
          (ks) => forward(pool, rest, url.search, req, adapted, ks),
          candidates,
        );
        pool.recordRace(kind.kind === "winner");
        if (kind.kind === "winner" && kind.payload instanceof Response) {
          keyName = kind.keyName ?? "unknown";
          status = kind.payload.status;
          auditor.log({
            ts: new Date().toISOString(),
            pool: poolName,
            key_fp: keyFp(pool, keyName),
            model,
            method: req.method,
            path: rest,
            status,
            ms: Date.now() - t0,
            race: true,
          });
          return kind.payload;
        }
        if (kind.kind === "error" && typeof kind.payload === "number") {
          return Response.json(
            { error: `keypool upstream: HTTP ${kind.payload}` },
            { status: kind.payload },
          );
        }
        return Response.json(
          {
            error: `keypool '${poolName}': no healthy key`,
            tried: candidates.map((c) => c.name),
            hint: "see /status for per-key states; keys revalidate on demand",
          },
          { status: 502 },
        );
      }

      const tried: string[] = [];
      for (;;) {
        const ks = await pool.pick(model);
        if (!ks) {
          return Response.json(
            {
              error: `keypool '${poolName}': no healthy key`,
              tried,
              hint: "see /status for per-key states; keys revalidate on demand",
            },
            { status: 502 },
          );
        }
        if (tried.includes(ks.name)) {
          return Response.json(
            { error: `keypool '${poolName}': keys exhausted`, tried },
            { status: 502 },
          );
        }
        tried.push(ks.name);
        keyName = ks.name;
        try {
          const resp = await forward(pool, rest, url.search, req, adapted, ks);
          status = resp.status;
          auditor.log({
            ts: new Date().toISOString(),
            pool: poolName,
            key_fp: ks.fp,
            model,
            method: req.method,
            path: rest,
            status,
            ms: Date.now() - t0,
            race: false,
          });
          return resp;
        } catch (e) {
          const st = (e as { status?: number }).status ?? 0;
          if (st !== 0 && pool.failStatus.has(st)) {
            pool.markDown(ks, st);
            continue;
          }
          if (st !== 0) {
            return Response.json(
              { error: `keypool upstream: HTTP ${st}` },
              { status: st },
            );
          }
          return Response.json(
            { error: `keypool upstream: ${e}` },
            { status: 502 },
          );
        }
      }
    } finally {

    }
  };
}

function serveEapModels(pool: Pool) {
  return Response.json({ object: "list", data: [] }, { headers: { "Access-Control-Allow-Origin": "*" } });
}

async function forward(
  pool: Pool,
  rest: string,
  search: string,
  req: Request,
  body: Uint8Array,
  ks: KeyState,
): Promise<Response> {
  const eap = pool.protocol === "gemini-interactions";
  const target = eap
    ? pool.upstream + pool.interactionsPath
    : pool.upstream + rest + search;
  const model = decodeModel(body);
  const outbound = eap
    ? JSON.stringify(
        interactionsTurn(
          decodeJson(body) as Record<string, unknown>,
          req.headers.get(PREV_HEADER),
        ).request,
      )
    : body;

  const headers = new Headers();
  for (const [k, v] of req.headers) {
    const lk = k.toLowerCase();
    if (HOP_HEADERS.has(lk) || STRIP_AUTH.has(lk) || lk === PREV_HEADER) continue;
    headers.set(k, v);
  }
  if (eap) headers.set("content-type", "application/json");

  const [authHeader, authValue] = upstreamAuthHeader(pool.upstream, pool.secretFor(ks.name));
  headers.set(authHeader, authValue);

  const isFreeinference = pool.upstream === "https://freeinference.org";
  let permitId: string | null = null;

  // Session/context isolation for multi-chat support
  const sessionId = isFreeinference ? getSessionId(req) : null;
  const cacheKeyStr = isFreeinference ? cacheKeyWithSession(req, body, sessionId) : "";
  const cached = isFreeinference ? getCached(cacheKeyStr) : null;
  if (cached) {
    const cachedHeaders = new Headers(cached.headers);
    cachedHeaders.set("x-cache", "HIT");
    return new Response(cached.body, {
      status: cached.status,
      statusText: cached.statusText,
      headers: cachedHeaders,
    });
  }

  if (isFreeinference) {
    // Coordinator is BEST-EFFORT (2026-11-08): a dead coordinator must not
    // 502 the lane — mimetite's pgate enforces freeinference concurrency
    // upstream of keypool. Connection failure degrades to null permit; a
    // coordinator that answers {ok:false} still sheds ({status:503}).
    permitId = await freeinferencePermit.acquire(model || "unknown", sessionId);
  }

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), pool.requestTimeoutMs);

  try {
    const resp = await fetch(target, {
      method: eap ? "POST" : req.method,
      headers,
      body: outbound.length > 0 ? outbound : undefined,
      signal: ctrl.signal,
    });

    if (resp.status >= 400) {
      await resp.arrayBuffer().catch(() => {});
      throw Object.assign(new Error(`HTTP ${resp.status}`), {
        status: resp.status,
      });
    }
    if (!eap) {
      if (isFreeinference) await setCache(cacheKeyStr, resp);
      return resp;
    }
    const upstream = (await resp.json()) as Record<string, unknown>;
    const response = Response.json(
      interactionsToOpenai(upstream, model ?? "gemini-flash-tool-retrieval"),
      { status: 200 },
    );
    const id = upstream["id"];
    if (typeof id === "string" && id.length > 0) response.headers.set(ID_HEADER, id);
    if (isFreeinference) await setCache(cacheKeyStr, response);
    return response;
  } catch (e) {
    const err = e as Error & { status?: number; retryAfter?: number };
    if (err.name === "AbortError") {
      throw Object.assign(new Error("upstream timeout"), { status: 0 });
    }
    if (err.status) {
      throw Object.assign(new Error(err.message), { status: err.status, retryAfter: err.retryAfter });
    }
    throw Object.assign(new Error(err.message), { status: 0 });
  } finally {
    clearTimeout(t);

    if (isFreeinference && permitId) {
      freeinferencePermit.release(permitId, model || "unknown");
    }
  }
}

function keyFp(pool: Pool, name: string): string {
  return pool.keys.find((k) => k.name === name)?.fp ?? "unknown";
}