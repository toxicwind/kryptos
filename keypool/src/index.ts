// @estate/keypool — main entrypoint.
// Port of herd-keypool.py main(). Bun.serve replaces ThreadingHTTPServer.

import { Pool } from "./pool.js";
import { loadKeypoolConfig } from "./config.js";
import { Auditor } from "./audit.js";
import { createHandler } from "./server.js";
import { Poller } from "./poller.js";

const SERVICE = "keypool";
const PORT_ENV = "KEYPOOL_PORT";
const DEFAULT_PORT = 25109;

function requiredPort(): number {
  const raw = process.env[PORT_ENV];
  if (!raw) return DEFAULT_PORT;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error(`FATAL ${SERVICE}: ${PORT_ENV}=${raw} is not a valid port`);
    process.exit(1);
  }
  return port;
}

const POOLS_PATH =
  process.env["KEYPOOL_CONFIG"] ?? "/home/toxic/estate/config/keypools.yaml";
const SECRETS_PATH =
  process.env["KEYPOOL_SECRETS"] ?? "/home/toxic/.secrets";
const AUDIT_PATH =
  process.env["KEYPOOL_AUDIT"] ??
  "/home/toxic/estate/data/keypool-audit.jsonl";
const AUDIT_MAX = Number(process.env["KEYPOOL_AUDIT_MAX_BYTES"] ?? 50 * 1024 * 1024);
const RACE_KEYS = Number(process.env["KEYPOOL_RACE_KEYS"] ?? 1);
const HEALTHY_TTL_MS = Number(process.env["KEYPOOL_HEALTHY_TTL"] ?? 300) * 1000;

let pools = new Map<string, Pool>();
const auditor = new Auditor(AUDIT_PATH, AUDIT_MAX);

function loadPools(): void {
  const cfg = loadKeypoolConfig(POOLS_PATH, SECRETS_PATH);
  const next = new Map<string, Pool>();
  for (const [name, poolCfg] of cfg.pools) {
    next.set(name, new Pool(name, poolCfg, cfg.secrets));
  }
  pools = next;
  console.log(
    `[${SERVICE}] loaded ${pools.size} pools: ${[...pools.keys()].join(", ")}`,
  );
}
const poller = new Poller(() => pools, { ttlMs: HEALTHY_TTL_MS });

// SIGHUP reload (parity with herd-keypool.py)
process.on("SIGHUP", () => {
  console.log(`[${SERVICE}] SIGHUP: reloading pools config`);
  try {
    loadPools();
    poller.wake();
  } catch (e) {
    console.error(`[${SERVICE}] reload failed: ${e}`);
  }
});

loadPools();
poller.start().catch((e) => {
  console.error(`[${SERVICE}] poller crashed: ${e}`);
  process.exit(1);
});

const port = requiredPort();
const server = Bun.serve({
  port,
  hostname: "127.0.0.1",
  fetch: createHandler({ getPools: () => pools, auditor, raceKeys: RACE_KEYS }),
});

console.log(
  `[${SERVICE}] listening on 127.0.0.1:${port} (pools: ${[...pools.keys()].join(", ") || "none"})`,
);

// Graceful shutdown
for (const sig of ["SIGTERM", "SIGINT"] as const) {
  process.on(sig, () => {
    console.log(`[${SERVICE}] ${sig}: shutting down`);
    poller.stop();
    server.stop();
    process.exit(0);
  });
}
