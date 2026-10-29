/**
 * env-preload.ts — zero-transport kernel secrets preload (cache-first).
 *
 * Race winner (2026-10-29): a full D-Bus keyring read via python
 * secretstorage costs ~1.1-1.5s (172 items). The keyring blob's mtime is a
 * cheap freshness oracle: any secret write touches
 * ~/.local/share/keyrings/Default_Keyring.keyring, so a stamped JSON cache
 * is valid until that mtime moves. Cache hit = ~0ms; only a real keyring
 * change triggers the expensive dump.
 *
 * Inject-once semantics: never overwrites an already-set env value (the
 * estate merge order is env → file → keyring-gapfill; the kernel env wins).
 */
import { existsSync, statSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const BASE = process.env.KRYPTO_PRELOAD_DIR ?? homedir();
export const KEYRING_FILE = process.env.KRYPTO_KEYRING_FILE
  ?? join(BASE, ".local/share/keyrings/Default_Keyring.keyring");
export const CACHE_FILE = process.env.KRYPTO_CACHE_FILE
  ?? join(BASE, ".cache/kryptos-env.json");
export const STAMP_FILE = process.env.KRYPTO_STAMP_FILE
  ?? join(BASE, ".cache/kryptos-env.stamp");

/** Inject only when the keyring on disk is newer than our stamp. */
export function cacheIsFresh(): boolean {
  try {
    if (!existsSync(CACHE_FILE) || !existsSync(STAMP_FILE) || !existsSync(KEYRING_FILE)) {
      return false;
    }
    const stamped = Number(readFileSync(STAMP_FILE, "utf8"));
    return Number.isFinite(stamped) && stamped >= statSync(KEYRING_FILE).mtimeMs;
  } catch {
    return false;
  }
}

export function readCache(): Record<string, string> {
  try {
    return JSON.parse(readFileSync(CACHE_FILE, "utf8")) as Record<string, string>;
  } catch {
    return {};
  }
}

/** Full D-Bus dump (python secretstorage — proven lane, 172 items). */
export function dumpViaDBus(): Record<string, string> {
  const py = `python3 - << 'PYEOF'
import secretstorage, json, sys
conn = secretstorage.dbus_init()
coll = secretstorage.get_default_collection(conn)
out = {}
for item in coll.get_all_items():
    try:
        out[item.get_label()] = item.get_secret().decode("utf-8", "replace")
    except Exception:
        pass
print(json.dumps(out))
PYEOF`;
  try {
    const res = Bun.spawnSync(["bash", "-c", py]);
    const obj = JSON.parse(res.stdout.toString()) as Record<string, string>;
    writeFileSync(CACHE_FILE, JSON.stringify(obj));
    writeFileSync(STAMP_FILE, String(statSync(KEYRING_FILE).mtimeMs));
    return obj;
  } catch {
    return {};
  }
}

export type LoadResult = {
  count: number;
  ms: number;
  via: "cache" | "dbus";
};

/** Load all keyring secrets into process.env (never overwrites existing). */
export function loadKryptosEnv(dump: () => Record<string, string> = dumpViaDBus): LoadResult {
  const t0 = performance.now();
  const fresh = cacheIsFresh();
  const env = fresh ? readCache() : dump();
  for (const [k, v] of Object.entries(env)) {
    if (v && (process.env[k] === undefined || process.env[k] === "")) {
      process.env[k] = v;
    }
  }
  return { count: Object.keys(env).length, ms: Math.round(performance.now() - t0), via: fresh ? "cache" : "dbus" };
}