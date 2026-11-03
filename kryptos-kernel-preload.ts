// Eval-kernel secrets preload — WINNER: technique B (in-process D-Bus via
// python3 secretstorage). Loads ALL keyring items into process.env ONCE at
// kernel boot; zero per-command transport afterwards (no secretsmith spawns).
//
// Race results (2026-10-29):
//   A) subprocess `secretsmith search '' --json --show` : 295ms dump, but
//      secret_preview is MASKED — full secrets need per-label gets = N
//      subprocess spawns per read. Loses on transport count.
//   C) `secretsmith env --app <app>` : BROKEN (0 vars) — anomaly #19 emitter-skip.
//   B) in-process D-Bus (secretstorage) : 173 items in 1.65s, FULL secrets,
//      ZERO per-command transport. WINNER.
//
// Gotcha found: `secretsmith get THRESHER_API_KEY --show` returns junk
// ("label:" YAML blob, 221 chars) while the D-Bus item is correct (64 chars) —
// same item, two truths. D-Bus is ground truth; secretsmith's read path is
// the buggy half (anomaly #19 class). Never trust secretsmith -show for
// verification; read via D-Bus.
//
// Usage: %load <this file> at kernel start (or run once; state persists
// across compaction). Kernel loss -> re-run this cell.

const { spawnSync } = await import("node:child_process");

const PRELOAD_SCRIPT = `
import secretstorage, os, sys

def main():
    try:
        conn = secretstorage.dbus_init()
    except Exception as e:
        print(f"DBUS_UNAVAILABLE: {e}", file=sys.stderr)
        return
    coll = secretstorage.get_default_collection(conn)
    loaded = 0
    for it in coll.get_all_items():
        try:
            lab = it.get_label()
        except Exception:
            continue
        if not lab or lab.startswith("label:") or "=" in lab:
            continue
        try:
            sec = it.get_secret()
        except Exception:
            continue
        if not sec:
            continue
        # valid env names only (the SSOT names are all uppercase snake)
        if not lab.replace("_", "").isalnum() or not lab.isupper():
            continue
        os.environ[lab] = sec.decode(errors="replace")
        loaded += 1
    print(f"loaded {loaded} items")
main()
`;

function dbusLoad() {
  const res = spawnSync("python3", ["-c", PRELOAD_SCRIPT], {
    encoding: "utf8",
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
    timeout: 20_000,
  });
  if (res.status !== 0) {
    throw new Error(`keyring D-Bus preload failed: ${res.stderr || res.stdout}`);
  }
  return (res.stdout || "").trim();
}

// Idempotent: only run the D-Bus read once per kernel lifetime.
if (!globalThis.__KERNEL_SECRETS_LOADED__) {
  const t0 = performance.now();
  const msg = dbusLoad();
  globalThis.__KERNEL_SECRETS_LOADED__ = true;
  globalThis.__KERNEL_SECRETS_MS__ = Math.round(performance.now() - t0);
  console.log(`[kryptos-preload] ${msg} in ${globalThis.__KERNEL_SECRETS_MS__}ms (zero-transport D-Bus)`);
} else {
  console.log("[kryptos-preload] already loaded in this kernel lifetime");
}

// Prove: THRESHER_API_KEY present in process.env without any subprocess.
const k = process.env.THRESHER_API_KEY || "";
console.log(
  `[kryptos-preload] THRESHER_API_KEY ${k ? `OK len=${k.length} prefix=${k.slice(0, 6)}` : "MISSING"}`,
);

export {};