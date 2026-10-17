// @estate/keypool — event-driven health poller.
// Port of keypool/__main__.py _health_poller + wake_poller
// (commit ea5ee2bf35: TTL revalidation for healthy keys + event-driven poller).
//
// Behavioral parity contract:
// - probes unknown keys, down-but-unparked keys, and healthy keys whose
//   last probe is older than ttlMs (previously healthy keys were NEVER
//   revalidated, so a provider-side revocation left them green forever)
// - event-driven: sleeps until the next healthy-key TTL expiry or an
//   explicit wake() (e.g. after a config reload) — no fixed-interval timer
// - floor: never sleeps less than 1s; default 30s when no healthy keys exist

import { Pool } from "./pool.js";
import type { KeyState } from "./types.js";

/** True if this healthy key's last probe is older than ttlMs. */
export function needsRevalidation(ks: KeyState, ttlMs: number): boolean {
  return ks.state === "healthy" && ks.lastProbeAt > 0 && Date.now() - ks.lastProbeAt >= ttlMs;
}

export interface PollerOpts {
  /** healthy-key revalidation TTL, ms. Default 300_000 (KEYPOOL_HEALTHY_TTL=300s). */
  ttlMs?: number;
  log?: (msg: string) => void;
}

export class Poller {
  private readonly getPools: () => Map<string, Pool>;
  private readonly ttlMs: number;
  private readonly log: (msg: string) => void;
  private waker: (() => void) | null = null;
  private running = false;

  constructor(getPools: () => Map<string, Pool>, opts: PollerOpts = {}) {
    this.getPools = getPools;
    this.ttlMs = opts.ttlMs ?? 300_000;
    this.log = opts.log ?? ((m) => console.log(`[keypool] ${m}`));
  }

  /** Wake the poller immediately (e.g. after a config reload). */
  wake(): void {
    this.waker?.();
  }

  stop(): void {
    this.running = false;
    this.wake();
  }

  private sleepInterruptible(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const t = setTimeout(() => {
        this.waker = null;
        resolve();
      }, ms);
      this.waker = () => {
        clearTimeout(t);
        this.waker = null;
        resolve();
      };
    });
  }

  /** Run the poll loop until stop() is called. */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    await this.sleepInterruptible(1500); // let the server socket bind first
    while (this.running) {
      const now = Date.now();
      let nextWakeMs: number | null = null;
      try {
        for (const [poolName, pool] of this.getPools()) {
          for (const ks of pool.keys) {
            const needs =
              ks.state === "unknown" ||
              (ks.state === "down" && ks.downUntil <= now) ||
              needsRevalidation(ks, this.ttlMs);
            if (needs) {
              const ok = await pool.probe(ks);
              this.log(`poller: ${poolName}/${ks.name} -> ${ok ? "healthy" : "down"}`);
            }
          }
          for (const ks of pool.keys) {
            if (ks.state === "healthy" && ks.lastProbeAt > 0) {
              const expiry = ks.lastProbeAt + this.ttlMs - now;
              if (nextWakeMs === null || expiry < nextWakeMs) nextWakeMs = expiry;
            }
          }
        }
      } catch (e) {
        this.log(`poller error: ${e}`);
      }
      const waitMs =
        nextWakeMs !== null ? Math.max(1000, nextWakeMs) : 30_000;
      await this.sleepInterruptible(waitMs);
    }
  }
}
