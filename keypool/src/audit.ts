// @estate/keypool — audit: JSONL with recursive secret fingerprinting.
// Port of herd-keypool.py audit(). Raw keys never touch the log.

import type { AuditEvent } from "./types.js";
import { appendFileSync, existsSync, statSync, renameSync } from "node:fs";
import { fingerprint } from "./pool.js";

const CRED_KEYS = [
  "authorization",
  "api_key",
  "apikey",
  "key",
  "token",
  "secret",
  "password",
  "bearer",
];

function looksCredential(key: string, value: unknown): boolean {
  if (typeof value !== "string" || value.length < 8) return false;
  const k = key.toLowerCase();
  return CRED_KEYS.some((c) => k.includes(c));
}

/** Recursively replace credential-shaped strings with fingerprints. */
export function scrub(value: unknown): unknown {
  if (typeof value === "string") {
    // bare credential-shaped string: long, high-entropy
    if (value.length >= 20 && /[A-Za-z0-9_\-]{20,}/.test(value)) {
      return `fp:${fingerprint(value)}`;
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(scrub);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = looksCredential(k, v) ? `fp:${fingerprint(String(v))}` : scrub(v);
    }
    return out;
  }
  return value;
}

export class Auditor {
  private path: string;
  private maxBytes: number;

  constructor(path: string, maxBytes: number) {
    this.path = path;
    this.maxBytes = maxBytes;
  }

  log(event: AuditEvent): void {
    try {
      // Rotate if over max bytes
      if (existsSync(this.path) && statSync(this.path).size >= this.maxBytes) {
        renameSync(this.path, this.path + ".1");
      }
      const scrubbed = scrub(event) as AuditEvent;
      appendFileSync(this.path, JSON.stringify(scrubbed) + "\n");
    } catch {
      // audit must never break the request path
    }
  }
}
