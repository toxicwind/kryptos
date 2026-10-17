// @estate/keypool — config: minimal YAML parser, secrets file.
// Port of herd-keypool.py's custom simple YAML parser (strict subset).

import type { PoolConfig } from "./types.js";
import { readFileSync, existsSync } from "node:fs";

function parseScalar(s: string): unknown {
  s = s.trim();
  if (s === "" || s === "~" || s === "null") return null;
  if (s === "true") return true;
  if (s === "false") return false;
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^-?\d*\.\d+$/.test(s)) return parseFloat(s);
  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    return s.slice(1, -1);
  }
  if (s.startsWith("[") && s.endsWith("]")) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(",").map((x) => parseScalar(x.trim()));
  }
  if (s.startsWith("{") && s.endsWith("}")) {
    const inner = s.slice(1, -1).trim();
    const obj: Record<string, unknown> = {};
    if (inner) {
      for (const part of splitTop(inner, ",")) {
        const ci = part.indexOf(":");
        if (ci > 0) obj[part.slice(0, ci).trim()] = parseScalar(part.slice(ci + 1));
      }
    }
    return obj;
  }
  return s;
}

/** Split on sep, ignoring sep inside {} or []. */
function splitTop(s: string, sep: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of s) {
    if (ch === "{" || ch === "[") depth++;
    else if (ch === "}" || ch === "]") depth--;
    if (ch === sep && depth === 0) {
      out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

interface Frame {
  indent: number;
  container: Record<string, unknown> | unknown[];
  /** key in parent that holds this container (for list conversion) */
  key?: string;
  parent?: Record<string, unknown> | unknown[];
}

/**
 * Parse the strict YAML subset used by keypools.yaml:
 * maps, nested maps, lists of scalars, lists of inline maps.
 */
export function parseSimpleYaml(text: string): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  const stack: Frame[] = [{ indent: -1, container: root }];

  const lines = text.split("\n");
  for (let li = 0; li < lines.length; li++) {
    const raw = lines[li];
    // strip comments (naive: # not inside quotes — good enough for our files)
    const hashIdx = raw.indexOf("#");
    const line = (hashIdx >= 0 ? raw.slice(0, hashIdx) : raw).replace(/\s+$/, "");
    if (!line.trim()) continue;

    const indent = line.length - line.trimStart().length;
    const content = line.trim();

    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) {
      stack.pop();
    }
    const frame = stack[stack.length - 1];
    let container = frame.container;

    // List item?
    if (content.startsWith("- ") || content === "-") {
      // Ensure container is an array (convert placeholder map if needed)
      if (!Array.isArray(container)) {
        if (
          frame.key !== undefined &&
          frame.parent &&
          !Array.isArray(frame.parent)
        ) {
          const arr: unknown[] = [];
          (frame.parent as Record<string, unknown>)[frame.key] = arr;
          frame.container = arr;
          container = arr;
        } else {
          throw new Error(`YAML: list item under non-list at line ${li + 1}: ${raw}`);
        }
      }
      const valStr = content.startsWith("- ") ? content.slice(2).trim() : "";
      if (!valStr) {
        const item: Record<string, unknown> = {};
        (container as unknown[]).push(item);
        stack.push({ indent, container: item });
      } else if (valStr.includes(":") && !valStr.startsWith("{")) {
        // "- key: value" map item
        const ci = valStr.indexOf(":");
        const k = valStr.slice(0, ci).trim();
        const v = valStr.slice(ci + 1).trim();
        const item: Record<string, unknown> = {};
        item[k] = v ? parseScalar(v) : {};
        (container as unknown[]).push(item);
        if (!v) stack.push({ indent, container: item });
      } else {
        (container as unknown[]).push(parseScalar(valStr));
      }
      continue;
    }

    // Map entry "key: value"
    const ci = content.indexOf(":");
    if (ci < 0) throw new Error(`YAML: no colon at line ${li + 1}: ${raw}`);
    const key = content.slice(0, ci).trim();
    const valStr = content.slice(ci + 1).trim();

    if (Array.isArray(container)) {
      throw new Error(`YAML: map key under list at line ${li + 1}: ${raw}`);
    }
    const map = container as Record<string, unknown>;
    if (!valStr) {
      // nested block — placeholder, may become list on "- " children
      const placeholder: Record<string, unknown> = {};
      map[key] = placeholder;
      stack.push({ indent, container: placeholder, key, parent: map });
    } else {
      map[key] = parseScalar(valStr);
    }
  }

  return root;
}

/** Load secrets from KEY=VALUE file. */
export function loadSecrets(path: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!existsSync(path)) {
    throw new Error(`keypool: secrets file not found: ${path}`);
  }
  for (const line of readFileSync(path, "utf8").split("\n")) {
    let t = line.trim();
    if (!t || t.startsWith("#")) continue;
    if (t.startsWith("export ")) t = t.slice(7).trim();
    const eq = t.indexOf("=");
    if (eq < 0) continue;
    out.set(t.slice(0, eq).trim(), t.slice(eq + 1).trim());
  }
  return out;
}

export interface KeypoolConfig {
  pools: Map<string, PoolConfig>;
  secrets: Map<string, string>;
}

export function loadKeypoolConfig(
  poolsPath: string,
  secretsPath: string,
): KeypoolConfig {
  const raw = parseSimpleYaml(readFileSync(poolsPath, "utf8"));
  const poolsRaw = raw["pools"] as Record<string, PoolConfig> | undefined;
  if (!poolsRaw || typeof poolsRaw !== "object" || Array.isArray(poolsRaw)) {
    throw new Error(`keypool: no 'pools' map in ${poolsPath}`);
  }
  const secrets = loadSecrets(secretsPath);
  const pools = new Map<string, PoolConfig>();
  for (const [name, cfg] of Object.entries(poolsRaw)) {
    if (!cfg || typeof cfg !== "object")
      throw new Error(`keypool '${name}': invalid config`);
    if (!cfg.upstream) throw new Error(`keypool '${name}': missing upstream`);
    if (!Array.isArray(cfg.keys) || cfg.keys.length === 0)
      throw new Error(`keypool '${name}': no keys configured`);
    // cooldown.default -> cooldown_default
    const cd = (cfg as unknown as Record<string, unknown>)["cooldown"] as
      | Record<string, number>
      | undefined;
    if (cd && typeof cd === "object" && "default" in cd) {
      cfg.cooldown_default = cd["default"];
      delete cd["default"];
    }
    pools.set(name, cfg);
  }
  return { pools, secrets };
}
