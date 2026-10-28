#!/usr/bin/env bun
/**
 * secretsmith — maximal freedesktop Secret Service CLI (Bun port).
 * Ported 1:1 from secretsmith.py; identical CLI contract so all tests hold.
 * Drop-in surfaces:
 *   eval "$(secretsmith env)"            # shell env loader
 *   secretsmith exec --env K=attr=v cmd  # secrets injected, never printed
 *   secretsmith get --label X --show     # fuzzy-label fallback built in
 */
import { spawnSync } from "node:child_process";
import { createDecipheriv } from "node:crypto";
import {
  existsSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import * as dbus from "dbus-next";

const BUS_NAME = "org.freedesktop.secrets";
const SERVICE_PATH = "/org/freedesktop/secrets";
const IFACE_SERVICE = "org.freedesktop.Secret.Service";
const IFACE_COLLECTION = "org.freedesktop.Secret.Collection";
const IFACE_ITEM = "org.freedesktop.Secret.Item";
const IFACE_PROPS = "org.freedesktop.DBus.Properties";

export class SecretsmithError extends Error {}

// ---------- registry ----------
interface SchemaEntry {
  description?: string;
  attributes?: Record<string, string>;
  protected?: boolean;
}
export function loadRegistry(): any {
  const p = join(import.meta.dir, "schemas.json");
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return {};
  }
}
export function resolveSchema(name: string, reg: any): [string, SchemaEntry] {
  const schemas: Record<string, any> = reg?.schemas ?? reg ?? {};
  let entry: any = schemas[name];
  if (entry && typeof entry === "object" && "alias_of" in entry)
    entry = schemas[entry.alias_of];
  if (entry?.["xdg:schema"]) return [entry["xdg:schema"], entry];
  return [name, { description: "unregistered raw schema" }];
}
function protectedSchemas(reg: Record<string, SchemaEntry>): Set<string> {
  return new Set(
    Object.entries(reg)
      .filter(([, v]) => v?.protected)
      .map(([k]) => k),
  );
}
function refuseProtected(it: any, reg: Record<string, SchemaEntry>): void {
  const schema = it.attributes["xdg:schema"];
  if (schema && protectedSchemas(reg).has(schema))
    throw new SecretsmithError(
      `item ${it.label} is protected by schema ${schema}; refusing`,
    );
}
export const redact = (n: number) => `<redacted ${n} bytes>`;
const isText = (b: Buffer) => !b.subarray(0, 512).includes(0);

// ---------- Secret Service (dbus-next) ----------
const unwrap = (v: any): any => {
  if (v instanceof dbus.Variant) return unwrap(v.value);
  if (
    v &&
    typeof v === "object" &&
    "type" in v &&
    "value" in v &&
    Object.getPrototypeOf(v) !== Object.prototype &&
    !(v instanceof Array)
  )
    return unwrap(v.value);
  return v;
};

export class SecretService {
  bus: dbus.MessageBus;
  svc: any;
  private sessionPath: string | null = null;

  constructor() {
    this.bus = dbus.sessionBus();
  }

  private service() {
    return this.iface(SERVICE_PATH, IFACE_SERVICE);
  }

  private obj(path: string) {
    if (typeof path !== "string")
      throw new SecretsmithError(
        `dbus object path must be a string, got ${typeof path}: ${String(path)}`,
      );
    return this.bus.getProxyObject(BUS_NAME, path);
  }
  private iface(path: string, name: string) {
    // synchronous-style lazy proxy: dbus-next is async; we memoize proxies
    const key = `${path}::${name}`;
    let p = (this as any)._proxies?.get(key);
    if (!p) {
      p = this.obj(path).then((o: any) => o.getInterface(name));
      (this as any)._proxies = (this as any)._proxies ?? new Map();
      (this as any)._proxies.set(key, p);
    }
    return p;
  }

  private async getProp(
    path: string,
    iface: string,
    prop: string,
  ): Promise<any> {
    const props = await this.iface(path, IFACE_PROPS);
    return unwrap(await props.Get(iface, prop));
  }

  async session(): Promise<string> {
    if (this.sessionPath) return this.sessionPath;
    const [, sess] = await (this.service() as any).then((s: any) =>
      s.OpenSession("plain", new dbus.Variant("s", "")),
    );
    this.sessionPath = String(sess);
    return this.sessionPath;
  }

  async collections(): Promise<
    Array<{ path: string; label: string; locked: boolean }>
  > {
    const paths: string[] = await this.getProp(
      SERVICE_PATH,
      IFACE_SERVICE,
      "Collections",
    );
    const out = [];
    for (const p of paths) {
      out.push({
        path: p,
        label: String(await this.getProp(p, IFACE_COLLECTION, "Label")),
        locked: Boolean(await this.getProp(p, IFACE_COLLECTION, "Locked")),
      });
    }
    return out;
  }

  async defaultCollection(): Promise<string | null> {
    // ReadAlias is an async dbus call: the result is a PROMISE, and
    // String(promise) is "[object Promise]" — which later blew up as
    // "Invalid object path: [object Promise]". Await it first.
    const raw = await (await this.service()).ReadAlias("default");
    const p = String(raw);
    return p === "/" ? null : p;
  }

  async resolveCollection(target: string): Promise<string> {
    if (target === "default") {
      const p = await this.defaultCollection();
      if (!p) throw new SecretsmithError("no default collection alias set");
      return p;
    }
    if (target.startsWith("/")) return target;
    for (const c of await this.collections())
      if (c.label === target) return c.path;
    throw new SecretsmithError(`no such collection: ${JSON.stringify(target)}`);
  }

  async createCollection(label: string, alias = ""): Promise<string> {
    const props = {
      [`${IFACE_COLLECTION}.Label`]: new dbus.Variant("s", label),
    };
    const [path, prompt] = (await this.service()).CreateCollection(
      props,
      alias ?? "",
    );
    if (String(prompt) !== "/") await this.awaitUnlock([String(path)]);
    return String(path);
  }

  async deleteCollection(target: string): Promise<string> {
    const path = await this.resolveCollection(target);
    await (await this.iface(path, IFACE_COLLECTION)).Delete();
    return path;
  }

  private async itemPaths(collectionPath: string): Promise<string[]> {
    return (await this.getProp(collectionPath, IFACE_COLLECTION, "Items")).map(
      String,
    );
  }

  async itemInfo(itemPath: string, collectionLabel: string) {
    const attrsRaw = await this.getProp(itemPath, IFACE_ITEM, "Attributes");
    const attributes: Record<string, string> = {};
    for (const [k, v] of Object.entries(attrsRaw ?? {}))
      attributes[k] = String(v);
    const [label, locked, created, modified] = await Promise.all([
      this.getProp(itemPath, IFACE_ITEM, "Label"),
      this.getProp(itemPath, IFACE_ITEM, "Locked"),
      this.getProp(itemPath, IFACE_ITEM, "Created"),
      this.getProp(itemPath, IFACE_ITEM, "Modified"),
    ]);
    return {
      path: itemPath,
      collection: collectionLabel,
      label: String(label),
      locked: Boolean(locked),
      attributes,
      created: Number(created),
      modified: Number(modified),
    };
  }

  async listItems(collection?: string) {
    const items = [];
    for (const c of await this.collections()) {
      if (collection && collection !== c.path && collection !== c.label)
        continue;
      for (const ip of await this.itemPaths(c.path))
        items.push(await this.itemInfo(ip, c.label));
    }
    return items;
  }

  async search(
    attrFilters: Record<string, string>,
    collection?: string,
    label?: string,
    query?: string,
  ) {
    const out = [];
    for (const it of await this.listItems(collection)) {
      if (label != null && it.label !== label) continue;
      if (
        !Object.entries(attrFilters).every(([k, v]) => it.attributes[k] === v)
      )
        continue;
      if (query != null) {
        const hay = [
          it.label,
          ...Object.entries(it.attributes).map(([k, v]) => `${k}=${v}`),
        ].join(" ");
        if (!hay.toLowerCase().includes(query.toLowerCase())) continue;
      }
      out.push(it);
    }
    return out;
  }

  private async isLocked(path: string, iface: string) {
    return Boolean(await this.getProp(path, iface, "Locked"));
  }

  private async awaitUnlock(paths: string[], timeout = 15) {
    const deadline = Date.now() + timeout * 1000;
    while (Date.now() < deadline) {
      const states = [];
      for (const p of paths) {
        const iface = p.includes("/collection/")
          ? IFACE_COLLECTION
          : IFACE_ITEM;
        try {
          states.push(await this.isLocked(p, iface));
        } catch {
          states.push(true);
        }
      }
      if (!states.some(Boolean)) return;
      await Bun.sleep(500);
    }
    throw new SecretsmithError(
      "unlock did not complete (keyring may need a GUI unlock)",
    );
  }

  async unlockPaths(paths: string[]) {
    if (!paths.length) return [];
    const [unlocked, prompt] = (await this.service()).Unlock(paths);
    if (String(prompt) !== "/") await this.awaitUnlock(paths.map(String));
    return unlocked.map(String);
  }

  async ensureUnlockedItems(items: any[]) {
    const locked = items.filter((it) => it.locked).map((it) => it.path);
    if (locked.length) {
      await this.unlockPaths(locked);
      for (const it of items) it.locked = false;
    }
  }

  async getSecret(itemPath: string): Promise<[Buffer, string]> {
    const item = await this.iface(itemPath, IFACE_ITEM);
    const [, , secret, contentType] = await item.GetSecret(
      await this.session(),
    );
    return [Buffer.from(secret), String(contentType)];
  }

  async setItem(
    collectionTarget: string,
    label: string,
    attributes: Record<string, string>,
    secretBytes: Buffer,
    contentType = "text/plain",
    replace = false,
  ) {
    const cpath = await this.resolveCollection(collectionTarget);
    if (await this.isLocked(cpath, IFACE_COLLECTION))
      await this.unlockPaths([cpath]);
    const coll = await this.iface(cpath, IFACE_COLLECTION);
    const props = {
      [`${IFACE_ITEM}.Label`]: new dbus.Variant("s", label),
      [`${IFACE_ITEM}.Attributes`]: new dbus.Variant("a{ss}", attributes),
    };
    const secret = [
      await this.session(),
      Buffer.alloc(0),
      secretBytes,
      contentType,
    ];
    const [itemPath, prompt] = await coll.CreateItem(props, secret, replace);
    if (String(prompt) !== "/") await this.awaitUnlock([String(itemPath)]);
    return String(itemPath);
  }

  async deleteItem(itemPath: string) {
    await (await this.iface(itemPath, IFACE_ITEM)).Delete();
  }

  async lock(paths: string[]) {
    const [locked] = (await this.service()).Lock(paths);
    return locked.map(String);
  }

  async unlock(paths: string[]) {
    return this.unlockPaths(paths);
  }
}

// ---------- helpers: attrs / aliases / fuzzy ----------
export function parseAttrs(pairs: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of pairs ?? []) {
    const i = pair.indexOf("=");
    if (i <= 0)
      throw new SecretsmithError(
        `attr must be k=v, got ${JSON.stringify(pair)}`,
      );
    out[pair.slice(0, i)] = pair.slice(i + 1);
  }
  return out;
}

function loadTomlFile(fpath: string): Record<string, any> {
  const raw = readFileSync(fpath, "utf8");
  const out: Record<string, any> = {};
  let section = "";
  for (let line of raw.split("\n")) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;
    const sec = line.match(/^\[([^\]]+)\]$/);
    if (sec) {
      section = sec[1];
      out[section] = out[section] ?? {};
      continue;
    }
    const kv = line.match(/^([A-Za-z0-9_.\-]+)\s*=\s*(.+)$/);
    if (kv) {
      let val: any = kv[2].trim().replace(/^"|"$/g, "");
      if (val === "true") val = true;
      else if (val === "false") val = false;
      if (section) out[section][kv[1]] = val;
      else out[kv[1]] = val;
    }
  }
  return out;
}

export function loadAliasMap(configDir?: string): Record<string, string> {
  const dir = configDir || join(homedir(), ".config", "secretsmith");
  for (const cand of [join(dir, "aliases.toml"), join(dir, "aliases.json")]) {
    if (existsSync(cand)) {
      try {
        const parsed = cand.endsWith(".json")
          ? JSON.parse(readFileSync(cand, "utf8"))
          : loadTomlFile(cand);
        return parsed.aliases ?? parsed;
      } catch {
        return {};
      }
    }
  }
  return {};
}

export function resolveAlias(
  aliases: Record<string, string>,
  envName: string,
): [string, boolean] {
  if (envName in aliases) return [aliases[envName], true];
  return [envName, false];
}

const BASE_RE = /[_\-]?\d+$/;
const normalizeLabel = (s: string | undefined) =>
  (s ?? "").replace(/[\s_\-.]+/g, "").toLowerCase();

export function fuzzyFind(
  svc: SecretService,
  label: string,
  collection?: string,
) {
  const target = normalizeLabel(label);
  if (!target) return [];
  return svc.search({}, collection).then((items) => {
    const exact: any[] = [],
      prefix: any[] = [],
      substring: any[] = [];
    for (const it of items) {
      const norm = normalizeLabel(it.label);
      if (!norm) continue;
      if (norm === target) exact.push(it);
      else if (norm.startsWith(target)) prefix.push(it);
      else if (norm.includes(target)) substring.push(it);
    }
    for (const bucket of [exact, prefix, substring])
      if (bucket.length)
        return bucket.sort(
          (a, b) =>
            a.label.length - b.label.length || (a.label < b.label ? -1 : 1),
        );
    return [];
  });
}

// ---------- commands ----------
async function cmdSearch(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const filters = parseAttrs(a.attr ?? []);
  let warned = false;
  if (a.schema) {
    const [schema, entry] = resolveSchema(a.schema, registry);
    if ((entry.description ?? "").startsWith("unregistered")) warned = true;
    filters["xdg:schema"] = schema;
  }
  const found: any[] = await svc.search(
    filters,
    a.collection,
    a.label,
    a.query ?? null,
  );
  if (a.show) {
    for (const it of found) refuseProtected(it, registry);
    await svc.ensureUnlockedItems(found);
    for (const it of found) {
      const [secret] = await svc.getSecret(it.path);
      it.secret_len = secret.length;
      it.secret_preview = isText(secret)
        ? secret.toString("utf8")
        : redact(secret.length);
    }
  } else {
    for (const it of found) it.secret_len = null;
  }
  if (asJson) {
    console.log(
      JSON.stringify(
        {
          count: found.length,
          items: found.map((it) => {
            const { secret_preview, ...rest } = it;
            return a.show ? it : rest;
          }),
        },
        null,
        2,
      ),
    );
  } else {
    if (warned)
      console.error(
        `warning: schema ${JSON.stringify(a.schema)} not in registry, used as raw xdg:schema`,
      );
    if (!found.length) console.log("(no items match)");
    for (const it of found) {
      console.log(
        `path: ${it.path}\ncollection: ${it.collection}\nlabel: ${it.label}\nlocked: ${it.locked}` +
          Object.entries(it.attributes)
            .map(([k, v]) => `\nattr ${k} = ${v}`)
            .join("") +
          (a.show ? `\nsecret: ${it.secret_preview}` : ""),
      );
      console.log();
    }
  }
  return 0;
}

async function cmdGet(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const filters = parseAttrs(a.attr ?? []);
  const label = a.label ?? null;
  let found = await svc.search(filters, a.collection, label);
  if (!found.length && label && !a.no_fuzzy && !Object.keys(filters).length) {
    found = await fuzzyFind(svc, label, a.collection);
    if (found.length > 1) {
      const norm = found
        .map((it) => [normalizeLabel(it.label), it] as const)
        .sort((x, y) => x[0].length - y[0].length);
      const base = norm[0][0];
      if (norm.slice(1).every(([n]) => n.startsWith(base)))
        found = [norm[0][1]];
    }
    if (found.length > 1)
      throw new SecretsmithError(
        `${found.length} fuzzy matches for ${JSON.stringify(label)}: ${found
          .map((f) => f.label)
          .sort()
          .join(", ")} — refine with --label or --no-fuzzy`,
      );
  }
  if (!found.length)
    throw new SecretsmithError(`no item matches ${JSON.stringify(filters)}`);
  const it = found[0];
  if (a.show) refuseProtected(it, registry);
  await svc.ensureUnlockedItems([it]);
  const [secret, contentType] = await svc.getSecret(it.path);
  if (asJson) {
    console.log(
      JSON.stringify(
        {
          label: it.label,
          path: it.path,
          attributes: it.attributes,
          content_type: contentType,
          secret:
            a.show && isText(secret)
              ? secret.toString("utf8")
              : a.show
                ? null
                : redact(secret.length),
          secret_base64:
            a.show && !isText(secret) ? secret.toString("base64") : null,
        },
        null,
        2,
      ),
    );
  } else {
    console.log(
      `label: ${it.label}\npath: ${it.path}\ncontent_type: ${contentType}`,
    );
    for (const k of Object.keys(it.attributes).sort())
      console.log(`attr ${k} = ${it.attributes[k]}`);
    console.log(
      a.show
        ? isText(secret)
          ? `secret: ${secret.toString("utf8")}`
          : `secret (base64): ${secret.toString("base64")}`
        : `secret: ${redact(secret.length)}  (use --show to print)`,
    );
  }
  return 0;
}

function readSecretInput(a: any): Buffer {
  if (a.secret_file) return readFileSync(a.secret_file);
  return Buffer.from(readFileSync(0));
}

async function cmdSet(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const secret = readSecretInput(a);
  const attrs = parseAttrs(a.attr ?? []);
  const path = await svc.setItem(
    a.collection ?? "default",
    a.label,
    attrs,
    secret,
    "text/plain",
    !!a.replace,
  );
  if (asJson)
    console.log(JSON.stringify({ stored: path, label: a.label }, null, 2));
  else console.log(`stored: ${path}`);
  return 0;
}

async function cmdDelete(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const filters = parseAttrs(a.attr ?? []);
  const found = await svc.search(filters, a.collection, a.label ?? null);
  if (!found.length)
    throw new SecretsmithError(`no item matches ${JSON.stringify(filters)}`);
  if (!a.yes) {
    console.log(`would delete ${found.length} item(s):`);
    for (const it of found) console.log(`  [${it.path}] ${it.label}`);
    console.log("re-run with --yes to delete");
    return 0;
  }
  for (const it of found) await svc.deleteItem(it.path);
  if (asJson)
    console.log(JSON.stringify({ deleted: found.map((f) => f.path) }, null, 2));
  else console.log(`deleted ${found.length} item(s)`);
  return 0;
}

async function cmdCollections(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const colls = await svc.collections();
  if (asJson)
    console.log(
      JSON.stringify({ count: colls.length, collections: colls }, null, 2),
    );
  else
    for (const c of colls)
      console.log(`${c.path}  label=${c.label}${c.locked ? "  LOCKED" : ""}`);
  return 0;
}

async function cmdCollectionCreate(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const path = await svc.createCollection(a.name, a.alias ?? "");
  if (asJson) console.log(JSON.stringify({ created: path }, null, 2));
  else console.log(`created: ${path}`);
  return 0;
}

async function cmdCollectionDelete(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  if (!a.yes) {
    console.log("re-run with --yes to delete");
    return 0;
  }
  const path = await svc.deleteCollection(a.name);
  console.log(`deleted: ${path}`);
  return 0;
}

async function resolveTargets(
  svc: SecretService,
  targets: string[],
  kind: "collection" | "any",
) {
  const paths: string[] = [];
  for (const t of targets) {
    if (t.startsWith("/")) paths.push(t);
    else if (
      kind === "any" &&
      (t.includes("/collection/") || t.includes("/item/"))
    )
      paths.push(t);
    else paths.push(await svc.resolveCollection(t));
  }
  return paths;
}

async function cmdLock(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const paths = await resolveTargets(svc, a.targets, "any");
  await svc.lock(paths);
  if (asJson) console.log(JSON.stringify({ locked: paths }, null, 2));
  else console.log(`locked ${paths.length} target(s)`);
  return 0;
}

async function cmdUnlock(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const paths = await resolveTargets(svc, a.targets, "any");
  await svc.unlock(paths);
  if (asJson) console.log(JSON.stringify({ unlocked: paths }, null, 2));
  else console.log(`unlocked ${paths.length} target(s)`);
  return 0;
}

async function cmdSchemas(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  if (asJson) console.log(JSON.stringify(registry, null, 2));
  else
    for (const [k, v] of Object.entries(registry))
      console.log(`${k}: ${v.description ?? ""}`);
  return 0;
}

async function cmdCheck(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const result: any = { service: BUS_NAME, ok: true, problems: [] };
  result.bus = process.env.DBUS_SESSION_BUS_ADDRESS ?? "(default)";
  const colls = await svc.collections();
  result.collections = colls.length;
  const def = await svc.defaultCollection();
  result.default_collection = def;
  if (def) {
    result.default_locked = await svc.isLocked(def, IFACE_COLLECTION);
    if (result.default_locked)
      result.problems.push("default collection is locked");
  } else result.problems.push("no default collection alias");
  const [schema] = resolveSchema("chromium", registry);
  const found = await svc.search({ "xdg:schema": schema });
  result.chromium_entry = found.length > 0;
  if (found.length) {
    try {
      await svc.ensureUnlockedItems(found);
      const [secret] = await svc.getSecret(found[0].path);
      result.chromium_secret_bytes = secret.length;
      result.chromium_key_candidates = keyCandidates(secret).length;
    } catch (e) {
      result.problems.push(
        `chromium secret unreadable: ${(e as Error).message}`,
      );
    }
  } else result.problems.push("no Chromium Safe Storage entry");
  result.ok = result.problems.length === 0;
  if (asJson) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(`service: ${result.service}  bus: ${result.bus}`);
    console.log(
      `collections: ${result.collections}  default: ${result.default_collection}${result.default_locked ? " (LOCKED)" : ""}`,
    );
    console.log(`chromium entry: ${result.chromium_entry ? "yes" : "NO"}`);
    if (result.problems.length) {
      console.log("PROBLEMS:");
      for (const p of result.problems) console.log(`  - ${p}`);
    } else console.log("OK — all checks passed");
  }
  return result.ok ? 0 : 1;
}

const shellIdent = /^[A-Za-z_][A-Za-z0-9_]*$/;
const shellQuote = (s: string) => "'" + s.replace(/'/g, "'\\''") + "'";

async function resolveEnvSpecs(
  svc: SecretService,
  a: any,
  registry: any,
): Promise<Record<string, string>> {
  const aliases = loadAliasMap(a.alias_map || undefined);
  const exports: Record<string, string> = {};
  for (const spec of a.env ?? []) {
    if (!spec.includes("="))
      throw new SecretsmithError(
        `env spec must be VAR=k=v[,k2=v2...], got ${JSON.stringify(spec)}`,
      );
    const eq = spec.indexOf("=");
    const varName = spec.slice(0, eq);
    const attrspec = spec.slice(eq + 1);
    if (!shellIdent.test(varName))
      throw new SecretsmithError(
        `env var name ${JSON.stringify(varName)} is not a valid identifier`,
      );
    const [canonical] = resolveAlias(aliases, varName);
    const filters = parseAttrs(attrspec.split(","));
    const found = await svc.search(filters, a.collection, canonical);
    if (!found.length)
      throw new SecretsmithError(`no item matches ${JSON.stringify(filters)}`);
    if (found.length > 1)
      throw new SecretsmithError(
        `${found.length} items match ${JSON.stringify(filters)} — refine attributes`,
      );
    const it = found[0];
    refuseProtected(it, registry);
    await svc.ensureUnlockedItems([it]);
    const [secret] = await svc.getSecret(it.path);
    const value = secret.toString("utf8");
    exports[varName] = value;
    if (canonical !== varName && !(canonical in exports))
      exports[canonical] = value;
    for (const [aliasName, aliasCanon] of Object.entries(aliases))
      if (
        aliasCanon === canonical &&
        aliasName !== varName &&
        !(aliasName in exports)
      )
        exports[aliasName] = value;
  }
  return exports;
}

async function cmdEnv(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const aliases = loadAliasMap(a.alias_map || undefined);
  const exports: Record<string, string> = {};
  if (a.env?.length) {
    Object.assign(exports, await resolveEnvSpecs(svc, a, registry));
  } else if (a.all) {
    let found = await svc.search({}, a.collection);
    found = found.filter((it) => shellIdent.test(it.label ?? ""));
    await svc.ensureUnlockedItems(found);
    for (const it of found) {
      if (it.label in aliases) continue;
      try {
        const [secret] = await svc.getSecret(it.path);
        exports[it.label] = secret.toString("utf8");
      } catch {
        continue;
      }
      for (const [aliasName, aliasCanon] of Object.entries(aliases))
        if (aliasCanon === it.label && !(aliasName in exports))
          exports[aliasName] = exports[it.label];
    }
  } else {
    let found = await svc.search(parseAttrs(a.attr ?? []), a.collection);
    if (a.app) {
      // 2026-10-27: exact `service === app` silently dropped
      // KAPPA_SERVER_PASSWORD (that item has NO `service` attribute), so
      // `secretsmith env --app kappa` emitted only HODOS_API_KEY and the
      // kappa server booted UNSECURED ("KAPPA_SERVER_PASSWORD is not set").
      // An app owns a secret when EITHER the service attribute names it OR
      // the label/key belongs to it (case-insensitive prefix match).
      const app = a.app;
      const appUpper = app.toUpperCase();
      const appLower = app.toLowerCase();
      found = found.filter((it) => {
        const svcAttr = (it.attributes.service ?? "").toLowerCase();
        if (svcAttr === appLower || svcAttr === appUpper) return true;
        const label = (it.label ?? "").toUpperCase();
        const key = (it.attributes.key ?? "").toUpperCase();
        for (const cand of [label, key])
          if (cand === appUpper || cand.startsWith(appUpper + "_")) return true;
        return false;
      });
    }
    found = found.filter((it) => shellIdent.test(it.label ?? ""));
    await svc.ensureUnlockedItems(found);
    for (const it of found) {
      try {
        const [secret] = await svc.getSecret(it.path);
        exports[it.label] = secret.toString("utf8");
      } catch {
        continue;
      }
      for (const [aliasName, aliasCanon] of Object.entries(aliases))
        if (aliasCanon === it.label && !(aliasName in exports))
          exports[aliasName] = exports[it.label];
    }
  }
  if (asJson)
    console.log(
      JSON.stringify({ count: Object.keys(exports).length, exports }, null, 2),
    );
  else
    for (const label of Object.keys(exports).sort())
      console.log(`${label}=${shellQuote(exports[label])}`);
  return Object.keys(exports).length ? 0 : 1;
}

async function cmdExec(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const aliases = loadAliasMap(a.alias_map || undefined);
  const env: Record<string, string> = { ...process.env };
  if (a.env?.length) {
    Object.assign(
      env,
      await resolveEnvSpecs(svc, { ...a, collection: a.collection }, registry),
    );
  } else if (a.only?.length) {
    for (const envName of a.only) {
      const [canonical] = resolveAlias(aliases, envName);
      const found = await svc.search({}, a.collection, canonical);
      if (!found.length) {
        console.error(
          `warning: no item for ${JSON.stringify(envName)} (label=${JSON.stringify(canonical)}), skipping`,
        );
        continue;
      }
      await svc.ensureUnlockedItems([found[0]]);
      const [secret] = await svc.getSecret(found[0].path);
      env[envName] = secret.toString("utf8");
    }
  } else if (a.all) {
    let found = await svc.search({}, a.collection);
    found = found.filter((it) => shellIdent.test(it.label ?? ""));
    await svc.ensureUnlockedItems(found);
    for (const it of found) {
      if (it.label in aliases) continue;
      try {
        const [secret] = await svc.getSecret(it.path);
        env[it.label] = secret.toString("utf8");
      } catch {
        continue;
      }
      for (const [aliasName, aliasCanon] of Object.entries(aliases))
        if (aliasCanon === it.label && !(aliasName in env))
          env[aliasName] = env[it.label];
    }
  } else {
    throw new SecretsmithError("specify --env VAR=k=v, --only NAME, or --all");
  }
  if (a.print_env_names) {
    for (const name of Object.keys(env).sort())
      if (!(name in process.env && env[name] === process.env[name]))
        console.log(name);
    return 0;
  }
  const proc = spawnSync(a.command[0], a.command.slice(1), {
    env,
    stdio: "inherit",
  });
  return proc.status ?? 1;
}

// ---------- Chromium os_crypt ----------
export function keyCandidates(raw: Buffer): Buffer[] {
  const cands: Buffer[] = [];
  const seen = new Set<string>();
  const trimmed = Buffer.from(raw.toString("latin1").trim());
  const push = (b: Buffer) => {
    const k = b.toString("base64");
    if (!seen.has(k)) {
      seen.add(k);
      cands.push(b);
    }
  };
  if (trimmed.length) push(trimmed);
  const b64 = /^[A-Za-z0-9+/=]+$/.test(trimmed.toString("latin1"));
  if (trimmed.length && trimmed.length % 4 === 0 && b64) {
    try {
      push(Buffer.from(trimmed.toString("latin1"), "base64"));
    } catch {}
  }
  return cands.filter((c) => [16, 24, 32].includes(c.length));
}

export function decryptChromiumBlob(
  blob: Buffer,
  candidates: Buffer[],
): Buffer {
  if (
    blob.subarray(0, 3).toString() !== "v10" &&
    blob.subarray(0, 3).toString() !== "v11"
  )
    throw new SecretsmithError(
      `unsupported blob prefix ${JSON.stringify(blob.subarray(0, 3).toString())} (expected v10/v11)`,
    );
  const ct = blob.subarray(3);
  for (const key of candidates) {
    try {
      const d = createDecipheriv("aes-128-cbc", key, Buffer.alloc(16, 0x20));
      const pt = Buffer.concat([d.update(ct), d.final()]);
      const pad = pt[pt.length - 1];
      if (
        pad >= 1 &&
        pad <= 16 &&
        pt.subarray(pt.length - pad).every((b) => b === pad)
      )
        return pt.subarray(0, pt.length - pad);
    } catch {
      continue;
    }
  }
  throw new SecretsmithError(
    `decryption failed with all ${candidates.length} key candidates`,
  );
}

async function chromiumKeyBytes(svc: SecretService, registry: any) {
  const [schema] = resolveSchema("chromium", registry);
  const found = await svc.search({ "xdg:schema": schema });
  if (!found.length)
    throw new SecretsmithError(
      `no Chromium Safe Storage entry (schema ${schema})`,
    );
  await svc.ensureUnlockedItems(found);
  const [secret] = await svc.getSecret(found[0].path);
  return [secret, found[0]] as const;
}

function copyProfileDb(profileDir: string, name: string): [string, string] {
  const src = join(profileDir, name);
  if (!existsSync(src))
    throw new SecretsmithError(`profile db not found: ${src}`);
  const tmp = mkdtempSync(join(tmpdir(), "secretsmith-"));
  const dst = join(tmp, name);
  copyFileSync(src, dst);
  for (const suffix of ["-wal", "-shm"])
    if (existsSync(src + suffix)) copyFileSync(src + suffix, dst + suffix);
  return [dst, tmp];
}

async function cmdChromiumKey(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const [secret, item] = await chromiumKeyBytes(svc, registry);
  const cands = keyCandidates(secret);
  if (asJson)
    console.log(
      JSON.stringify(
        {
          label: item.label,
          secret_len: secret.length,
          key_candidates: cands.length,
          keys_hex: cands.map((c) => c.toString("hex")),
        },
        null,
        2,
      ),
    );
  else {
    console.log(
      `label: ${item.label}\nsecret bytes: ${secret.length}\nkey candidates: ${cands.length}`,
    );
    for (const c of cands) console.log(`  ${c.toString("hex")}`);
  }
  return 0;
}

async function cmdChromiumLogins(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  return chromiumRowsCmd(svc, a, registry, asJson, "logins");
}

async function cmdChromiumCookies(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  return chromiumRowsCmd(svc, a, registry, asJson, "cookies");
}

async function chromiumRowsCmd(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
  kind: "logins" | "cookies",
) {
  const profile = a.profile_dir || defaultChromiumProfile();
  const [keySecret] = await chromiumKeyBytes(svc, registry);
  const cands = keyCandidates(keySecret);
  const { Database } = await import("bun:sqlite");
  const [dbFile, tmp] = copyProfileDb(
    profile,
    kind === "logins" ? "Login Data" : "Cookies",
  );
  const db = new Database(dbFile, { readonly: true });
  let rows: any[];
  let show: (r: any) => Record<string, unknown>;
  if (kind === "logins") {
    rows = db
      .prepare(
        "SELECT origin_url, username_value, password_value, date_created FROM logins ORDER BY origin_url",
      )
      .all();
    show = (r) => ({
      origin: String(r.origin_url ?? ""),
      username: String(r.username_value ?? ""),
      password: decryptOrNull(Buffer.from(r.password_value), cands),
    });
  } else {
    rows = db
      .prepare(
        "SELECT host_key, name, encrypted_value, expires_utc FROM cookies ORDER BY host_key",
      )
      .all();
    show = (r) => ({
      host: String(r.host_key ?? ""),
      name: String(r.name ?? ""),
      value: decryptOrNull(Buffer.from(r.encrypted_value), cands),
    });
  }
  db.close();
  const out = rows.map(show);
  if (asJson)
    console.log(JSON.stringify({ count: out.length, rows: out }, null, 2));
  else for (const r of out) console.log(JSON.stringify(r));
  return 0;
}

function decryptOrNull(blob: Buffer, cands: Buffer[]): string | null {
  if (!blob.length) return "";
  try {
    return decryptChromiumBlob(blob, cands).toString("utf8");
  } catch {
    return null;
  }
}

function defaultChromiumProfile(): string {
  for (const base of [
    join(homedir(), ".config", "chromium"),
    join(homedir(), ".config", "google-chrome"),
  ]) {
    const p = join(base, "Default");
    if (existsSync(p)) return p;
  }
  throw new SecretsmithError("no chromium profile found; pass --profile-dir");
}

// ---------- Bitwarden ----------
async function cmdBitwardenStatus(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  let data: any;
  try {
    const res = spawnSync("bw", ["status"], {
      encoding: "utf8",
      timeout: 5000,
    });
    data = res.stdout?.trim()
      ? JSON.parse(res.stdout)
      : { status: "unreachable" };
  } catch (e) {
    data = { status: "error", error: String(e) };
  }
  if (asJson) console.log(JSON.stringify(data, null, 2));
  else
    console.log(
      `Bitwarden status: ${data.status} (server: ${data.serverUrl ?? "default"})`,
    );
  return 0;
}

async function cmdBitwardenGet(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const session = process.env.BW_SESSION;
  const cmd = [
    "bw",
    "get",
    a.item_type,
    a.id_or_name,
    ...(session ? ["--session", session] : []),
  ];
  let err = "";
  try {
    const res = spawnSync(cmd[0], cmd.slice(1), {
      encoding: "utf8",
      timeout: 10000,
    });
    if (res.status === 0) {
      if (asJson) console.log(res.stdout);
      else {
        const out = res.stdout.trim();
        console.log(a.show ? out : redact(out.length));
      }
      return 0;
    }
    err = res.stderr?.trim() ?? "";
  } catch (e) {
    err = String(e);
  }
  const items = await svc.search({ name: a.id_or_name });
  if (!items.length) {
    console.error(`secretsmith: bitwarden/secrets error: ${err}`);
    return 1;
  }
  await svc.ensureUnlockedItems([items[0]]);
  const [sec] = await svc.getSecret(items[0].path);
  const val = sec.toString("utf8");
  if (asJson)
    console.log(
      JSON.stringify({
        source: "secretservice",
        item: a.id_or_name,
        value: a.show ? val : redact(val.length),
      }),
    );
  else console.log(a.show ? val : redact(val.length));
  return 0;
}

// ---------- cookie-vault ----------
async function cmdCookieVaultSync(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const subcmd = a.vault_action ?? "sync";
  const candidates = [
    "/home/toxic/pens/ranch/cookie-vault/bin/cookie-vault.js",
    "/home/toxic/pens/ranch/barn/browserless/bin/cookie-vault.ts",
  ];
  const bin = candidates.find((c) => existsSync(c)) ?? candidates[0];
  const runner = bin.endsWith(".js")
    ? ["node", bin, subcmd]
    : ["bun", bin, subcmd];
  try {
    const res = spawnSync(runner[0], runner.slice(1), {
      encoding: "utf8",
      timeout: 15000,
    });
    const out = (res.stdout ?? "").trim();
    if (a.json)
      console.log(
        JSON.stringify({ action: subcmd, exit: res.status, output: out }),
      );
    else console.log(out);
    return res.status ?? 1;
  } catch (e) {
    console.error(`secretsmith: cookie-vault error: ${e}`);
    return 1;
  }
}

// ---------- tau-auth-sync ----------
async function cmdTauAuthSync(
  svc: SecretService,
  a: any,
  registry: any,
  asJson: boolean,
) {
  const dbPath = a.db_path || join(homedir(), ".tau", "agent", "agent.db");
  if (!existsSync(dbPath))
    throw new SecretsmithError(`tau agent.db not found at ${dbPath}`);
  const { Database } = await import("bun:sqlite");
  const db = new Database(dbPath, { readonly: true });
  const rows = db
    .prepare(
      "SELECT id, provider, credential_type, data, identity_key FROM auth_credentials ORDER BY id",
    )
    .all();
  db.close();
  if (!rows.length) {
    console.log("secretsmith: no tau credentials to sync");
    return 0;
  }
  let collection: string;
  if (a.collection) collection = a.collection;
  else {
    const colls = await svc.collections();
    const unlocked = colls.filter((c) => !c.locked);
    if (!unlocked.length)
      throw new SecretsmithError(
        "no unlocked Secret Service collection available (Default Keyring locked and no session collection). Unlock the keyring or run with --collection <label>.",
      );
    const labeled = unlocked.find((c) => c.label);
    collection = labeled ? labeled.label : unlocked[0].path;
  }
  const stored: any[] = [];
  for (const row of rows) {
    if (!row.data) continue;
    const data =
      typeof row.data === "string"
        ? row.data
        : Buffer.from(row.data).toString("utf8");
    const label = `tau-auth:${row.provider ?? ""}`;
    const attrs = {
      tau_credential: "1",
      provider: String(row.provider ?? ""),
      cred_type: String(row.credential_type ?? ""),
      ...(row.identity_key ? { identity: String(row.identity_key) } : {}),
    };
    const path = await svc.setItem(
      collection,
      label,
      attrs,
      Buffer.from(data),
      a.content_type || "application/json",
      true,
    );
    stored.push({ label, path });
  }
  if (asJson)
    console.log(
      JSON.stringify({ synced: stored.length, items: stored }, null, 2),
    );
  else {
    console.log(`synced ${stored.length} credential(s) into ${collection}`);
    for (const s of stored) console.log(`  ${s.label} -> ${s.path}`);
  }
  return 0;
}

// ---------- CLI parser (hand-rolled, argparse-compatible flags) ----------
interface Args {
  [k: string]: any;
}

function parse(argv: string[]): Args {
  const a: Args = {
    cmd: null,
    attr: [],
    env: [],
    only: [],
    targets: [],
    command: [],
  };
  const rest = argv.slice();
  // global flags may appear BEFORE subcommand
  const globalFlags = (key: string) => {
    const i = rest.indexOf(key);
    if (i >= 0) {
      rest.splice(i, 1);
      return true;
    }
    return false;
  };
  let rootShow = globalFlags("--show");
  let rootJson = globalFlags("--json");
  let rootBus: string | undefined;
  const bi = rest.indexOf("--bus");
  if (
    bi >= 0 &&
    !rest[0].includes(" ") &&
    rest.slice(1).length >= 0 &&
    i0IsSub(rest[0]) === false
  ) {
    rootBus = rest[bi + 1];
    rest.splice(bi, 2);
  }
  const cmd = rest.shift();
  a.cmd = cmd;
  const flags = (key: string) => {
    const i = rest.indexOf(key);
    if (i >= 0) {
      rest.splice(i, 1);
      return true;
    }
    return false;
  };
  const flagVal = (key: string, dest: string) => {
    const i = rest.indexOf(key);
    if (i >= 0) {
      a[dest] = rest[i + 1];
      rest.splice(i, 2);
      return true;
    }
    return false;
  };
  const repeated = (key: string, dest: string) => {
    for (;;) {
      const i = rest.indexOf(key);
      if (i < 0) break;
      a[dest].push(rest[i + 1]);
      rest.splice(i, 2);
    }
  };
  a.show = flags("--show") || rootShow;
  a.json = flags("--json") || rootJson;
  a.bus = (() => {
    const i = rest.indexOf("--bus");
    if (i >= 0) {
      const v = rest[i + 1];
      rest.splice(i, 2);
      return v;
    }
    return rootBus;
  })();
  switch (cmd) {
    case "search":
      a.query =
        rest.length && !rest[0].startsWith("--") ? rest.shift() : undefined;
      flagVal("--schema", "schema");
      flagVal("--label", "label");
      repeated("--attr", "attr");
      flagVal("--collection", "collection");
      break;
    case "get":
      flagVal("--label", "label");
      a.no_fuzzy = flags("--no-fuzzy");
      repeated("--attr", "attr");
      flagVal("--collection", "collection");
      break;
    case "set":
      if (!flagVal("--label", "label"))
        throw new SecretsmithError("set requires --label");
      repeated("--attr", "attr");
      flagVal("--collection", "collection");
      flagVal("--secret-file", "secret_file");
      a.replace = flags("--replace");
      break;
    case "delete":
      flagVal("--label", "label");
      repeated("--attr", "attr");
      flagVal("--collection", "collection");
      a.yes = flags("--yes");
      break;
    case "collections":
      break;
    case "collection-create":
      a.name = rest.shift();
      flagVal("--alias", "alias");
      break;
    case "collection-delete":
      a.name = rest.shift();
      a.yes = flags("--yes");
      break;
    case "lock":
    case "unlock":
      a.targets = rest.splice(0);
      if (!a.targets.length)
        throw new SecretsmithError(`${cmd} requires targets`);
      break;
    case "schemas":
      break;
    case "env":
      repeated("--env", "env");
      flagVal("--app", "app");
      repeated("--attr", "attr");
      flagVal("--collection", "collection");
      a.all = flags("--all");
      flagVal("--alias-map", "alias_map");
      break;
    case "exec":
      repeated("--env", "env");
      repeated("--only", "only");
      a.all = flags("--all");
      flagVal("--collection", "collection");
      flagVal("--alias-map", "alias_map");
      a.print_env_names = flags("--print-env-names");
      a.command = rest.splice(0);
      if (!a.command.length)
        throw new SecretsmithError("exec requires a command");
      break;
    case "check":
    case "chromium-key":
      break;
    case "chromium-logins":
    case "chromium-cookies":
      flagVal("--profile-dir", "profile_dir");
      break;
    case "bw-status":
      break;
    case "bw-get":
      a.item_type = rest.shift();
      a.id_or_name = rest.shift();
      break;
    case "cookie-vault":
      a.vault_action =
        rest.length && !rest[0].startsWith("--") ? rest.shift() : "sync";
      break;
    case "tau-auth-sync":
      flagVal("--db-path", "db_path");
      flagVal("--collection", "collection");
      flagVal("--content-type", "content_type");
      break;
    default:
      throw new SecretsmithError(`unknown command: ${cmd}`);
  }
  return a;
}

function i0IsSub(tok?: string): boolean {
  return !!tok && !tok.startsWith("--");
}

function wantsHelp(argv: string[]): boolean {
  return argv.some((t) => t === "--help" || t === "-h");
}

const commands: Record<
  string,
  (
    svc: SecretService,
    a: Args,
    registry: any,
    asJson: boolean,
  ) => Promise<number>
> = {
  search: cmdSearch,
  get: cmdGet,
  set: cmdSet,
  delete: cmdDelete,
  collections: cmdCollections,
  "collection-create": cmdCollectionCreate,
  "collection-delete": cmdCollectionDelete,
  lock: cmdLock,
  unlock: cmdUnlock,
  schemas: cmdSchemas,
  env: cmdEnv,
  exec: cmdExec,
  check: cmdCheck,
  "chromium-key": cmdChromiumKey,
  "chromium-logins": cmdChromiumLogins,
  "chromium-cookies": cmdChromiumCookies,
  "bw-status": cmdBitwardenStatus,
  "bw-get": cmdBitwardenGet,
  "cookie-vault": cmdCookieVaultSync,
  "tau-auth-sync": cmdTauAuthSync,
};

async function main(): Promise<number> {
  if (wantsHelp(process.argv.slice(2))) {
    printUsage();
    return process.argv.length > 3 ? 0 : 2;
  }
  if (process.argv.length < 3) {
    printUsage();
    return 2;
  }
  let a: Args;
  try {
    a = parse(process.argv.slice(2));
  } catch (e) {
    console.error(
      `secretsmith: ${e instanceof SecretsmithError ? "error: " + e.message : e}`,
    );
    return 2;
  }
  if (a.bus) process.env.DBUS_SESSION_BUS_ADDRESS = a.bus;
  try {
    const registry = loadRegistry();
    const svc = new SecretService();
    const fn = commands[a.cmd];
    if (!fn) {
      printUsage();
      return 2;
    }
    const code = await fn(svc, a, registry, !!a.json);
    svc.bus.disconnect();
    return code;
  } catch (e) {
    if (e instanceof SecretsmithError) {
      console.error(`secretsmith: error: ${e.message}`);
      return 1;
    }
    if (e instanceof dbus.DBusError) {
      console.error(`secretsmith: D-Bus error: ${e.message}`);
      return 1;
    }
    throw e;
  }
}

function printUsage() {
  console.log(`usage: secretsmith [--json] [--show]
                   {search,get,set,delete,collections,collection-create,collection-delete,lock,unlock,schemas,env,exec,check,chromium-key,chromium-logins,chromium-cookies,bw-status,bw-get,cookie-vault,tau-auth-sync} ...`);
}

if (import.meta.main) {
  const code = await main();
  try {
    dbus.sessionBus().disconnect();
  } catch {}
  process.exit(code);
}
