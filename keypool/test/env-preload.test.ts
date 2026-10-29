/**
 * TDD contract for keypool/src/env-preload.ts — zero-transport kernel secrets
 * preload. Cache/mtime-oracle semantics proven in a sandbox dir; the D-Bus
 * dump lane is injected (proven separately against the live keyring).
 */
import { afterAll, describe, expect, it, mock } from "bun:test";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const tmp = mkdtempSync(join(tmpdir(), "kryptos-preload-test-"));
const keyring = join(tmp, "Default_Keyring.keyring");
const cache = join(tmp, "kryptos-env.json");
const stamp = join(tmp, "kryptos-env.stamp");

process.env.KRYPTO_KEYRING_FILE = keyring;
process.env.KRYPTO_CACHE_FILE = cache;
process.env.KRYPTO_STAMP_FILE = stamp;

const preload = await import("../src/env-preload.ts");
const fakeDump = mock(() => ({ ZZ_TEST_A: "a", ZZ_TEST_B: "b" }));

function writeKeyring(ms: number) {
  writeFileSync(keyring, "k", { flag: "w" });
  utimesSync(keyring, new Date(ms), new Date(ms));
}

describe("env-preload cache oracle", () => {
  afterAll(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("cacheIsFresh is false when no cache exists", () => {
    expect(preload.cacheIsFresh()).toBe(false);
  });

  it("readCache returns {} on missing/empty file", () => {
    expect(preload.readCache()).toEqual({});
  });

  it("triggers the dump lane when keyring is newer than stamp", () => {
    fakeDump.mockClear();
    const old = Date.now() - 60_000;
    writeFileSync(stamp, String(old), { flag: "w" });
    writeFileSync(cache, "{}", { flag: "w" });
    writeKeyring(old + 5_000); // keyring newest
    const res = preload.loadKryptosEnv(fakeDump);
    expect(fakeDump).toHaveBeenCalled();
    expect(res.via).toBe("dbus");
    expect(res.count).toBe(2);
    expect(process.env.ZZ_TEST_A).toBe("a");
  });

  it("second load hits the cache lane (stamp now >= keyring)", () => {
    fakeDump.mockClear();
    const ms = Date.now() - 1_000;
    writeFileSync(stamp, String(ms + 1_000), { flag: "w" });
    writeFileSync(cache, JSON.stringify({ ZZ_TEST_A: "a", ZZ_TEST_B: "b" }), { flag: "w" });
    writeKeyring(ms); // keyring behind stamp
    const res = preload.loadKryptosEnv(fakeDump);
    expect(fakeDump).not.toHaveBeenCalled();
    expect(res.via).toBe("cache");
    expect(res.count).toBe(2);
  });

  it("cache invalidates when keyring mtime moves forward", () => {
    fakeDump.mockClear();
    writeKeyring(Date.now() + 5_000);
    expect(preload.cacheIsFresh()).toBe(false);
    const res = preload.loadKryptosEnv(fakeDump);
    expect(fakeDump).toHaveBeenCalled();
    expect(res.via).toBe("dbus");
  });

  it("never overwrites existing env (env wins)", () => {
    process.env.ZZ_TEST_B = "existing";
    fakeDump.mockClear();
    const ms = Date.now() - 1_000;
    writeFileSync(stamp, String(ms + 1_000), { flag: "w" });
    writeKeyring(ms);
    preload.loadKryptosEnv(fakeDump);
    expect(process.env.ZZ_TEST_B).toBe("existing");
  });

  it("stale cache JSON does not crash readCache", () => {
    writeFileSync(cache, "{not json");
    expect(preload.readCache()).toEqual({});
  });

  it("dump lane is the real D-Bus reader (defined)", () => {
    expect(typeof preload.dumpViaDBus).toBe("function");
  });
});
