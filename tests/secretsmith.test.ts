import { describe, expect, test } from "bun:test";
import { execSync } from "node:child_process";
import { createCipheriv } from "node:crypto";
import {
  decryptChromiumBlob,
  keyCandidates,
  loadRegistry,
  parseAttrs,
  redact,
  resolveSchema,
  SecretsmithError,
} from "../secretsmith.ts";

const pad16 = (pt: Buffer) =>
  Buffer.concat([
    pt,
    Buffer.alloc(16 - (pt.length % 16), 16 - (pt.length % 16)),
  ]);

function makeV10Blob(key: Buffer, plaintext: Buffer): Buffer {
  const iv = Buffer.alloc(16, 0x20);
  const c = createCipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([
    Buffer.from("v10"),
    c.update(pad16(plaintext)),
    c.final(),
  ]);
}

describe("Secretsmith CLI & Integrations", () => {
  test("secretsmith collections lists available collections", () => {
    const out = execSync("secretsmith collections", { encoding: "utf8" });
    expect(out).toContain("/org/freedesktop/secrets/collection");
  });

  test("secretsmith bw-status reports bitwarden status", () => {
    const out = execSync("secretsmith --json bw-status", { encoding: "utf8" });
    const data = JSON.parse(out);
    expect(data).toHaveProperty("status");
    expect(typeof data.status).toBe("string");
  });

  test("secretsmith cookie-vault sync executes and reports stored cookies", () => {
    const out = execSync("secretsmith cookie-vault status", {
      encoding: "utf8",
    });
    expect(out).toContain("cookies");
  });

  test("tau-auth-sync is wired into the CLI", () => {
    let exit = 0;
    let stderr = "";
    try {
      execSync("secretsmith tau-auth-sync --db-path /nonexistent/agent.db", {
        encoding: "utf8",
        stdio: ["ignore", "ignore", "pipe"],
      });
    } catch (e: any) {
      exit = e.status ?? -1;
      stderr = String(e.stderr ?? "");
    }
    expect(exit).toBe(1);
    expect(stderr).toContain("agent.db not found");
    expect(stderr).not.toContain("Traceback");
  });

  test("registry resolves chromium schema and chrome alias", () => {
    const reg = loadRegistry();
    expect("chromium" in reg.schemas).toBe(true);
    expect(resolveSchema("chromium", reg)[0]).toBe(
      "chrome_libsecret_os_crypt_password_v2",
    );
    expect(resolveSchema("chrome", reg)[0]).toBe(
      "chrome_libsecret_os_crypt_password_v2",
    );
    expect(resolveSchema("generic", reg)[0]).toBe(
      "org.freedesktop.Secret.Generic",
    );
    const [name, entry] = resolveSchema("com.example.Custom", reg);
    expect(name).toBe("com.example.Custom");
    expect(entry.description).toContain("unregistered");
  });

  test("chromium crypto round-trips raw and base64 keys", () => {
    const key = Buffer.from(crypto.getRandomValues(new Uint8Array(16)));
    const blob = makeV10Blob(key, Buffer.from("correct horse"));
    expect(decryptChromiumBlob(blob, [key]).toString()).toBe("correct horse");
    // base64-encoded key candidate path
    const b64Key = Buffer.from(key.toString("base64"));
    const cands = keyCandidates(b64Key);
    expect(cands.length).toBeGreaterThan(0);
    expect(decryptChromiumBlob(blob, cands).toString()).toBe("correct horse");
  });

  test("chromium crypto rejects wrong key and bad prefix", () => {
    const key = Buffer.from(crypto.getRandomValues(new Uint8Array(16)));
    const blob = makeV10Blob(key, Buffer.from("nope"));
    const wrongKey = Buffer.from(crypto.getRandomValues(new Uint8Array(16)));
    expect(() => decryptChromiumBlob(blob, [wrongKey])).toThrow(
      SecretsmithError,
    );
    expect(() =>
      decryptChromiumBlob(
        Buffer.concat([Buffer.from("v99"), Buffer.alloc(32)]),
        [wrongKey],
      ),
    ).toThrow(SecretsmithError);
  });

  test("safety helpers redact and parse attrs", () => {
    expect(redact(24)).toBe("<redacted 24 bytes>");
    expect(parseAttrs(["a=1", "b=x=y"])).toEqual({ a: "1", b: "x=y" });
    expect(() => parseAttrs(["bare"])).toThrow(SecretsmithError);
  });
});

describe("Secretsmith live keyring (SSM_TEST_KEYRING=1)", () => {
  test("fuzzy get resolves canonical labels", () => {
    if (process.env.SSM_TEST_KEYRING !== "1") {
      console.log("skip: set SSM_TEST_KEYRING=1 to run live keyring tests");
      return;
    }
    const out = execSync("secretsmith get --label openrouter --show --json", {
      encoding: "utf8",
    });
    const data = JSON.parse(out);
    expect(data.label.startsWith("OPENROUTER")).toBe(true);
    expect(data.secret.length).toBeGreaterThan(0);
  });
});
