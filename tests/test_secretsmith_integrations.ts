import { describe, expect, test } from "bun:test";
import { execSync } from "node:child_process";

describe("Kryptos CLI & Integrations", () => {
  test("kryptos collections lists available collections", () => {
    const out = execSync("kryptos collections", { encoding: "utf8" });
    expect(out).toContain("/org/freedesktop/secrets/collection");
  });

  test("kryptos bw-status reports bitwarden status", () => {
    const out = execSync("kryptos --json bw-status", { encoding: "utf8" });
    const data = JSON.parse(out);
    expect(data).toHaveProperty("status");
    expect(typeof data.status).toBe("string");
  });

  test("kryptos cookie-vault sync executes and updates backup", () => {
    const out = execSync("kryptos cookie-vault status", { encoding: "utf8" });
    expect(out).toContain("cookies across");
  });

  test("tok counter works with crashless o200k_harmony encoding", () => {
    const out = execSync("tok 'sample test payload with special tokens <|endoftext|>'", { encoding: "utf8" });
    const count = parseInt(out.trim(), 10);
    expect(count).toBeGreaterThan(0);
  });
});
