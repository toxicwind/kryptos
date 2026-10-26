import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadSecrets } from "../src/config.js";

function withFile(content: string): () => string {
  const dir = mkdtempSync(join(tmpdir(), "kp-test-"));
  const p = join(dir, "secrets");
  writeFileSync(p, content);
  return () => p;
}

describe("loadSecrets secretsmith env contract", () => {
  test("strips single-quoted export values from `secretsmith env` output", () => {
    const f = withFile(
      `export OPENROUTER_API_KEY='sk-or-clean-key'\nexport NIM_API_KEY_1='nvapi-clean'\n`,
    );
    // secretsmith env emits shell exports: KEY='value' — the stored secret
    // must NOT carry the literal quotes, else Bearer headers become
    // `sk-...'` and every upstream 401s (the 2026-10-26 mass-down).
    const m = loadSecrets(f());
    expect(m.get("OPENROUTER_API_KEY")).toBe("sk-or-clean-key");
    expect(m.get("NIM_API_KEY_1")).toBe("nvapi-clean");
  });

  test("strips double quotes too", () => {
    const f = withFile(`GEMINI_EAP_KEY_1="dq-value"\nPLAIN=no-quotes\n`);
    const m = loadSecrets(f());
    expect(m.get("GEMINI_EAP_KEY_1")).toBe("dq-value");
    expect(m.get("PLAIN")).toBe("no-quotes");
  });

  test("leaves a quote inside the value alone (only matching pairs strip)", () => {
    const f = withFile(`A='has "inside"'\nB="it's fine"\n`);
    const m = loadSecrets(f());
    expect(m.get("A")).toBe('has "inside"');
    expect(m.get("B")).toBe("it's fine");
  });
});
