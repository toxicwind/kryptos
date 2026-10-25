// @estate/keypool — EAP Interactions translate tests (TDD).
// Covers openaiToInteractions / interactionsToOpenai against the verified
// Gemini Tool Retrieval (EAP) wire contract. theta (pens/olympus/products/theta)
// is the nominal owner of this translation; this test is its behavior contract.

import { describe, test, expect } from "bun:test";
import {
  openaiToInteractions,
  interactionsToOpenai,
  resolveGeminiModel,
} from "../src/translate.js";

describe("resolveGeminiModel", () => {
  test("maps roost aliases to interactions model ids", () => {
    expect(resolveGeminiModel("gemini-eap")).toBe(
      "models/gemini-flash-tool-retrieval",
    );
    expect(resolveGeminiModel("gemini-3.6-flash")).toBe(
      "models/gemini-3.6-flash",
    );
    expect(resolveGeminiModel("gemini-3.1-pro")).toBe(
      "models/gemini-3.1-pro-preview",
    );
    expect(resolveGeminiModel("gemini-2.5-flash")).toBe(
      "models/gemini-2.5-flash",
    );
  });

  test("passes native models/... ids through untouched", () => {
    expect(resolveGeminiModel("models/gemini-2.5-flash")).toBe(
      "models/gemini-2.5-flash",
    );
    expect(resolveGeminiModel("gemini-flash-tool-retrieval")).toBe(
      "gemini-flash-tool-retrieval",
    );
  });

  test("passes non-strings through untouched", () => {
    expect(resolveGeminiModel(null)).toBeNull();
    expect(resolveGeminiModel(undefined)).toBeUndefined();
  });
});

describe("openaiToInteractions", () => {
  test("already-interactions body passes through untouched", () => {
    const native = { model: "models/gemini-flash-tool-retrieval", input: "hi" };
    expect(openaiToInteractions(native)).toBe(native);
  });

  test("resolves model alias and flattens conversation to role-prefixed input", () => {
    const out = openaiToInteractions({
      model: "gemini-eap",
      messages: [
        { role: "user", content: "hello" },
        { role: "assistant", content: "hi there" },
      ],
    }) as Record<string, unknown>;
    expect(out["model"]).toBe("models/gemini-flash-tool-retrieval");
    expect(out["input"]).toBe("user: hello\nassistant: hi there");
    expect(out["tools"]).toBeUndefined();
  });

  test("seeds tool_search and defers every function declaration", () => {
    const out = openaiToInteractions({
      model: "gemini-eap",
      messages: [{ role: "user", content: "convert" }],
      tools: [
        {
          type: "function",
          function: {
            name: "convert_currency",
            description: "x",
            parameters: { type: "object" },
          },
        },
      ],
    }) as { tools?: unknown[] };
    expect(out["tools"]?.[0]).toEqual({ type: "tool_search" });
    expect(out["tools"]?.[1]).toMatchObject({
      type: "function",
      name: "convert_currency",
      defer_loading: true,
    });
  });

  test("no tools -> no tools key emitted", () => {
    const out = openaiToInteractions({
      model: "gemini-eap",
      messages: [{ role: "user", content: "hi" }],
    }) as Record<string, unknown>;
    expect(out["tools"]).toBeUndefined();
  });

  test("tool role messages become function_result inputs", () => {
    const out = openaiToInteractions({
      model: "gemini-eap",
      messages: [
        {
          role: "tool",
          content: '{"ok":true}',
          name: "f",
          tool_call_id: "call_1",
        },
      ],
    }) as { input?: unknown[] };
    expect(out["input"]?.[0]).toEqual({
      type: "function_result",
      name: "f",
      call_id: "call_1",
      result: { ok: true },
    });
  });

  test("non-JSON tool content is wrapped as {content: ...}", () => {
    const out = openaiToInteractions({
      model: "gemini-eap",
      messages: [{ role: "tool", content: "plain text", name: "g" }],
    }) as { input?: unknown[] };
    expect((out["input"]?.[0] as Record<string, unknown>)["result"]).toEqual({
      content: "plain text",
    });
  });

  test("object tool content passes through as-is", () => {
    const out = openaiToInteractions({
      model: "gemini-eap",
      messages: [{ role: "tool", content: { k: 1 }, name: "h", id: "cid" }],
    }) as { input?: unknown[] };
    expect((out["input"]?.[0] as Record<string, unknown>)["result"]).toEqual({
      k: 1,
    });
  });

  test("array content is joined to text", () => {
    const out = openaiToInteractions({
      model: "gemini-eap",
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "a" },
            { type: "text", text: "b" },
          ],
        },
      ],
    }) as { input?: string };
    expect(out["input"]).toBe("user: ab");
  });

  test("stream / previous_interaction_id are forwarded", () => {
    const out = openaiToInteractions({
      model: "gemini-eap",
      messages: [{ role: "user", content: "hi" }],
      stream: true,
      previous_interaction_id: "abc",
    }) as Record<string, unknown>;
    expect(out["stream"]).toBe(true);
    expect(out["previous_interaction_id"]).toBe("abc");
  });
});

describe("interactionsToOpenai", () => {
  test("no steps -> stop, no content", () => {
    const out = interactionsToOpenai(
      { id: "i", steps: [] },
      "gemini-eap",
    ) as Record<string, unknown>;
    expect(out["choices"]?.[0]?.["finish_reason"]).toBe("stop");
    expect(out["choices"]?.[0]?.["message"]?.["content"]).toBe("");
  });

  test("function_call step -> assistant tool_calls with finish_reason tool_calls", () => {
    const out = interactionsToOpenai(
      {
        id: "i1",
        steps: [
          {
            type: "function_call",
            id: "fc1",
            name: "get_weather",
            arguments: { city: "NYC" },
          },
        ],
      },
      "gemini-eap",
    ) as Record<string, unknown>;
    const msg = out["choices"]?.[0]?.["message"] as Record<string, unknown>;
    expect(out["choices"]?.[0]?.["finish_reason"]).toBe("tool_calls");
    expect((msg["tool_calls"] as unknown[])[0]).toEqual({
      id: "fc1",
      type: "function",
      function: { name: "get_weather", arguments: '{"city":"NYC"}' },
    });
  });

  test("mcp_server_tool_call step -> namespaced server:tool", () => {
    const out = interactionsToOpenai(
      {
        id: "i2",
        steps: [
          {
            type: "mcp_server_tool_call",
            id: "mc1",
            server_name: "fs",
            name: "read",
            arguments: { p: "/a" },
          },
        ],
      },
      "gemini-eap",
    ) as Record<string, unknown>;
    const msg = out["choices"]?.[0]?.["message"] as Record<string, unknown>;
    expect((msg["tool_calls"] as unknown[])[0]).toEqual({
      id: "mc1",
      type: "function",
      function: { name: "fs:read", arguments: '{"p":"/a"}' },
    });
  });

  test("text steps are concatenated into assistant content", () => {
    const out = interactionsToOpenai(
      {
        id: "i3",
        steps: [
          { type: "message", content: "hello " },
          { type: "text", content: "world" },
        ],
      },
      "gemini-eap",
    ) as Record<string, unknown>;
    const msg = out["choices"]?.[0]?.["message"] as Record<string, unknown>;
    expect(out["choices"]?.[0]?.["finish_reason"]).toBe("stop");
    expect(msg["content"]).toBe("hello world");
  });

  test("string output fallback when no text steps", () => {
    const out = interactionsToOpenai(
      { id: "i4", output: "direct output", steps: [] },
      "gemini-eap",
    ) as Record<string, unknown>;
    expect(out["choices"]?.[0]?.["message"]?.["content"]).toBe("direct output");
  });
});
