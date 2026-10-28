import { describe, test, expect } from "bun:test";
import { QuotaTracker, utcDayKey } from "../src/quota.js";
const D = "/tmp/qtest-129121";

describe("QuotaTracker (pro \$160/day, UTC-midnight reset)", () => {
  test("spend accumulates and remaining decrements", () => {
    const t = QuotaTracker.open(16000, D + "/q1.json");
    t.spendForTest(9721);
    expect(t.remainingCents()).toBe(6279);
  });
  test("resets at UTC midnight boundary (day-key roll)", () => {
    const t = QuotaTracker.open(16000, D + "/q2.json");
    t.spendForTest(15999);
    t.forceDayForTest("2099-01-02");
    expect(t.remainingCents()).toBe(16000);
  });
  test("ledger persists across instances (restart-safe)", () => {
    QuotaTracker.open(16000, D + "/q3.json").spendForTest(5000);
    expect(QuotaTracker.open(16000, D + "/q3.json").remainingCents()).toBe(11000);
  });
  test("over-budget flagged, spend still recorded", () => {
    const t = QuotaTracker.open(100, D + "/q4.json");
    t.spendForTest(250);
    expect(t.remainingCents()).toBeLessThan(0);
    expect(t.overBudget()).toBe(true);
  });
  test("utcDayKey is YYYY-MM-DD UTC", () => {
    expect(utcDayKey(Date.UTC(2026,9,28,23,59,59))).toBe("2026-10-28");
    expect(utcDayKey(Date.UTC(2026,9,29,0,0,0))).toBe("2026-10-29");
  });
});
