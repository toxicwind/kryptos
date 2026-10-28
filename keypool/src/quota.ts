// QuotaTracker — FreeInference pro-plan daily quota ledger.
// Contract (dossier 2026-10-28): JWT role:pro => \$160.00/day ceiling,
// resets at UTC midnight (provider-side build d55dab6 semantics).
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

export function utcDayKey(ms: number = Date.now()): string {
  return new Date(ms).toISOString().slice(0, 10);
}

export class QuotaTracker {
  private day: string;
  private spentCents: number;
  private constructor(
    readonly dailyLimitCents: number,
    readonly ledgerPath: string,
  ) {
    this.day = "";
    this.spentCents = 0;
    this.load();
  }
  static open(dailyLimitCents: number, ledgerPath: string): QuotaTracker {
    return new QuotaTracker(dailyLimitCents, ledgerPath);
  }
  private load(): void {
    try {
      if (existsSync(this.ledgerPath)) {
        const j = JSON.parse(readFileSync(this.ledgerPath, "utf8")) as {
          day?: string; spentCents?: number;
        };
        this.day = j.day ?? "";
        this.spentCents = j.spentCents ?? 0;
      }
    } catch { /* corrupt ledger => fresh day */ }
    this.rolloverIfNewDay();
  }
  private rolloverIfNewDay(): void {
    const today = utcDayKey();
    if (this.day !== today) { this.day = today; this.spentCents = 0; }
  }
  private persist(): void {
    mkdirSync(dirname(this.ledgerPath), { recursive: true });
    writeFileSync(this.ledgerPath, JSON.stringify({ day: this.day, spentCents: this.spentCents }));
  }
  spend(dollarsSpent: number): void { this.spendForTest(Math.round(dollarsSpent * 100)); }
  spendCents(cents: number): void { this.spendForTest(cents); }
  spendForTest(cents: number): void {
    this.rolloverIfNewDay();
    this.spentCents += cents;
    this.persist();
  }
  remainingCents(): number { this.rolloverIfNewDay(); return this.dailyLimitCents - this.spentCents; }
  forceDayForTest(day: string): void { this.day = day; this.spentCents = 0; this.persist(); }
  overBudget(): boolean { return this.remainingCents() < 0; }
  snapshot() { this.rolloverIfNewDay(); return { day: this.day, limitCents: this.dailyLimitCents, spentCents: this.spentCents, remainingCents: this.remainingCents() }; }
}
