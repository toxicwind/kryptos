# cyoa-router — Choose-Your-Own-Adventure weighted router skill

A router where EVERY answer carries a weight that DIFFS the route graph. Orthogonal axes: each question is an independent dimension; the selected option's weight vector is added to the route state; the resolved route is the highest-weighted compatible route.

## Q-bank (12 orthogonal questions)

| # | Question | Options (weight → route effect) |
|---|----------|---------------------------------|
| Q1 | Latency vs quality when they conflict? | A) Latency absolutist → w_speed+3 (2s breach → race faster pattern, always) · B) Quality floor → w_quality+3 (never ship below full verification) · C) Pareto router → w_both+2 (pick from frontier per task shape) |
| Q2 | Autonomy ceiling when plausible-but-unverified? | A) Act-first → w_act+3 (default informed action, escalate only on deadlock) · B) Confirm-at-risk → w_confirm+3 (pause at every consequential edge) · C) Risk-tiered → w_tiered+2 (act freely below irreversible, confirm above) |
| Q3 | Failure posture when a daemon stops cleanly? | A) Fix-forward → w_ff+3 (root-cause + restart, never roll back) · B) Rollback → w_rb+3 (revert to known-good, investigate later) · C) Piecemeal → w_piece+2 (cherry-pick or maximally refactor the broken piece) |
| Q4 | Secrets/keys handling? | A) Vault-first → w_vault+3 (everything through keyring SSOT/secretsmith) · B) Speed → w_speed+3 (raw env vars, fastest path) · C) Hybrid → w_hyb+2 (vault for production, env for sessions) |
| Q5 | Provider/model preference when a free tier is available? | A) Free tier → w_free+3 (prefer free regardless of capability) · B) Instruction-following → w_instr+3 (prefer best instruction-following model) · C) Router-weighted → w_router+2 (router weights: FREE > FAST > follow) |
| Q6 | Concurrency/subagents appetite? | A) High parallelism → w_sub+3 (spawn many subagents, race paths) · B) Serial → w_ser+3 (one turn at a time, deterministic) · C) Adaptive → w_ad+2 (batch independent steps, serialize dependent) |
| Q7 | Git history discipline? | A) Forward-only → w_fwd+3 (dirty tree = git add *, never roll back) · B) Preserve history → w_hist+3 (keep provenance, cherry-pick only) · C) Rewrite → w_rewrite+2 (squash/rebase for clean narrative) |
| Q8 | Verification depth before declaring done? | A) Probe-everything → w_probe+3 (live HTTP + listener + state per change) · B) Smoke test → w_smoke+2 (healthz + one representative case) · C) Code-read → w_read+1 (read + reason, minimal execution) |
| Q9 | Fleet collaboration model? | A) Fleet-debate → w_fleet+3 (ambiguous → squawk fleet debate, architect only on deadlock) · B) Ask-architect → w_arch+3 (halt and ask the architect) · C) Solo-decide → w_solo+2 (decide locally, document after) |
| Q10 | Hardware/latency awareness? | A) NVMe-lane-max → w_nvme+3 (per-NVMe placement, parallel sweeps, same-fs mv) · B) Standard → w_std+2 (uniform treatment) · C) Oblivious → w_obl+1 (ignore hardware) |
| Q11 | Documentation doctrine? | A) Retro-always → w_retro+3 (dossier + KB + AGENTS table every session) · B) Code-only → w_code+2 (docs lie, code is absolute) · C) Contracts-only → w_contract+2 (only capability-contract docs persist) |
| Q12 | Public/star-readiness polish? | A) Star-whore max → w_polish+3 (badges, LICENSE, topics, tags — public-ready) · B) Private utility → w_private+2 (works-for-me beats pretty) · C) Ship-then-shine → w_ship+2 (function first, polish pass later) |

## Routing semantics

- Start state: zero vector over all weights.
- Each answer adds its option's weight vector.
- Route resolution: select the route whose requirement vector has maximal dot product with the accumulated weight vector, subject to route feasibility (daemon healthy, port free, config present).
- Each Q's three options form a simplex: exactly one may be chosen per question; weights are additive across questions.
- The router rejects routes whose constraints contradict the accumulated vector (e.g., w_code-only route cannot be selected if w_retro > w_code).

## Implementation plan (T5 TDD)

1. Write skill/core.ts: `Router` class with `ask(qId, optId)` → `weights: Map<string,number>` and `resolve(routes: Route[]) → Route`.
2. TDD: `test/weight.test.ts` — weight accumulation correctness; `test/route.test.ts` — route selection & contradiction rejection.
3. Golden-path walkthrough: one full quiz run end-to-end → recorded in `test/golden.md`.
4. Wire into `~/.tau/skills/cyoa-router/` (tau skills dir) for fleet use.

## Router contract

- `ask(qId: string, optId: string): void` — record one answer (may be called 12 times, once per question).
- `resolve(routes: Route[]): Route | null` — compute weight vector, filter feasible routes, return max dot product.
- Routes carry `weightReqs: Map<string,number>` (min weights required) and `weightExcludes: Set<string>` (weights that disqualify).
