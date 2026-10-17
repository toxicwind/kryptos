# keypool

*The API key pool sidecar for the mesh: health-probed, failover-aware key routing with request racing — Tier 0 of the estate's routing stack.*

![ranch](https://img.shields.io/badge/toxicwind-ranch-blue?style=for-the-badge) ![mesh](https://img.shields.io/badge/mesh-keypool-purple?style=for-the-badge) ![bun](https://img.shields.io/badge/bun-black?style=for-the-badge) ![port 25109](https://img.shields.io/badge/port-25109-orange?style=for-the-badge)

## Why this exists

Cloud providers rate-limit per key. keypool holds the estate's API keys, probes their health, and hands the routers a working key — failing over and racing requests so one dead key never stalls the mesh. It's a Bun/TypeScript port of the original `herd-keypool.py` (`@estate/keypool`).

- **Health probing** — a poller keeps per-key health fresh; dead keys are skipped, not retried into.
- **Failover + racing** — no healthy key → explicit error, never a silent stall.
- **Gemini-native aware** — serves `/v1beta/models` for the Gemini EAP path alongside OpenAI-compat `/v1/models`.

## Quick Start

```bash
bun src/index.ts                        # port via KEYPOOL_PORT (default :25109)
curl -sf http://127.0.0.1:25109/health  # liveness (when the daemon is up)
```

## Status

**DOWN as of 2026-10-02** — nothing is listening on `:25109`; cuttinggate currently handles keys itself. A pitchfork stanza does ship (`estate/pitchfork.d/keypool.toml`, mirrored as `[daemons.keypool]` in `estate/pitchfork.toml`, `auto = ["start"]`, currently stopped); to run it by hand use `bun src/index.ts`.

## Layout

```text
src/
  index.ts    entry — Bun.serve, KEYPOOL_PORT (default 25109)
  pool.ts     key-pool routing: health, failover, racing
  config.ts   pool + key configuration
  server.ts   HTTP surface (/health, /models, /v1/models, /v1beta/models)
  poller.ts   background health probing
  audit.ts    key auditing
test/         bun test suite
```

## Dev / contributing

Changes land as commits in the [toxicwind/ranch](https://github.com/toxicwind/ranch) repo (`mesh/keypool/`). `bun test` before pushing. Keys live in 0600 files under `/home/toxic/` — never in this repo, never in logs.