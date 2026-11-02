# Changelog

Auto-backfilled from git history 2026-11-02 (real commits only).

## 2026-11-01
- test: pin anomaly-63 contract — missing label MUST error (no item matches, empty stdout, exit!=0), label-echo  (a4cca12)
- fix(cookie-vault): repoint binary path to post-reorg canonical home (ranch/products/cookie-vault) (60bf67b)

## 2026-10-31
- chore: fold-forward cookie-vault ghost-path fix + keypool config surface (2ae46b4)
- fix(keypool): CLOUDFLARE_API_TOKEN gap-fills from keyring (admit *_TOKEN in filter, drop retired ~/.secrets bl (fb45da9)

## 2026-10-30
- chore(eidos): apply bun-scaffold bunfig + infra drop-in env (qdrant/hindsight/kafka/redis) — eidos is the pare (01443d6)

## 2026-10-29
- secretsmith: get LABEL positional support (anomaly #61) — bare positional was silently dropped, search({}) mat (7a9a6cc)
- feat(keypool): cache-first kernel secrets preload (env-preload) (bb2c8c6)

## 2026-10-28
- chore(kryptos): rig keyring alias in schemas (0d1a329)
- docs: secrets SSOT layout (keyring stamps, --app contract, recovery vault) (54a9d17)
- test(keypool): hermetic quota suite (beforeAll ledger cleanup) (e9ba53d)
- feat(keypool): $160/day pro-plan quota tracker — UTC-midnight reset, restart-safe ledger, /quota endpoint, usa (a411783)
- feat(kryptos): single canonical identity + README + keypool vault wiring (3587a2e)
- fix(keypool): POOLS_PATH/AUDIT_PATH ghost defaults -> pens/estate (boot ENOENT post estate retirement) (325d44d)
- docs+chore: star-ready README (features table, keypool pools, mastership lineage) + canonical moon.yml/package (f6e7ef7)
- fix(keypool): loadSecrets merge order — file record is local override (TDD quotes.test green 41/41); keyring g (e19f114)
- feat(keypool): ingest runtime health state; canonical key-pool router (keygate retired) (f67e784)
- feat: consolidate secretsmith into kryptos master — cherry-pick label-scoped --replace + exec/env + alias-map  (f1224d1)

## 2026-10-26
- fix(keypool): strip shell quotes from secretsmith env imports (TDD) (cdfb2d5)
- fix(keypool): keyring-SSOT secret loading + strict TS7 typing + README SSOT doc (11c3f37)

## 2026-10-24
- test(keypool): TDD translate.test.ts for EAP openai<->interactions wire contract (20 cases); fold moon type +  (4a291e2)

## 2026-10-16
- moon: project scaffold (c90e902)
- init kryptos (faf578f)
