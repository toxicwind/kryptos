# kryptos 🔐

![kryptos](https://img.shields.io/badge/secrets--SSOT-7A28A0?style=for-the-badge) ![bun](https://img.shields.io/badge/runtime-bun-F9E000?style=for-the-badge&logo=bun&logoColor=black) ![freedesktop](https://img.shields.io/badge/Secret%20Service-181717?style=for-the-badge)

> **kryptos** (Greek: κρυπτός, "hidden") — the secrets SSOT for the estate:
> a from-scratch [freedesktop Secret Service][ss] CLI + the **keypool** router
> that races provider keys with per-key health, cooldowns and quota lanes.
>
> [ss]: https://specifications.freedesktop.org/secret-service/latest/

```bash
secretsmith set MY_KEY                 # store into the Default keyring
secretsmith get MY_KEY --show          # read (also --json)
secretsmith env --app myapp            # export app-scoped env block
secretsmith exec -- cmd args...        # run with secrets injected
secretsmith tau-auth-sync              # mirror tau auth state
```

## What's inside

| Component | What it does |
|---|---|
| `secretsmith.ts` | The Secret Service CLI — D-Bus native via `dbus-next`; schema registry, JSON scripting mode, Chromium `os_crypt` pipeline that can never print the raw key |
| `keypool/` | Provider key-pool router (Bun.serve, :25109): races keys per pool, parks 401s with cooldowns, gap-fills secrets from the keyring SSOT, health probes via event-driven poller |
| `schemas.json` | Schema registry for structured secrets |
| `bin/secretsmith` | Launcher (bin contract: `~/.local/bin/secretsmith → here`) |

## Keypool pools

`openrouter-free`, `openrouter-paid`, `gemini-eap`, `gemini-eap-interactions`,
`nvidia`, … — pool definitions are data, not code: see the estate
`config/keypools.yaml`. Auth headers resolve through one function
(`upstreamAuthHeader`) so a new upstream cannot be half-wired: bearer for
`/openai` lanes, `x-goog-api-key` for Google-native lanes.

## Why kryptos is the master

- Single repo (`toxicwind/kryptos`) — vendored copies in `ranch` and `barn`
  were retired 2026-10-28 (md5-divergence audited, newest code cherry-picked here)
- Label-scoped `--replace`, `exec/env` + alias-map autoload (2026-10-24+)
- Keyring-SSOT secret loading; strict TS typing; TDD quotes contract (41/41)

## Lineage

From-scratch reimplementation of GNOME `secret-tool`'s D-Bus semantics — no
libsecret code. Fork lineage documented for provenance: [GNOME/libsecret](https://gitlab.gnome.org/GNOME/libsecret).

## License

MIT — see [LICENSE](LICENSE).
