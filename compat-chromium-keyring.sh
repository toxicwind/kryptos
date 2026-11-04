#!/usr/bin/env bash
# chromium-keyring — SUPERSEDED by kryptos (mesh project).
# Thin shim for muscle memory; one truth lives in kryptos.
# NOTE: the old `key` subcommand was removed — the raw os_crypt secret is never printed.
case "${1:-check}" in
  check) exec kryptos check ;;
  attrs) exec kryptos search --schema chromium ;;
  *) echo "chromium-keyring: superseded by kryptos; usage: chromium-keyring {check|attrs}" >&2; exit 2 ;;
esac
