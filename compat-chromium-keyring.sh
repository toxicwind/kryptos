#!/usr/bin/env bash
# chromium-keyring — SUPERSEDED by secretsmith (mesh project).
# Thin shim for muscle memory; one truth lives in secretsmith.
# NOTE: the old `key` subcommand was removed — the raw os_crypt secret is never printed.
case "${1:-check}" in
  check) exec secretsmith check ;;
  attrs) exec secretsmith search --schema chromium ;;
  *) echo "chromium-keyring: superseded by secretsmith; usage: chromium-keyring {check|attrs}" >&2; exit 2 ;;
esac
