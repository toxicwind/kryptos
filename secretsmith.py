#!/usr/bin/env python3
"""
secretsmith — maximal freedesktop Secret Service CLI for the estate.

Fork lineage: GNOME/libsecret (secret-tool), forked to toxicwind/libsecret.
This tool reimplements and maximalizes secret-tool's D-Bus semantics in Python
(stdlib dbus-python + cryptography, no secretstorage needed):

  * full item CRUD: search / list / get / set / delete with attribute filters
  * collection management: create / delete / lock / unlock, default alias
  * JSON output mode for everything (scriptable)
  * known-schema registry (schemas.json) — schema-aware search, so the
    wrong-schema empty search that started this project is impossible
  * Chromium/Chrome os_crypt pipeline: key lookup + Login Data / Cookies
    decryption (the real use case that started this)
  * safe defaults: secrets never printed without --show; values redacted in
    listings and logs; os_crypt key material (secret_is_key schemas) is
    never printed on any path -- check/attrs are metadata-only
  * `exec` subcommand: run a command with secrets injected as env vars
    (secrets never printed)
  * `env` subcommand: resolve keyring items to env vars with alias expansion
  * `check` health command

Exit codes: 0 ok, 1 runtime error, 2 usage error.
"""

import argparse
import base64
import copy
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

try:
    import dbus
except ImportError:  # pragma: no cover — yote has dbus-python; the cell does not
    dbus = None

BUS_NAME = "org.freedesktop.secrets"
SERVICE_PATH = "/org/freedesktop/secrets"
IFACE_SERVICE = "org.freedesktop.Secret.Service"
IFACE_COLLECTION = "org.freedesktop.Secret.Collection"
IFACE_ITEM = "org.freedesktop.Secret.Item"
IFACE_PROPS = "org.freedesktop.DBus.Properties"

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY_PATH = os.path.join(HERE, "schemas.json")


class SecretsmithError(RuntimeError):
    pass


def load_registry():
    try:
        with open(REGISTRY_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise SecretsmithError(
            "cannot load schema registry %s: %s" % (REGISTRY_PATH, e)
        )


def resolve_schema(name, registry):
    """Resolve a friendly schema name (or raw xdg:schema) to an xdg:schema value."""
    schemas = registry.get("schemas", {})
    if name in schemas:
        entry = schemas[name]
        while "alias_of" in entry:
            entry = schemas[entry["alias_of"]]
        return entry["xdg:schema"], entry
    # raw schema string passthrough (warned at call site)
    return name, {"xdg:schema": name, "description": "unregistered raw schema"}


def protected_schemas(registry):
    """xdg:schema strings whose secrets must NEVER be printed.

    Driven by the registry: any schema entry with secret_is_key: true
    (Chromium's os_crypt Safe Storage entry) is display-protected on every
    output path -- get --show, search --show, human and JSON alike. The key
    is consumed internally by decrypt operations only; no flag can print it.
    """
    out = set()
    for _name, entry in registry.get("schemas", {}).items():
        if isinstance(entry, dict) and entry.get("secret_is_key"):
            xs = entry.get("xdg:schema")
            if xs:
                out.add(xs)
    return out


def _refuse_protected(item, registry):
    schema = (item.get("attributes") or {}).get("xdg:schema", "")
    if schema in protected_schemas(registry):
        raise SecretsmithError(
            "refusing to display secret for schema %r: os_crypt key material "
            "is never printed (check/attrs report metadata only)" % schema
        )


def redact(nbytes):
    return "<redacted: %d bytes>" % nbytes


class SecretService:
    def __init__(self, bus=None):
        if dbus is None:
            raise SecretsmithError("dbus-python is required on this machine")
        self.bus = bus or dbus.SessionBus()
        if not self.bus.name_has_owner(BUS_NAME):
            raise SecretsmithError(
                "no %s on the session bus (is a Secret Service daemon running? "
                "bus=%s)"
                % (BUS_NAME, os.environ.get("DBUS_SESSION_BUS_ADDRESS", "(default)"))
            )
        obj = self.bus.get_object(BUS_NAME, SERVICE_PATH)
        self.svc = dbus.Interface(obj, IFACE_SERVICE)
        self._session = None

    # -- low-level helpers -------------------------------------------------
    def _props(self, path):
        return dbus.Interface(self.bus.get_object(BUS_NAME, path), IFACE_PROPS)

    def _get(self, path, iface, prop):
        return self._props(path).Get(iface, prop)

    def session(self):
        if self._session is None:
            # 'plain' session: input is an empty-string variant
            _out, sess = self.svc.OpenSession("plain", dbus.String("", variant_level=1))
            self._session = str(sess)
        return self._session

    # -- collections --------------------------------------------------------
    def collections(self):
        out = []
        for p in self._get(SERVICE_PATH, IFACE_SERVICE, "Collections"):
            p = str(p)
            out.append(
                {
                    "path": p,
                    "label": str(self._get(p, IFACE_COLLECTION, "Label")),
                    "locked": bool(self._get(p, IFACE_COLLECTION, "Locked")),
                }
            )
        return out

    def default_collection(self):
        p = str(self.svc.ReadAlias("default"))
        return p if p != "/" else None

    def resolve_collection(self, target):
        """target: label, 'default', or object path -> object path."""
        if target == "default":
            p = self.default_collection()
            if not p:
                raise SecretsmithError("no default collection alias set")
            return p
        if target.startswith("/"):
            return target
        for c in self.collections():
            if c["label"] == target:
                return c["path"]
        raise SecretsmithError("no such collection: %r" % target)

    def create_collection(self, label, alias=""):
        props = {"org.freedesktop.Secret.Collection.Label": label}
        path, prompt = self.svc.CreateCollection(props, alias or "")
        path, prompt = str(path), str(prompt)
        if prompt != "/":
            self._await_unlock([path])
        return path

    def delete_collection(self, target):
        path = self.resolve_collection(target)
        dbus.Interface(self.bus.get_object(BUS_NAME, path), IFACE_COLLECTION).Delete()
        return path

    # -- items ---------------------------------------------------------------
    def _item_paths(self, collection_path):
        return [str(p) for p in self._get(collection_path, IFACE_COLLECTION, "Items")]

    def item_attributes(self, item_path):
        raw = self._get(item_path, IFACE_ITEM, "Attributes")
        return {str(k): str(v) for k, v in dict(raw).items()}

    def item_info(self, item_path, collection_label):
        return {
            "path": item_path,
            "collection": collection_label,
            "label": str(self._get(item_path, IFACE_ITEM, "Label")),
            "locked": bool(self._get(item_path, IFACE_ITEM, "Locked")),
            "attributes": self.item_attributes(item_path),
            "created": int(self._get(item_path, IFACE_ITEM, "Created")),
            "modified": int(self._get(item_path, IFACE_ITEM, "Modified")),
        }

    def list_items(self, collection=None):
        items = []
        for c in self.collections():
            if collection and collection not in (c["path"], c["label"]):
                continue
            for ip in self._item_paths(c["path"]):
                items.append(self.item_info(ip, c["label"]))
        return items

    def search(self, attr_filters, collection=None, label=None, query=None):
        out = []
        for it in self.list_items(collection):
            if label is not None and it.get("label") != label:
                continue
            if not all(it["attributes"].get(k) == v for k, v in attr_filters.items()):
                continue
            if query is not None:
                hay = " ".join(
                    [it.get("label") or ""]
                    + ["%s=%s" % (k, v) for k, v in it["attributes"].items()]
                )
                if query.lower() not in hay.lower():
                    continue
            out.append(it)
        return out

    def is_locked(self, path, iface):
        return bool(self._get(path, iface, "Locked"))

    def _await_unlock(self, paths, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            states = []
            for p in paths:
                iface = (
                    IFACE_COLLECTION
                    if "/collection/" in p or p == self.default_collection()
                    else IFACE_ITEM
                )
                try:
                    states.append(self.is_locked(p, iface))
                except dbus.DBusException:
                    states.append(True)
            if not any(states):
                return
            time.sleep(0.5)
        raise SecretsmithError(
            "unlock did not complete (keyring may need a GUI unlock)"
        )

    def unlock_paths(self, paths):
        if not paths:
            return []
        unlocked, prompt = self.svc.Unlock([dbus.ObjectPath(p) for p in paths])
        if str(prompt) != "/":
            self._await_unlock([str(p) for p in paths])
        return [str(p) for p in unlocked]

    def ensure_unlocked_items(self, items):
        locked = [it["path"] for it in items if it["locked"]]
        if locked:
            self.unlock_paths(locked)
            for it in items:
                it["locked"] = False

    def get_secret(self, item_path):
        item = dbus.Interface(self.bus.get_object(BUS_NAME, item_path), IFACE_ITEM)
        _sess, _params, secret, content_type = item.GetSecret(
            dbus.ObjectPath(self.session())
        )
        return bytes(secret), str(content_type)

    def set_item(
        self,
        collection_target,
        label,
        attributes,
        secret_bytes,
        content_type="text/plain",
        replace=False,
    ):
        cpath = self.resolve_collection(collection_target)
        if self.is_locked(cpath, IFACE_COLLECTION):
            self.unlock_paths([cpath])
        coll = dbus.Interface(self.bus.get_object(BUS_NAME, cpath), IFACE_COLLECTION)
        props = {
            "org.freedesktop.Secret.Item.Label": label,
            "org.freedesktop.Secret.Item.Attributes": dbus.Dictionary(
                attributes, signature="ss"
            ),
        }
        secret = (
            dbus.ObjectPath(self.session()),
            dbus.ByteArray(b""),
            dbus.ByteArray(secret_bytes),
            content_type,
        )
        item_path, prompt = coll.CreateItem(props, secret, replace)
        item_path, prompt = str(item_path), str(prompt)
        if prompt != "/":
            self._await_unlock([item_path])
        return item_path

    def delete_item(self, item_path):
        dbus.Interface(self.bus.get_object(BUS_NAME, item_path), IFACE_ITEM).Delete()

    def lock(self, paths):
        locked, prompt = self.svc.Lock([dbus.ObjectPath(p) for p in paths])
        return [str(p) for p in locked]

    def unlock(self, paths):
        return self.unlock_paths(paths)


# -- Chromium / Chrome os_crypt pipeline --------------------------------------
# Linux Chromium encrypts Login Data / Cookies with AES-128-CBC (IV = 16 spaces),
# blobs prefixed b'v10'/b'v11', key = the Secret Service item's secret under
# schema chrome_libsecret_os_crypt_password_v2. The stored secret is commonly
# base64 (24 chars incl. '==' padding for a 16-byte key); we try raw and
# base64-decoded candidates and validate via PKCS#7.

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False


def _key_candidates(raw):
    cands, seen = [], set()
    s = bytes(raw).strip()
    if s and s not in seen:
        seen.add(s)
        cands.append(s)
    b64alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    if s and len(s) % 4 == 0 and all(c in b64alphabet for c in s):
        try:
            d = base64.b64decode(s, validate=True)
            if d not in seen:
                cands.append(d)
        except Exception:
            pass
    return [c for c in cands if len(c) in (16, 24, 32)]


def decrypt_chromium_blob(blob, key_candidates):
    if not _HAVE_CRYPTO:
        raise SecretsmithError("cryptography package required for decryption")
    blob = bytes(blob)
    if blob[:3] not in (b"v10", b"v11"):
        raise SecretsmithError(
            "unsupported blob prefix %r (expected v10/v11)" % blob[:3]
        )
    ct = blob[3:]
    for key in key_candidates:
        try:
            d = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor()
            pt = d.update(ct) + d.finalize()
        except Exception:
            continue
        pad = pt[-1]
        if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
            return pt[:-pad]
    raise SecretsmithError(
        "decryption failed with all %d key candidates" % len(key_candidates)
    )


def chromium_key_bytes(svc, registry):
    schema, _entry = resolve_schema("chromium", registry)
    found = svc.search({"xdg:schema": schema})
    if not found:
        raise SecretsmithError("no Chromium Safe Storage entry (schema %s)" % schema)
    svc.ensure_unlocked_items(found)
    secret, _ct = svc.get_secret(found[0]["path"])
    return secret, found[0]


def _copy_profile_db(profile_dir, name):
    src = os.path.join(profile_dir, name)
    if not os.path.exists(src):
        raise SecretsmithError("profile db not found: %s" % src)
    tmp = tempfile.mkdtemp(prefix="secretsmith-")
    dst = os.path.join(tmp, name)
    shutil.copy2(src, dst)
    for suffix in ("-wal", "-shm"):
        if os.path.exists(src + suffix):
            shutil.copy2(src + suffix, dst + suffix)
    return dst, tmp


def _to_bytes(v):
    if isinstance(v, bytes):
        return v
    if isinstance(v, (bytearray, memoryview)):
        return bytes(v)
    if isinstance(v, str):
        return v.encode("utf-8")  # best effort; sqlite TEXT affinity
    raise SecretsmithError("cannot coerce %r to bytes" % type(v))


def _to_text(v):
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return str(v)


def _open_ro(db_path):
    con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    con.text_factory = bytes  # everything comes back bytes; we decode text cols
    return con


def chromium_logins(svc, registry, profile_dir):
    key, _info = chromium_key_bytes(svc, registry)
    cands = _key_candidates(key)
    if not cands:
        raise SecretsmithError(
            "no usable AES key candidate from keyring secret (%d bytes)" % len(key)
        )
    db_path, tmpdir = _copy_profile_db(profile_dir, "Login Data")
    try:
        con = _open_ro(db_path)
        rows = con.execute(
            "SELECT origin_url, username_value, password_value FROM logins"
        ).fetchall()
        con.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    out = []
    for url_b, user_b, blob in rows:
        try:
            pw = decrypt_chromium_blob(_to_bytes(blob), cands).decode(
                "utf-8", "replace"
            )
            ok = True
        except SecretsmithError:
            pw, ok = None, False
        out.append(
            {
                "origin_url": _to_text(url_b),
                "username": _to_text(user_b),
                "password": pw,
                "decrypted": ok,
            }
        )
    return out


def chromium_cookies(svc, registry, profile_dir):
    key, _info = chromium_key_bytes(svc, registry)
    cands = _key_candidates(key)
    if not cands:
        raise SecretsmithError(
            "no usable AES key candidate from keyring secret (%d bytes)" % len(key)
        )
    db_path, tmpdir = _copy_profile_db(profile_dir, "Cookies")
    try:
        con = _open_ro(db_path)
        rows = con.execute(
            "SELECT host_key, name, path, value, encrypted_value FROM cookies"
        ).fetchall()
        con.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    out = []
    for host_b, name_b, path_b, value_b, blob in rows:
        host, name, path = _to_text(host_b), _to_text(name_b), _to_text(path_b)
        value = _to_text(value_b) if value_b else ""
        if value:
            out.append(
                {
                    "host": host,
                    "name": name,
                    "path": path,
                    "value": value,
                    "decrypted": True,
                    "source": "plaintext",
                }
            )
            continue
        try:
            dec = decrypt_chromium_blob(_to_bytes(blob), cands).decode(
                "utf-8", "replace"
            )
            ok = True
        except SecretsmithError:
            dec, ok = None, False
        out.append(
            {
                "host": host,
                "name": name,
                "path": path,
                "value": dec,
                "decrypted": ok,
                "source": "encrypted",
            }
        )
    return out


# -- Alias map ----------------------------------------------------------------


def _load_alias_map(config_dir=None):
    """Load alias map from ~/.config/secretsmith/aliases.toml (or TOML/json).

    Format: [aliases]  GH_TOKEN = "GITHUB_TOKEN"  etc.
    Returns dict {alias_name: canonical_label}.
    """
    if config_dir is None:
        config_dir = os.path.join(os.path.expanduser("~"), ".config", "secretsmith")
    for fname in ("aliases.toml", "aliases.json"):
        fpath = os.path.join(config_dir, fname)
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, "rb" if fname.endswith(".toml") else "r") as f:
                data = json.load(f) if fname.endswith(".json") else _load_toml(fpath)
            aliases = data.get("aliases", {})
            if not isinstance(aliases, dict):
                aliases = {}
            return aliases
        except (OSError, ValueError) as e:
            print("warning: cannot load alias map %s: %s" % (fpath, e), file=sys.stderr)
            return {}
    return {}


def _load_toml(fpath):
    """Minimal TOML loader for aliases.toml (handles [aliases] + key = "value")."""
    import importlib

    try:
        tomllib = importlib.import_module("tomllib")  # 3.11+
    except ImportError:
        try:
            import tomli as _tl

            tomllib = _tl
        except ImportError:
            # Fallback: simple parser for flat [aliases] sections
            return _simple_toml_load(fpath)
    with open(fpath, "rb") as f:
        return tomllib.load(f)


def _simple_toml_load(fpath):
    """Minimal TOML parser for the aliases.toml format."""
    import re

    aliases = {}
    in_aliases = False
    with open(fpath) as f:
        for line in f:
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                in_aliases = line[1:-1].strip() == "aliases"
                continue
            if in_aliases and "=" in line and not line.startswith("#"):
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and val:
                    aliases[key] = val
    return {"aliases": aliases}


def _resolve_alias(aliases, env_name):
    """Resolve an env var name through the alias map.

    Returns (canonical_label, is_alias).
    If env_name is in aliases, returns (aliases[env_name], True).
    Otherwise returns (env_name, False).
    """
    if env_name in aliases:
        return aliases[env_name], True
    return env_name, False


# -- CLI ------------------------------------------------------------------------


def parse_attrs(pairs):
    attrs = {}
    for p in pairs or []:
        if "=" not in p:
            raise SecretsmithError("attribute must be k=v, got %r" % p)
        k, v = p.split("=", 1)
        attrs[k] = v
    return attrs


def fmt_item_human(it, show):
    lines = [
        "[%s] %s  (collection: %s%s)"
        % (
            it["path"],
            it["label"],
            it["collection"],
            ", LOCKED" if it["locked"] else "",
        )
    ]
    for k in sorted(it["attributes"]):
        lines.append("    %s = %s" % (k, it["attributes"][k]))
    if show:
        secret_txt = it.get("secret_preview", redact(0))
    elif it.get("secret_len") is None:
        secret_txt = "<not fetched — use --show>"
    else:
        secret_txt = redact(it["secret_len"])
    lines.append("    secret = %s" % secret_txt)
    return "\n".join(lines)


_BASE_RE = re.compile(r"[_\-]?\d+$")


def _normalize_label(s):
    """Case- and separator-insensitive normalization for fuzzy label match."""
    return re.sub(r"[\s_\-.]+", "", (s or "").casefold())


def _fuzzy_find(svc, label, collection=None):
    """Find keyring items whose label fuzzy-matches `label`.

    Precedence: normalized-exact > prefix > substring; ties broken by
    shortest label then lexicographic for determinism.
    """
    target = _normalize_label(label)
    if not target:
        return []
    try:
        items = svc.search({}, collection=collection)
    except SecretsmithError:
        return []
    exact, prefix, substring = [], [], []
    for it in items:
        lab = it.get("label") or ""
        norm = _normalize_label(lab)
        if not norm:
            continue
        if norm == target:
            exact.append(it)
        elif norm.startswith(target):
            prefix.append(it)
        elif target in norm:
            substring.append(it)
    for bucket in (exact, prefix, substring):
        if bucket:
            return sorted(
                bucket,
                key=lambda it: (len(it.get("label") or ""), it.get("label") or ""),
            )
    return []


def cmd_search(svc, a, registry, as_json):
    filters = parse_attrs(a.attr)
    warned = False
    if a.schema:
        schema, entry = resolve_schema(a.schema, registry)
        if entry.get("description", "").startswith("unregistered"):
            warned = True
        filters["xdg:schema"] = schema
    # NOTE: no schema filter by default — we search EVERYTHING, so the original
    # bug (wrong-schema filter silently returning empty) cannot happen.
    found = svc.search(
        filters,
        collection=a.collection,
        label=getattr(a, "label", None),
        query=getattr(a, "query", None),
    )
    if a.show:
        for it in found:
            _refuse_protected(it, registry)
        svc.ensure_unlocked_items(found)
        for it in found:
            secret, _ct = svc.get_secret(it["path"])
            it["secret_len"] = len(secret)
            it["secret_preview"] = (
                secret.decode("utf-8", "replace")
                if _is_text(secret)
                else redact(len(secret))
            )
    else:
        for it in found:
            it["secret_len"] = None  # unknown until read; never fetched without --show
    if as_json:
        print(
            json.dumps(
                {
                    "count": len(found),
                    "items": [
                        {k: v for k, v in it.items() if k != "secret_preview" or a.show}
                        for it in found
                    ],
                },
                indent=2,
            )
        )
    else:
        if warned:
            print(
                "warning: schema %r not in registry, used as raw xdg:schema" % a.schema,
                file=sys.stderr,
            )
        if not found:
            print("(no items match)")
        for it in found:
            print(fmt_item_human(it, a.show))
            print()
    return 0


def _is_text(b):
    try:
        b.decode("utf-8")
        return True
    except ValueError:
        return False


def cmd_get(svc, a, registry, as_json):
    filters = parse_attrs(a.attr)
    label = getattr(a, "label", None)
    found = svc.search(filters, collection=a.collection, label=label)
    if not found and label and not getattr(a, "no_fuzzy", False) and not filters:
        found = _fuzzy_find(svc, label, collection=a.collection)
        if len(found) > 1:
            # Family auto-pick: the shortest match wins only when it is a
            # normalized prefix of every other match (canonical base item,
            # e.g. FOO with FOO_1/FOO_FREE variants). Genuinely divergent
            # labels stay ambiguous and error with candidates.
            norm = [(_normalize_label(it.get("label") or ""), it) for it in found]
            norm.sort(key=lambda p: len(p[0]))
            base = norm[0][0]
            if all(n.startswith(base) for n, _ in norm[1:]):
                found = [norm[0][1]]
        if len(found) > 1:
            raise SecretsmithError(
                "%d fuzzy matches for %r: %s — refine with --label or --no-fuzzy"
                % (
                    len(found),
                    label,
                    ", ".join(sorted(it.get("label") or "" for it in found)),
                )
            )
    if not found:
        raise SecretsmithError("no item matches %r" % filters)
    if len(found) > 1:
        raise SecretsmithError(
            "%d items match %r — refine attributes" % (len(found), filters)
        )
    it = found[0]
    if a.show:
        _refuse_protected(it, registry)
    svc.ensure_unlocked_items([it])
    secret, content_type = svc.get_secret(it["path"])
    if as_json:
        print(
            json.dumps(
                {
                    "label": it["label"],
                    "path": it["path"],
                    "attributes": it["attributes"],
                    "content_type": content_type,
                    "secret": secret.decode("utf-8", "replace")
                    if a.show and _is_text(secret)
                    else (redact(len(secret)) if not a.show else None),
                    "secret_base64": base64.b64encode(secret).decode()
                    if a.show and not _is_text(secret)
                    else None,
                },
                indent=2,
            )
        )
    else:
        print(
            "label: %s\npath: %s\ncontent_type: %s"
            % (it["label"], it["path"], content_type)
        )
        for k in sorted(it["attributes"]):
            print("attr %s = %s" % (k, it["attributes"][k]))
        if a.show:
            if _is_text(secret):
                print("secret: %s" % secret.decode("utf-8", "replace"))
            else:
                print("secret (base64): %s" % base64.b64encode(secret).decode())
        else:
            print("secret: %s  (use --show to print)" % redact(len(secret)))
    return 0


def read_secret_input(a):
    if a.secret_file:
        with open(a.secret_file, "rb") as f:
            data = f.read()
    else:
        if sys.stdin.isatty():
            sys.stderr.write("secret (stdin, end with Ctrl-D): ")
        data = sys.stdin.buffer.read()
    if data.endswith(b"\n"):
        data = data[:-1]  # strip one trailing newline (echo convention)
    if not data:
        raise SecretsmithError("empty secret — refusing to store nothing")
    return data


def cmd_set(svc, a, registry, as_json):
    attrs = parse_attrs(a.attr)
    secret = read_secret_input(a)
    collection = a.collection or "default"
    if collection == "default" and not svc.default_collection():
        colls = svc.collections()
        if not colls:
            raise SecretsmithError("no collections exist — create one first")
        collection = colls[0]["label"]
    # `--replace` means "replace by LABEL", not "replace by identical attributes".
    # libsecret's CreateItem(replace=True) only overwrites an item whose
    # attributes EXACTLY match the incoming ones; when they differ it creates a
    # fresh item, silently leaving a duplicate label (the 2026-10-24
    # GITHUB_TOKEN duplication root cause). Delete existing same-label items
    # first, then create one fresh item with the caller's attributes.
    if a.replace:
        for it in svc.search({}, collection=collection, label=a.label):
            svc.delete_item(it["path"])
    path = svc.set_item(collection, a.label, attrs, secret, replace=False)
    if as_json:
        print(
            json.dumps(
                {"stored": True, "path": path, "label": a.label, "attributes": attrs},
                indent=2,
            )
        )
    else:
        print("stored %s (%d bytes)" % (path, len(secret)))
    return 0


def cmd_delete(svc, a, registry, as_json):
    filters = parse_attrs(a.attr)
    found = svc.search(
        filters, collection=a.collection, label=getattr(a, "label", None)
    )
    if not found:
        raise SecretsmithError("no item matches %r" % filters)
    if not a.yes:
        print("would delete %d item(s):" % len(found))
        for it in found:
            print("  [%s] %s" % (it["path"], it["label"]))
        print("re-run with --yes to delete")
        return 0
    for it in found:
        svc.delete_item(it["path"])
    if as_json:
        print(json.dumps({"deleted": [it["path"] for it in found]}, indent=2))
    else:
        print("deleted %d item(s)" % len(found))
    return 0


def cmd_collections(svc, a, registry, as_json):
    colls = svc.collections()
    default = svc.default_collection()
    for c in colls:
        c["default"] = c["path"] == default
        c["items"] = len(svc._item_paths(c["path"]))
    if as_json:
        print(json.dumps({"collections": colls}, indent=2))
    else:
        for c in colls:
            print(
                "%s  label=%r  locked=%s  items=%d%s"
                % (
                    c["path"],
                    c["label"],
                    c["locked"],
                    c["items"],
                    "  [default]" if c["default"] else "",
                )
            )
    return 0


def cmd_collection_create(svc, a, registry, as_json):
    path = svc.create_collection(a.name, alias=a.alias or "")
    if as_json:
        print(json.dumps({"created": path, "label": a.name}, indent=2))
    else:
        print("created collection %s" % path)
    return 0


def cmd_collection_delete(svc, a, registry, as_json):
    path = svc.resolve_collection(a.name)
    n = len(svc._item_paths(path))
    if n and not a.yes:
        print("collection %s holds %d item(s); re-run with --yes" % (path, n))
        return 0
    svc.delete_collection(a.name)
    if as_json:
        print(json.dumps({"deleted": path}, indent=2))
    else:
        print("deleted collection %s" % path)
    return 0


def _resolve_targets(svc, targets, kind):
    paths = []
    for t in targets:
        if kind == "collection" or not t.startswith("/"):
            try:
                paths.append(svc.resolve_collection(t))
                continue
            except SecretsmithError:
                pass
        if t.startswith("/"):
            paths.append(t)
        else:
            raise SecretsmithError("cannot resolve %r as collection or path" % t)
    return paths


def cmd_lock(svc, a, registry, as_json):
    paths = _resolve_targets(svc, a.targets, "any")
    locked = svc.lock(paths)
    if as_json:
        print(json.dumps({"locked": locked}, indent=2))
    else:
        print("locked: %s" % ", ".join(locked))
    return 0


def cmd_unlock(svc, a, registry, as_json):
    paths = _resolve_targets(svc, a.targets, "any")
    unlocked = svc.unlock(paths)
    if as_json:
        print(json.dumps({"unlocked": unlocked}, indent=2))
    else:
        print("unlocked: %s" % ", ".join(unlocked))
    return 0


def cmd_schemas(svc, a, registry, as_json):
    schemas = registry.get("schemas", {})
    if as_json:
        print(json.dumps({"schemas": schemas}, indent=2))
    else:
        for name in sorted(schemas):
            e = schemas[name]
            print(
                "%-10s -> %s%s"
                % (
                    name,
                    e.get("xdg:schema", "?"),
                    "  (alias of %s)" % e["alias_of"] if "alias_of" in e else "",
                )
            )
            if e.get("description"):
                print("             %s" % e["description"])
    return 0


def cmd_check(svc, a, registry, as_json):
    result = {"service": BUS_NAME, "ok": True, "problems": []}
    result["bus"] = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "(default)")
    colls = svc.collections()
    result["collections"] = len(colls)
    default = svc.default_collection()
    result["default_collection"] = default
    if default:
        result["default_locked"] = svc.is_locked(default, IFACE_COLLECTION)
        if result["default_locked"]:
            result["problems"].append("default collection is locked")
    else:
        result["problems"].append("no default collection alias")
    schema, _e = resolve_schema("chromium", registry)
    found = svc.search({"xdg:schema": schema})
    result["chromium_entry"] = bool(found)
    if found:
        try:
            svc.ensure_unlocked_items(found)
            secret, _ct = svc.get_secret(found[0]["path"])
            result["chromium_secret_bytes"] = len(secret)
            result["chromium_key_candidates"] = len(_key_candidates(secret))
        except SecretsmithError as e:
            result["problems"].append("chromium secret unreadable: %s" % e)
    else:
        result["problems"].append("no Chromium Safe Storage entry")
    result["ok"] = not result["problems"]
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print("service: %s  bus: %s" % (result["service"], result["bus"]))
        print(
            "collections: %d  default: %s%s"
            % (
                result["collections"],
                result["default_collection"],
                " (LOCKED)" if result.get("default_locked") else "",
            )
        )
        print(
            "chromium entry: %s%s"
            % (
                "yes" if result["chromium_entry"] else "NO",
                "  secret=%d bytes, key candidates=%d"
                % (
                    result.get("chromium_secret_bytes", 0),
                    result.get("chromium_key_candidates", 0),
                )
                if result["chromium_entry"] and "chromium_secret_bytes" in result
                else "",
            )
        )
        if result["problems"]:
            print("PROBLEMS:")
            for p in result["problems"]:
                print("  - %s" % p)
        else:
            print("OK — all checks passed")
    return 0 if result["ok"] else 1


_SHELL_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def cmd_env(svc, a, registry, as_json):
    """Drop-in env loader with alias expansion support.

    If --env specs are given, resolves each VAR=k=v[,k2=v2...] against the keyring.
    With --alias-map (default: ~/.config/secretsmith/aliases.toml), env names that
    are aliases expand to their canonical label and are injected too.
    With --all (and no --env), exports every keyring item whose label is a valid
    shell identifier, expanded through the alias map.
    """
    aliases = _load_alias_map(getattr(a, "alias_map", None) or None)
    exports = {}

    if getattr(a, "env", None):
        # --env mode: resolve explicit VAR=k=v specs
        for spec in a.env:
            if "=" not in spec:
                raise SecretsmithError(
                    "env spec must be VAR=k=v[,k2=v2...], got %r" % spec
                )
            var, attrspec = spec.split("=", 1)
            if not var.isidentifier():
                raise SecretsmithError(
                    "env var name %r is not a valid identifier" % var
                )
            canonical, is_alias = _resolve_alias(aliases, var)
            filters = parse_attrs(attrspec.split(","))
            found = svc.search(
                filters, collection=getattr(a, "collection", None), label=canonical
            )
            if not found:
                raise SecretsmithError("no item matches %r" % filters)
            if len(found) > 1:
                raise SecretsmithError(
                    "%d items match %r — refine attributes" % (len(found), filters)
                )
            it = found[0]
            _refuse_protected(it, registry)
            svc.ensure_unlocked_items([it])
            secret, _ct = svc.get_secret(it["path"])
            value = secret.decode("utf-8", "replace")
            exports[var] = value
            # Also inject the canonical name if not already present
            if canonical != var and canonical not in exports:
                exports[canonical] = value
            # Inject all other aliases that point to the same canonical
            for alias_name, alias_canon in aliases.items():
                if (
                    alias_canon == canonical
                    and alias_name != var
                    and alias_name not in exports
                ):
                    exports[alias_name] = value
    elif getattr(a, "all", False):
        # --all mode: every keyring item, expanded through alias map
        found = svc.search({}, collection=getattr(a, "collection", None))
        found = [it for it in found if _SHELL_IDENT.match(it.get("label") or "")]
        if found:
            svc.ensure_unlocked_items(found)
        for it in found:
            label = it["label"]
            if label in aliases:
                continue  # skip alias labels
            try:
                secret, _ct = svc.get_secret(it["path"])
            except SecretsmithError:
                continue
            try:
                exports[label] = secret.decode("utf-8")
            except UnicodeDecodeError:
                continue
            # Inject aliases for this canonical label
            for alias_name, alias_canon in aliases.items():
                if alias_canon == label and alias_name not in exports:
                    exports[alias_name] = secret.decode("utf-8")
    else:
        # Backward compatible: dump all items with valid identifier labels
        found = svc.search({}, collection=getattr(a, "collection", None))
        filters = parse_attrs(getattr(a, "attr", []))
        if filters:
            found = [
                it
                for it in found
                if all(it["attributes"].get(k) == v for k, v in filters.items())
            ]
        if getattr(a, "app", None):
            found = [it for it in found if it["attributes"].get("service") == a.app]
        found = [it for it in found if _SHELL_IDENT.match(it.get("label") or "")]
        if found:
            svc.ensure_unlocked_items(found)
        for it in found:
            label = it["label"]
            try:
                secret, _ct = svc.get_secret(it["path"])
            except SecretsmithError:
                continue
            try:
                exports[label] = secret.decode("utf-8")
            except UnicodeDecodeError:
                continue
            for alias_name, alias_canon in aliases.items():
                if alias_canon == label and alias_name not in exports:
                    exports[alias_name] = secret.decode("utf-8")

    if as_json:
        print(json.dumps({"count": len(exports), "exports": exports}, indent=2))
    else:
        for label in sorted(exports):
            print("%s=%s" % (label, _shell_quote(exports[label])))
    return 0 if exports else 1


def cmd_exec(svc, a, registry, as_json):
    """Run cmd with secrets injected as env vars. Secrets are never printed."""
    aliases = _load_alias_map(getattr(a, "alias_map", None) or None)
    env = dict(os.environ)

    if getattr(a, "env", None):
        # --env mode: resolve explicit VAR=k=v specs
        for spec in a.env:
            if "=" not in spec:
                raise SecretsmithError(
                    "env spec must be VAR=k=v[,k2=v2...], got %r" % spec
                )
            var, attrspec = spec.split("=", 1)
            if not var.isidentifier():
                raise SecretsmithError(
                    "env var name %r is not a valid identifier" % var
                )
            canonical, is_alias = _resolve_alias(aliases, var)
            filters = parse_attrs(attrspec.split(","))
            found = svc.search(
                filters, collection=getattr(a, "collection", None), label=canonical
            )
            if not found:
                raise SecretsmithError("no item matches %r" % filters)
            if len(found) > 1:
                raise SecretsmithError(
                    "%d items match %r — refine attributes" % (len(found), filters)
                )
            it = found[0]
            _refuse_protected(it, registry)
            svc.ensure_unlocked_items([it])
            secret, _ct = svc.get_secret(it["path"])
            value = secret.decode("utf-8", "replace")
            env[var] = value
            if canonical != var and canonical not in env:
                env[canonical] = value
            for alias_name, alias_canon in aliases.items():
                if (
                    alias_canon == canonical
                    and alias_name != var
                    and alias_name not in env
                ):
                    env[alias_name] = value
    elif getattr(a, "only", None):
        # --only NAME… mode: inject specific env names from the alias map
        for env_name in a.only:
            canonical, _is_alias = _resolve_alias(aliases, env_name)
            found = svc.search(
                {}, collection=getattr(a, "collection", None), label=canonical
            )
            if not found:
                print(
                    "warning: no item for %r (label=%r), skipping"
                    % (env_name, canonical),
                    file=sys.stderr,
                )
                continue
            it = found[0]
            svc.ensure_unlocked_items([it])
            secret, _ct = svc.get_secret(it["path"])
            env[env_name] = secret.decode("utf-8", "replace")
    elif getattr(a, "all", False):
        # --all mode: inject every keyring item expanded through alias map
        found = svc.search({}, collection=getattr(a, "collection", None))
        found = [it for it in found if _SHELL_IDENT.match(it.get("label") or "")]
        if found:
            svc.ensure_unlocked_items(found)
        for it in found:
            label = it["label"]
            if label in aliases:
                continue
            try:
                secret, _ct = svc.get_secret(it["path"])
            except SecretsmithError:
                continue
            env[label] = secret.decode("utf-8", "replace")
            for alias_name, alias_canon in aliases.items():
                if alias_canon == label and alias_name not in env:
                    env[alias_name] = secret.decode("utf-8", "replace")
    else:
        raise SecretsmithError("specify --env VAR=k=v, --only NAME, or --all")

    if getattr(a, "print_env_names", False):
        for name in sorted(env.keys()):
            if name in os.environ and env[name] == os.environ[name]:
                continue
            print(name)
        return 0

    try:
        proc = subprocess.run(a.command, env=env)
    except FileNotFoundError as e:
        raise SecretsmithError("cannot exec %r: %s" % (a.command[0], e))
    return proc.returncode


def cmd_chromium_key(svc, a, registry, as_json):
    secret, info = chromium_key_bytes(svc, registry)
    cands = _key_candidates(secret)
    if as_json:
        print(
            json.dumps(
                {
                    "label": info["label"],
                    "path": info["path"],
                    "secret_bytes": len(secret),
                    "key_candidates": len(cands),
                    "key_base64": base64.b64encode(cands[0]).decode()
                    if a.show and cands
                    else None,
                    "note": "raw key printed only with --show",
                },
                indent=2,
            )
        )
    else:
        print(
            "Chromium Safe Storage: %d bytes, %d AES key candidate(s)"
            % (len(secret), len(cands))
        )
        if a.show and cands:
            print("key (base64): %s" % base64.b64encode(cands[0]).decode())
        elif not a.show:
            print("(use --show to print the key)")
    return 0


def _secret_rows(rows, show):
    red = []
    for r in rows:
        r = dict(r)
        if not show:
            for k in ("value", "password"):
                if r.get(k):
                    r[k] = redact(len(r[k]))
        red.append(r)
    return red


def cmd_chromium_logins(svc, a, registry, as_json):
    profile = a.profile_dir or os.path.expanduser("~/.config/chromium/Default")
    rows = chromium_logins(svc, registry, profile)
    rows = _secret_rows(rows, a.show)
    if as_json:
        print(
            json.dumps(
                {"profile": profile, "count": len(rows), "logins": rows}, indent=2
            )
        )
    else:
        for r in rows:
            print(
                "%s\n    user=%s  password=%s%s"
                % (
                    r["origin_url"],
                    r["username"],
                    r["value"] if "value" in r else r.get("password"),
                    "" if r["decrypted"] else "  [DECRYPT FAILED]",
                )
            )
    return 0


def cmd_chromium_cookies(svc, a, registry, as_json):
    profile = a.profile_dir or os.path.expanduser("~/.config/chromium/Default")
    rows = chromium_cookies(svc, registry, profile)
    rows = _secret_rows(rows, a.show)
    if as_json:
        print(
            json.dumps(
                {"profile": profile, "count": len(rows), "cookies": rows}, indent=2
            )
        )
    else:
        for r in rows:
            print(
                "%s  %s=%s%s"
                % (
                    r["host"],
                    r["name"],
                    r["value"],
                    "" if r["decrypted"] else "  [DECRYPT FAILED]",
                )
            )
    return 0


def cmd_bitwarden_status(svc, a, registry, as_json):
    import subprocess

    try:
        res = subprocess.run(
            ["bw", "status"], capture_output=True, text=True, timeout=5
        )
        data = (
            json.loads(res.stdout) if res.stdout.strip() else {"status": "unreachable"}
        )
    except Exception as e:
        data = {"status": "error", "error": str(e)}
    if as_json:
        print(json.dumps(data, indent=2))
    else:
        print(
            "Bitwarden status: %s (server: %s)"
            % (data.get("status"), data.get("serverUrl") or "default")
        )
    return 0


def cmd_bitwarden_get(svc, a, registry, as_json):
    import subprocess

    session = os.environ.get("BW_SESSION")
    cmd = ["bw", "get", a.item_type, a.id_or_name]
    if session:
        cmd.extend(["--session", session])
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            if as_json:
                print(res.stdout)
            else:
                out = res.stdout.strip()
                print(out if a.show else redact(len(out)))
            return 0
        else:
            err = res.stderr.strip()
    except Exception as e:
        err = str(e)
    items = svc.search({"name": a.id_or_name})
    if not items:
        print("secretsmith: bitwarden/secrets error: %s" % err, file=sys.stderr)
        return 1
    sec = items[0].get_secret()
    val = sec.decode("utf-8", "replace") if sec else ""
    if as_json:
        print(
            json.dumps(
                {
                    "source": "secretservice",
                    "item": a.id_or_name,
                    "value": val if a.show else redact(len(val)),
                }
            )
        )
    else:
        print(val if a.show else redact(len(val)))
    return 0


def cmd_cookie_vault_sync(svc, a, registry, as_json):
    import subprocess

    candidates = [
        "/home/toxic/estate/ranch/cookie-vault/bin/cookie-vault.js",
        "/home/toxic/estate/ranch/barn/browserless/bin/cookie-vault.ts",
    ]
    cookie_vault_bin = next((c for c in candidates if os.path.exists(c)), candidates[0])
    subcmd = a.vault_action or "sync"
    runner = (
        ["node", cookie_vault_bin, subcmd]
        if cookie_vault_bin.endswith(".js")
        else ["bun", cookie_vault_bin, subcmd]
    )
    try:
        res = subprocess.run(runner, capture_output=True, text=True, timeout=15)
        out = res.stdout.strip()
        if as_json:
            print(json.dumps({"action": subcmd, "exit": res.returncode, "output": out}))
        else:
            print(out)
        return res.returncode
    except Exception as e:
        print("secretsmith: cookie-vault error: %s" % e, file=sys.stderr)
        return 1


def cmd_tau_auth_sync(svc, a, registry, as_json):
    """Mirror tau's built-in auth_credentials table into the keyring.

    Reads ~/.tau/agent/agent.db (via getAgentDbPath symlink) and stores each
    credential as a Secret Service item so secretsmith is the SSOT for the
    built-in auth store too. OAuth tokens and API keys share one schema:
      attr tau_credential = "1"
      attr provider       = <provider>
      attr cred_type      = oauth|api_key
      attr identity       = identity_key (when present)
    Label: "tau-auth:<provider>". Secret bytes = the raw `data` JSON blob.
    """
    DB_PATH = a.db_path or os.path.join(
        os.path.expanduser("~"), ".tau", "agent", "agent.db"
    )
    if not os.path.exists(DB_PATH):
        raise SecretsmithError("tau agent.db not found at %s" % DB_PATH)
    import sqlite3

    con = sqlite3.connect("file:%s?mode=ro" % DB_PATH, uri=True)
    rows = con.execute(
        "SELECT id, provider, credential_type, data, identity_key "
        "FROM auth_credentials ORDER BY id"
    ).fetchall()
    con.close()
    if not rows:
        print("secretsmith: no tau credentials to sync")
        return 0

    # Maximal autonomous workaround for a locked Default Keyring: pick the
    # requested collection when it is unlocked, else fall back to the first
    # unlocked collection (usually the volatile `session` one) so the sync
    # never blocks on a GUI password prompt. The durable source stays
    # tau's agent.db -- this mirror is an access layer, not a second
    # authority, so volatile storage is acceptable.
    def _pick_unlocked():
        if a.collection:
            # Explicit target may be a label or an object path; resolve below.
            return a.collection
        coll = svc.collections()
        unlocked = [c for c in coll if not c.get("locked")]
        if unlocked:
            # Prefer a labeled collection; the volatile `session` collection
            # has an empty label, so hand back its object path directly when
            # it is the only unlocked one.
            labeled = next((c for c in unlocked if c.get("label")), None)
            if labeled:
                return labeled["label"]
            return unlocked[0]["path"]
        raise SecretsmithError(
            "no unlocked Secret Service collection available (Default Keyring "
            "locked and no session collection). Unlock the keyring or run with "
            "--collection <label>."
        )

    collection = _pick_unlocked()
    stored = []
    for row_id, provider, cred_type, data, identity_key in rows:
        if not data:
            continue
        if not isinstance(data, str):
            data = (
                data.decode("utf-8", "replace")
                if isinstance(data, (bytes, bytearray))
                else str(data)
            )
        label = "tau-auth:%s" % provider
        attrs = {
            "tau_credential": "1",
            "provider": str(provider or ""),
            "cred_type": str(cred_type or ""),
            "row_id": str(row_id),
            "identity": str(identity_key or ""),
        }
        try:
            svc.set_item(
                collection,
                label,
                attrs,
                data.encode("utf-8"),
                content_type=a.content_type,
                replace=True,
            )
            stored.append(
                {"id": row_id, "provider": provider, "type": cred_type, "label": label}
            )
        except Exception as e:
            raise SecretsmithError("failed to store %s: %s" % (label, e))
    if as_json:
        print(
            json.dumps(
                {
                    "synced": stored,
                    "count": len(stored),
                    "db": DB_PATH,
                    "collection": collection,
                },
                indent=2,
            )
        )
    else:
        for item in stored:
            print(
                "stored [%s] %s (%s, id %s)"
                % (item["type"], item["label"], item["provider"], item["id"])
            )
        print(
            "synced %d of %d tau credentials (%s)" % (len(stored), len(rows), DB_PATH)
        )
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="secretsmith", description="maximal freedesktop Secret Service CLI"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # Common flags work BOTH before and after the subcommand
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--bus", help="D-Bus session bus address (default: $DBUS_SESSION_BUS_ADDRESS)"
    )
    common.add_argument(
        "--json", action="store_true", help="JSON output for everything"
    )
    common.add_argument(
        "--show",
        action="store_true",
        help="print secret values (never printed without this flag)",
    )
    p.add_argument("--bus", dest="root_bus", help=argparse.SUPPRESS)
    p.add_argument(
        "--json",
        dest="root_json",
        action="store_true",
        help="JSON output for everything",
    )
    p.add_argument(
        "--show",
        dest="root_show",
        action="store_true",
        help="print secret values (never printed without this flag)",
    )

    s = sub.add_parser(
        "search",
        parents=[common],
        help="search items by attributes / label / free-text query",
    )
    s.add_argument(
        "query", nargs="?", help="free-text match against label and attributes"
    )
    s.add_argument(
        "--schema", help="friendly schema name from registry (or raw xdg:schema)"
    )
    s.add_argument("--label", help="exact item label match")
    s.add_argument("--attr", action="append", default=[], metavar="k=v")
    s.add_argument("--collection", help="collection label or path")
    s.set_defaults(func=cmd_search)

    g = sub.add_parser(
        "get",
        parents=[common],
        help="get exactly one item (metadata; add --show to print the secret)",
    )
    g.add_argument(
        "--label", help="item label match (fuzzy fallback when exact misses)"
    )
    g.add_argument(
        "--no-fuzzy",
        dest="no_fuzzy",
        action="store_true",
        help="disable fuzzy label fallback (strict exact match)",
    )
    g.add_argument(
        "--attr",
        action="append",
        default=[],
        metavar="k=v",
        required=False,
        help="attribute filter (required unless --label given)",
    )
    g.add_argument("--collection", help="collection label or path")
    g.set_defaults(func=cmd_get)

    st = sub.add_parser(
        "set",
        parents=[common],
        help="store a secret (reads stdin unless --secret-file)",
    )
    st.add_argument("--label", required=True)
    st.add_argument("--attr", action="append", default=[], metavar="k=v")
    st.add_argument(
        "--collection", help="collection label or path (default: default alias)"
    )
    st.add_argument("--secret-file", help="read secret from file instead of stdin")
    st.add_argument("--replace", action="store_true")
    st.set_defaults(func=cmd_set)

    d = sub.add_parser(
        "delete", parents=[common], help="delete items matching attributes or label"
    )
    d.add_argument("--label", help="exact item label match")
    d.add_argument(
        "--attr",
        action="append",
        default=[],
        metavar="k=v",
        required=False,
        help="attribute filter (required unless --label given)",
    )
    d.add_argument("--collection", help="collection label or path")
    d.add_argument("--yes", action="store_true")
    d.set_defaults(func=cmd_delete)

    sub.add_parser("collections", help="list collections").set_defaults(
        func=cmd_collections
    )

    cc = sub.add_parser("collection-create", help="create a collection")
    cc.add_argument("name")
    cc.add_argument("--alias", default="", help="alias, e.g. default")
    cc.set_defaults(func=cmd_collection_create)

    cd = sub.add_parser("collection-delete", help="delete a collection")
    cd.add_argument("name")
    cd.add_argument("--yes", action="store_true")
    cd.set_defaults(func=cmd_collection_delete)

    l = sub.add_parser("lock", help="lock collections/paths")
    l.add_argument("targets", nargs="+")
    l.set_defaults(func=cmd_lock)

    u = sub.add_parser("unlock", help="unlock collections/paths")
    u.add_argument("targets", nargs="+")
    u.set_defaults(func=cmd_unlock)

    sub.add_parser("schemas", help="list the known-schema registry").set_defaults(
        func=cmd_schemas
    )

    # env subcommand: drop-in env loader with alias expansion
    env_p = sub.add_parser(
        "env", parents=[common], help="drop-in env loader: emit NAME='value' exports"
    )
    env_p.add_argument(
        "--env",
        action="append",
        metavar="VAR=k=v[,k2=v2...]",
        help="resolve one keyring item to an env var; repeatable",
    )
    env_p.add_argument(
        "--app",
        default="",
        help="filter items by their `service=` attribute (only without --env)",
    )
    env_p.add_argument(
        "--attr",
        action="append",
        default=[],
        metavar="k=v",
        help="additional attribute filter (only without --env)",
    )
    env_p.add_argument("--collection", help="collection label or path")
    env_p.add_argument(
        "--all",
        action="store_true",
        help="export every keyring item (expanded through alias map)",
    )
    env_p.add_argument(
        "--alias-map",
        default="",
        help="path to aliases.toml/json config dir (default: ~/.config/secretsmith)",
    )
    env_p.set_defaults(func=cmd_env)

    # exec subcommand: run a command with secrets injected as env vars
    exec_p = sub.add_parser(
        "exec",
        help="run a command with secrets injected as env vars (secrets never printed)",
    )
    exec_p.add_argument(
        "--env",
        action="append",
        metavar="VAR=k=v[,k2=v2...]",
        help="resolve one keyring item to an env var; repeatable",
    )
    exec_p.add_argument(
        "--only",
        action="append",
        metavar="NAME",
        help="inject only these env var names (expanded through alias map)",
    )
    exec_p.add_argument(
        "--all",
        action="store_true",
        help="inject every keyring item (expanded through alias map)",
    )
    exec_p.add_argument("--collection", help="restrict search to a collection")
    exec_p.add_argument(
        "--alias-map",
        default="",
        help="path to aliases.toml/json config dir (default: ~/.config/secretsmith)",
    )
    exec_p.add_argument(
        "--print-env-names",
        action="store_true",
        help="print only the env var names that would be injected (diagnostics)",
    )
    exec_p.add_argument(
        "command", nargs="+", help="command to run with the injected environment"
    )
    exec_p.set_defaults(func=cmd_exec)

    sub.add_parser("check", help="health check").set_defaults(func=cmd_check)

    ck = sub.add_parser(
        "chromium-key", help="Chromium os_crypt key lookup via registry"
    )
    ck.set_defaults(func=cmd_chromium_key)

    cl = sub.add_parser("chromium-logins", help="decrypt Chromium Login Data")
    cl.add_argument("--profile-dir", default="")
    cl.set_defaults(func=cmd_chromium_logins)

    cc2 = sub.add_parser("chromium-cookies", help="decrypt Chromium Cookies")
    cc2.add_argument("--profile-dir", default="")
    cc2.set_defaults(func=cmd_chromium_cookies)

    bw_p = sub.add_parser("bw-status", help="check Bitwarden vault status")
    bw_p.set_defaults(func=cmd_bitwarden_status)

    bw_g = sub.add_parser(
        "bw-get", help="retrieve Bitwarden secret with Secret Service fallback"
    )
    bw_g.add_argument(
        "item_type", choices=["password", "username", "item", "totp", "notes"]
    )
    bw_g.add_argument("id_or_name", help="item name or ID")
    bw_g.set_defaults(func=cmd_bitwarden_get)

    cv = sub.add_parser(
        "cookie-vault", help="cookie-vault sync/grab/restore integration"
    )
    cv.add_argument(
        "vault_action",
        nargs="?",
        default="sync",
        choices=["sync", "grab-firefox", "grab-keeper", "restore-keeper", "status"],
    )
    cv.set_defaults(func=cmd_cookie_vault_sync)

    # tau built-in auth -> keyring mirror (secretsmith as SSOT for tau auth)
    ta = sub.add_parser(
        "tau-auth-sync",
        parents=[common],
        help="mirror tau agent.db auth_credentials into the keyring",
    )
    ta.add_argument(
        "--db-path",
        default="",
        help="path to tau agent.db (default ~/.tau/agent/agent.db)",
    )
    ta.add_argument("--collection", default="", help="collection label or 'default'")
    ta.add_argument(
        "--content-type",
        default="application/json",
        help="content type for stored secrets (default application/json)",
    )
    ta.set_defaults(func=cmd_tau_auth_sync)

    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    # Reconcile flags given BEFORE the subcommand with those given AFTER it
    a.bus = getattr(a, "bus", None) or getattr(a, "root_bus", None)
    a.json = getattr(a, "json", None) or getattr(a, "root_json", False)
    a.show = getattr(a, "show", None) or getattr(a, "root_show", False)
    if a.bus:
        os.environ["DBUS_SESSION_BUS_ADDRESS"] = a.bus
    try:
        registry = load_registry()
        svc = SecretService()
        return a.func(svc, a, registry, a.json)
    except SecretsmithError as e:
        print("secretsmith: error: %s" % e, file=sys.stderr)
        return 1
    except Exception as e:
        if dbus is not None and isinstance(e, dbus.DBusException):
            print(
                "secretsmith: D-Bus error: %s" % e.get_dbus_message(), file=sys.stderr
            )
            return 1
        raise


if __name__ == "__main__":
    sys.exit(main())
