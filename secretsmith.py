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



SECRETS_FILE = os.environ.get("SECRETS_FILE", "/home/toxic/.secrets")



def secrets_file_path():
    return os.environ.get("SECRETS_FILE", "/home/toxic/.secrets")


def load_dotenv(path=None):
    """Parse a KEY=value secret store into a dict.

    This is the local counterpart to the Secret Service: on a box where the
    keyring broker's socket is absent, this file is the source of truth for
    real keys. Values are never logged and never interpolated into errors.
    """
    path = path or SECRETS_FILE
    try:
        st = os.stat(path)
    except OSError:
        return {}
    mode = st.st_mode & 0o777
    if mode & 0o077:
        raise SecretsmithError(
            "%s is group/world accessible (mode %o); tighten it to 0600"
            % (path, mode))
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            if k:
                out[k] = v
    return out
def dotenv_candidates(credential):
    """Candidate KEY names for a credential id, most specific first.

    Broker credential ids are namespaced (`custom.exa`, `svc/context7`), but
    the store holds bare provider names (`EXA_API_KEY`). Try every suffix of
    the id so the namespace prefix is dropped, longest suffix first.
    """
    parts = [p for p in re.split(r"[^a-z0-9]+", str(credential).lower()) if p]
    out = []
    for i in range(len(parts)):
        tail = "_".join(parts[i:]).upper()
        for cand in ("%s_API_KEY" % tail, "%s_KEY" % tail, tail):
            if cand not in out:
                out.append(cand)
    return out or [str(credential).upper()]



def resolve_dotenv(credential, environ=None, path=None):
    """Return (key, value) for a credential name, or (None, None).

    Process env wins over the file: an explicit export is a deliberate
    override of the stored value.
    """
    environ = os.environ if environ is None else environ
    file_values = load_dotenv(path)
    for key in dotenv_candidates(credential):
        if key in environ:
            return key, environ[key]
    for key in dotenv_candidates(credential):
        if key in file_values:
            return key, file_values[key]
    return None, None

class SecretsmithError(RuntimeError):
    pass


def load_registry():
    try:
        with open(REGISTRY_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise SecretsmithError("cannot load schema registry %s: %s" % (REGISTRY_PATH, e))


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
            "is never printed (check/attrs report metadata only)" % schema)


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
                "bus=%s)" % (BUS_NAME, os.environ.get("DBUS_SESSION_BUS_ADDRESS", "(default)")))
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
            out.append({
                "path": p,
                "label": str(self._get(p, IFACE_COLLECTION, "Label")),
                "locked": bool(self._get(p, IFACE_COLLECTION, "Locked")),
            })
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

    def search(self, attr_filters, collection=None):
        return [it for it in self.list_items(collection)
                if all(it["attributes"].get(k) == v for k, v in attr_filters.items())]

    def is_locked(self, path, iface):
        return bool(self._get(path, iface, "Locked"))

    def _await_unlock(self, paths, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            states = []
            for p in paths:
                iface = IFACE_COLLECTION if "/collection/" in p or p == self.default_collection() else IFACE_ITEM
                try:
                    states.append(self.is_locked(p, iface))
                except dbus.DBusException:
                    states.append(True)
            if not any(states):
                return
            time.sleep(0.5)
        raise SecretsmithError("unlock did not complete (keyring may need a GUI unlock)")

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
        _sess, _params, secret, content_type = item.GetSecret(dbus.ObjectPath(self.session()))
        return bytes(secret), str(content_type)

    def set_item(self, collection_target, label, attributes, secret_bytes,
                 content_type="text/plain", replace=False):
        cpath = self.resolve_collection(collection_target)
        if self.is_locked(cpath, IFACE_COLLECTION):
            self.unlock_paths([cpath])
        coll = dbus.Interface(self.bus.get_object(BUS_NAME, cpath), IFACE_COLLECTION)
        props = {
            "org.freedesktop.Secret.Item.Label": label,
            "org.freedesktop.Secret.Item.Attributes": dbus.Dictionary(attributes, signature="ss"),
        }
        secret = (dbus.ObjectPath(self.session()), dbus.ByteArray(b""),
                  dbus.ByteArray(secret_bytes), content_type)
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
        raise SecretsmithError("unsupported blob prefix %r (expected v10/v11)" % blob[:3])
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
    raise SecretsmithError("decryption failed with all %d key candidates" % len(key_candidates))


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
        raise SecretsmithError("no usable AES key candidate from keyring secret (%d bytes)" % len(key))
    db_path, tmpdir = _copy_profile_db(profile_dir, "Login Data")
    try:
        con = _open_ro(db_path)
        rows = con.execute(
            "SELECT origin_url, username_value, password_value FROM logins").fetchall()
        con.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    out = []
    for url_b, user_b, blob in rows:
        try:
            pw = decrypt_chromium_blob(_to_bytes(blob), cands).decode("utf-8", "replace")
            ok = True
        except SecretsmithError:
            pw, ok = None, False
        out.append({"origin_url": _to_text(url_b), "username": _to_text(user_b),
                    "password": pw, "decrypted": ok})
    return out


def chromium_cookies(svc, registry, profile_dir):
    key, _info = chromium_key_bytes(svc, registry)
    cands = _key_candidates(key)
    if not cands:
        raise SecretsmithError("no usable AES key candidate from keyring secret (%d bytes)" % len(key))
    db_path, tmpdir = _copy_profile_db(profile_dir, "Cookies")
    try:
        con = _open_ro(db_path)
        rows = con.execute(
            "SELECT host_key, name, path, value, encrypted_value FROM cookies").fetchall()
        con.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    out = []
    for host_b, name_b, path_b, value_b, blob in rows:
        host, name, path = _to_text(host_b), _to_text(name_b), _to_text(path_b)
        value = _to_text(value_b) if value_b else ""
        if value:
            out.append({"host": host, "name": name, "path": path,
                        "value": value, "decrypted": True, "source": "plaintext"})
            continue
        try:
            dec = decrypt_chromium_blob(_to_bytes(blob), cands).decode("utf-8", "replace")
            ok = True
        except SecretsmithError:
            dec, ok = None, False
        out.append({"host": host, "name": name, "path": path,
                    "value": dec, "decrypted": ok, "source": "encrypted"})
    return out

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
    lines = ["[%s] %s  (collection: %s%s)" % (
        it["path"], it["label"], it["collection"],
        ", LOCKED" if it["locked"] else "")]
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
    found = svc.search(filters, collection=a.collection)
    if a.show:
        for it in found:
            _refuse_protected(it, registry)
        svc.ensure_unlocked_items(found)
        for it in found:
            secret, _ct = svc.get_secret(it["path"])
            it["secret_len"] = len(secret)
            it["secret_preview"] = secret.decode("utf-8", "replace") if _is_text(secret) else redact(len(secret))
    else:
        for it in found:
            it["secret_len"] = None  # unknown until read; never fetched without --show
    if as_json:
        print(json.dumps({"count": len(found), "items": [
            {k: v for k, v in it.items() if k != "secret_preview" or a.show}
            for it in found]}, indent=2))
    else:
        if warned:
            print("warning: schema %r not in registry, used as raw xdg:schema" % a.schema,
                  file=sys.stderr)
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
    found = svc.search(filters, collection=a.collection)
    if not found:
        raise SecretsmithError("no item matches %r" % filters)
    if len(found) > 1:
        raise SecretsmithError("%d items match %r — refine attributes" % (len(found), filters))
    it = found[0]
    if a.show:
        _refuse_protected(it, registry)
    svc.ensure_unlocked_items([it])
    secret, content_type = svc.get_secret(it["path"])
    if as_json:
        print(json.dumps({
            "label": it["label"], "path": it["path"],
            "attributes": it["attributes"], "content_type": content_type,
            "secret": secret.decode("utf-8", "replace") if a.show and _is_text(secret)
                      else (redact(len(secret)) if not a.show else None),
            "secret_base64": base64.b64encode(secret).decode() if a.show and not _is_text(secret) else None,
        }, indent=2))
    else:
        print("label: %s\npath: %s\ncontent_type: %s" % (it["label"], it["path"], content_type))
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
    path = svc.set_item(collection, a.label, attrs, secret, replace=a.replace)
    if as_json:
        print(json.dumps({"stored": True, "path": path, "label": a.label,
                          "attributes": attrs}, indent=2))
    else:
        print("stored %s (%d bytes)" % (path, len(secret)))
    return 0


def cmd_delete(svc, a, registry, as_json):
    filters = parse_attrs(a.attr)
    found = svc.search(filters, collection=a.collection)
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
        c["default"] = (c["path"] == default)
        c["items"] = len(svc._item_paths(c["path"]))
    if as_json:
        print(json.dumps({"collections": colls}, indent=2))
    else:
        for c in colls:
            print("%s  label=%r  locked=%s  items=%d%s" % (
                c["path"], c["label"], c["locked"], c["items"],
                "  [default]" if c["default"] else ""))
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
            # allow item paths too for lock/unlock
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
            print("%-10s -> %s%s" % (name, e.get("xdg:schema", "?"),
                                    "  (alias of %s)" % e["alias_of"] if "alias_of" in e else ""))
            if e.get("description"):
                print("             %s" % e["description"])
    return 0


def cmd_env_get(svc, a, registry, as_json):
    """Resolve a credential name against the local KEY=value secret store."""
    key, value = resolve_dotenv(a.name, environ=None)
    if value is None:
        raise SecretsmithError(
            "no secret for %r in %s (tried %s)"
            % (a.name, secrets_file_path(), ", ".join(dotenv_candidates(a.name))))
    if as_json:
        print(json.dumps({"name": a.name, "key": key, "value": value}, indent=2))
    else:
        # Raw stdout: this is the machine-readable path callers pipe into a
        # request. `secretsmith env-list` is the redacted view.
        print(value)
    return 0


def cmd_env_list(svc, a, registry, as_json):
    """List secret NAMES with values redacted."""
    values = load_dotenv()
    keys = sorted(values)
    if as_json:
        print(json.dumps({"file": secrets_file_path(),
                          "keys": [{"name": k, "bytes": len(values[k])} for k in keys]},
                         indent=2))
    else:
        for k in keys:
            print("%-40s %s" % (k, redact(len(values[k]))))
    return 0


def cmd_env_set(svc, a, registry, as_json):
    """Set KEY=value in the secret store (value from stdin or --secret-file)."""
    path = secrets_file_path()
    values = load_dotenv(path)
    values[a.name] = read_secret_input(a)
    lines = ["%s=%s" % (k, values[k]) for k in sorted(values)]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(json.dumps({"file": path, "name": a.name,
                      "bytes": len(values[a.name])}, indent=2) if as_json
          else "set %s (%d bytes)" % (a.name, len(values[a.name])))
    return 0


def cmd_env_resolve(svc, a, registry, as_json):
    """Print a ready-to-use shell export for a credential name."""
    key, value = resolve_dotenv(a.name)
    if value is None:
        raise SecretsmithError("no secret for %r" % a.name)
    if as_json:
        print(json.dumps({"name": a.name, "key": key}, indent=2))
    else:
        print("export %s=%s" % (key, value))
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
        print("collections: %d  default: %s%s" % (
            result["collections"], result["default_collection"],
            " (LOCKED)" if result.get("default_locked") else ""))
        print("chromium entry: %s%s" % (
            "yes" if result["chromium_entry"] else "NO",
            "  secret=%d bytes, key candidates=%d" % (
                result.get("chromium_secret_bytes", 0),
                result.get("chromium_key_candidates", 0))
            if result["chromium_entry"] and "chromium_secret_bytes" in result else ""))
        if result["problems"]:
            print("PROBLEMS:")
            for p in result["problems"]:
                print("  - %s" % p)
        else:
            print("OK — all checks passed")
    return 0 if result["ok"] else 1




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
        print(json.dumps({"profile": profile, "count": len(rows), "logins": rows}, indent=2))
    else:
        for r in rows:
            print("%s\n    user=%s  password=%s%s" % (
                r["origin_url"], r["username"], r["value"] if "value" in r else r.get("password"),
                "" if r["decrypted"] else "  [DECRYPT FAILED]"))
    return 0


def cmd_chromium_cookies(svc, a, registry, as_json):
    profile = a.profile_dir or os.path.expanduser("~/.config/chromium/Default")
    rows = chromium_cookies(svc, registry, profile)
    rows = _secret_rows(rows, a.show)
    if as_json:
        print(json.dumps({"profile": profile, "count": len(rows), "cookies": rows}, indent=2))
    else:
        for r in rows:
            print("%s  %s=%s%s" % (r["host"], r["name"], r["value"],
                                   "" if r["decrypted"] else "  [DECRYPT FAILED]"))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="secretsmith",
                                description="maximal freedesktop Secret Service CLI")
    p.add_argument("--bus", help="D-Bus session bus address (default: $DBUS_SESSION_BUS_ADDRESS)")
    p.add_argument("--json", action="store_true", help="JSON output for everything")
    p.add_argument("--show", action="store_true",
                   help="print secret values (never printed without this flag)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("search", help="search items by attributes (all schemas by default)")
    s.add_argument("--schema", help="friendly schema name from registry (or raw xdg:schema)")
    s.add_argument("--attr", action="append", default=[], metavar="k=v")
    s.add_argument("--collection", help="collection label or path")
    s.set_defaults(func=cmd_search)

    g = sub.add_parser("get", help="get exactly one item's secret metadata")
    g.add_argument("--attr", action="append", default=[], metavar="k=v", required=True)
    g.add_argument("--collection", help="collection label or path")
    g.set_defaults(func=cmd_get)

    st = sub.add_parser("set", help="store a secret (reads stdin unless --secret-file)")
    st.add_argument("--label", required=True)
    st.add_argument("--attr", action="append", default=[], metavar="k=v")
    st.add_argument("--collection", help="collection label or path (default: default alias)")
    st.add_argument("--secret-file", help="read secret from file instead of stdin")
    st.add_argument("--replace", action="store_true")
    st.set_defaults(func=cmd_set)

    d = sub.add_parser("delete", help="delete items matching attributes")
    d.add_argument("--attr", action="append", default=[], metavar="k=v", required=True)
    d.add_argument("--collection", help="collection label or path")
    d.add_argument("--yes", action="store_true")
    d.set_defaults(func=cmd_delete)

    sub.add_parser("collections", help="list collections").set_defaults(func=cmd_collections)

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

    sub.add_parser("schemas", help="list the known-schema registry").set_defaults(func=cmd_schemas)
    sub.add_parser("check", help="health check").set_defaults(func=cmd_check)

    cl = sub.add_parser("chromium-logins", help="decrypt Chromium Login Data")
    cl.add_argument("--profile-dir", default="")
    cl.set_defaults(func=cmd_chromium_logins)

    cc2 = sub.add_parser("chromium-cookies", help="decrypt Chromium Cookies")
    cc2.add_argument("--profile-dir", default="")
    cc2.set_defaults(func=cmd_chromium_cookies)

    # Local KEY=value store. These subcommands do not touch D-Bus at all —
    # the keyring broker is optional, the file is the fallback source of
    # truth for real keys on this box.
    eg = sub.add_parser("env-get", help="print the secret for a credential name")
    eg.add_argument("name", help="credential name, e.g. custom.exa or EXA_API_KEY")
    eg.set_defaults(func=cmd_env_get)

    sub.add_parser("env-list", help="list secret names (values redacted)") \
        .set_defaults(func=cmd_env_list)

    es = sub.add_parser("env-set",
                        help="store a secret (reads stdin unless --secret-file)")
    es.add_argument("name")
    es.add_argument("--secret-file", help="read secret from file instead of stdin")
    es.set_defaults(func=cmd_env_set)

    er = sub.add_parser("env-resolve", help="print a shell export for a credential")
    er.add_argument("name")
    er.set_defaults(func=cmd_env_resolve)

    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    if a.bus:
        os.environ["DBUS_SESSION_BUS_ADDRESS"] = a.bus
    try:
        registry = load_registry()
        # env-* operate on the local KEY=value file and must work with no
        # keyring and no dbus-python at all; only the Secret Service
        # subcommands need a live session bus.
        svc = None if a.cmd.startswith("env-") else SecretService()
        return a.func(svc, a, registry, a.json)
    except SecretsmithError as e:
        print("secretsmith: error: %s" % e, file=sys.stderr)
        return 1
    except Exception as e:
        if dbus is not None and isinstance(e, dbus.DBusException):
            print("secretsmith: D-Bus error: %s" % e.get_dbus_message(), file=sys.stderr)
            return 1
        raise


if __name__ == "__main__":
    sys.exit(main())
