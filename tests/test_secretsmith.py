#!/usr/bin/env python3
"""secretsmith tests: unit tests always run; keyring integration runs live
when SSM_TEST_KEYRING=1 (uses a throwaway collection, cleans up after itself)."""

import base64
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

import secretsmith as ssm


class TestRegistry(unittest.TestCase):
    def test_registry_loads(self):
        reg = ssm.load_registry()
        self.assertIn("chromium", reg["schemas"])

    def test_chromium_resolves(self):
        reg = ssm.load_registry()
        schema, entry = ssm.resolve_schema("chromium", reg)
        self.assertEqual(schema, "chrome_libsecret_os_crypt_password_v2")
        self.assertTrue(entry["secret_is_key"])

    def test_chrome_alias(self):
        reg = ssm.load_registry()
        schema, _ = ssm.resolve_schema("chrome", reg)
        self.assertEqual(schema, "chrome_libsecret_os_crypt_password_v2")

    def test_generic_is_not_chromium(self):
        reg = ssm.load_registry()
        schema, _ = ssm.resolve_schema("generic", reg)
        self.assertNotEqual(schema, "chrome_libsecret_os_crypt_password_v2")

    def test_raw_passthrough(self):
        reg = ssm.load_registry()
        schema, entry = ssm.resolve_schema("com.example.Custom", reg)
        self.assertEqual(schema, "com.example.Custom")
        self.assertIn("unregistered", entry["description"])


class TestChromiumCrypto(unittest.TestCase):
    def _blob(self, key, pt):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        pad = 16 - len(pt) % 16
        pt = pt + bytes([pad]) * pad
        d = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).encryptor()
        return b"v10" + d.update(pt) + d.finalize()

    def test_roundtrip_raw_key(self):
        key = os.urandom(16)
        blob = self._blob(key, b"hunter2")
        self.assertEqual(ssm.decrypt_chromium_blob(blob, [key]), b"hunter2")

    def test_roundtrip_b64_key(self):
        key = os.urandom(16)
        stored = base64.b64encode(key)  # 24 chars, like the real keyring entry
        self.assertEqual(len(stored), 24)
        blob = self._blob(key, b"correct horse")
        cands = ssm._key_candidates(stored)
        self.assertIn(key, cands)
        self.assertEqual(ssm.decrypt_chromium_blob(blob, cands), b"correct horse")

    def test_wrong_key_fails(self):
        blob = self._blob(os.urandom(16), b"nope")
        with self.assertRaises(ssm.SecretsmithError):
            ssm.decrypt_chromium_blob(blob, [os.urandom(16)])

    def test_bad_prefix_fails(self):
        with self.assertRaises(ssm.SecretsmithError):
            ssm.decrypt_chromium_blob(b"v99" + b"x" * 32, [os.urandom(16)])


class TestSafety(unittest.TestCase):
    def test_redact_format(self):
        self.assertEqual(ssm.redact(24), "<redacted: 24 bytes>")

    def test_parse_attrs(self):
        self.assertEqual(ssm.parse_attrs(["a=1", "b=x=y"]), {"a": "1", "b": "x=y"})

    def test_parse_attrs_rejects_bare(self):
        with self.assertRaises(ssm.SecretsmithError):
            ssm.parse_attrs(["bare"])


class TestKeyringIntegration(unittest.TestCase):
    """Live D-Bus integration against the real (unlocked) login collection.
    Gated on SSM_TEST_KEYRING=1. Uses a uniquely-named item, deletes it after.
    Collection create/delete needs a GUI password prompt — covered only with
    SSM_TEST_COLLECTIONS=1 on an interactive session."""

    @classmethod
    def setUpClass(cls):
        if os.environ.get("SSM_TEST_KEYRING") != "1":
            raise unittest.SkipTest("set SSM_TEST_KEYRING=1 to run live keyring tests")
        cls.svc = ssm.SecretService()
        cls.reg = ssm.load_registry()
        cls.coll = cls.svc.default_collection() or cls.svc.collections()[0]["path"]
        cls.test_id = "ssm-test-%d" % os.getpid()

    def test_set_get_search_delete(self):
        p = self.svc.set_item(self.coll, "secretsmith test item",
                              {"xdg:schema": "org.freedesktop.Secret.Generic",
                               "test-id": self.test_id},
                              b"s3cr3t-value", replace=True)
        self.assertTrue(p.startswith("/"))
        try:
            found = self.svc.search({"test-id": self.test_id})
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["label"], "secretsmith test item")
            secret, _ct = self.svc.get_secret(found[0]["path"])
            self.assertEqual(secret, b"s3cr3t-value")
        finally:
            for it in self.svc.search({"test-id": self.test_id}):
                self.svc.delete_item(it["path"])
        self.assertEqual(self.svc.search({"test-id": self.test_id}), [])

    def test_chromium_entry_visible(self):
        schema, _ = ssm.resolve_schema("chromium", self.reg)
        found = self.svc.search({"xdg:schema": schema})
        # the estate's Chromium Safe Storage entry must be findable via registry
        self.assertTrue(found, "Chromium Safe Storage entry not found via registry")

    def test_collection_create_delete(self):
        if os.environ.get("SSM_TEST_COLLECTIONS") != "1":
            raise unittest.SkipTest("needs GUI keyring password prompt")
        name = "secretsmith-test-%d" % os.getpid()
        path = self.svc.create_collection(name)
        self.assertTrue(path.startswith("/"))
        self.svc.delete_collection(name)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestDisplayProtection(unittest.TestCase):
    """os_crypt key material (secret_is_key schemas) is never printable."""

    def _reg(self):
        return ssm.load_registry()

    def _chromium_schema(self):
        reg = self._reg()
        schema, _ = ssm.resolve_schema("chromium", reg)
        return schema

    def test_protected_schemas_contains_chromium(self):
        self.assertIn(self._chromium_schema(), ssm.protected_schemas(self._reg()))

    def test_generic_not_protected(self):
        reg = self._reg()
        schema, _ = ssm.resolve_schema("generic", reg)
        self.assertNotIn(schema, ssm.protected_schemas(reg))

    def _fake_svc(self, schema):
        item = {"path": "/org/freedesktop/secrets/item/1",
                "label": "Chromium Safe Storage",
                "attributes": {"xdg:schema": schema, "application": "chromium"},
                "collection": "/org/freedesktop/secrets/aliases/default",
                "locked": False}

        class FakeSvc:
            def __init__(self):
                self.secret_calls = []

            def search(self, filters, collection=None):
                return [item]

            def ensure_unlocked_items(self, items):
                pass

            def get_secret(self, path):
                self.secret_calls.append(path)
                return (b"raw-key-bytes", "text/plain")

        return FakeSvc()

    def _args(self, show):
        import argparse
        return argparse.Namespace(attr=[], collection=None, show=show, schema=None)

    def test_get_show_refuses_chromium(self):
        reg = self._reg()
        svc = self._fake_svc(self._chromium_schema())
        with self.assertRaises(ssm.SecretsmithError):
            ssm.cmd_get(svc, self._args(True), reg, False)
        self.assertEqual(svc.secret_calls, [])  # refused BEFORE any fetch

    def test_get_noshow_ok_chromium(self):
        reg = self._reg()
        svc = self._fake_svc(self._chromium_schema())
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = ssm.cmd_get(svc, self._args(False), reg, False)
        self.assertEqual(rc, 0)
        self.assertIn("<redacted", buf.getvalue())

    def test_search_show_refuses_chromium(self):
        reg = self._reg()
        svc = self._fake_svc(self._chromium_schema())
        with self.assertRaises(ssm.SecretsmithError):
            ssm.cmd_search(svc, self._args(True), reg, False)
        self.assertEqual(svc.secret_calls, [])

    def test_get_show_ok_for_generic(self):
        reg = self._reg()
        schema, _ = ssm.resolve_schema("generic", reg)
        svc = self._fake_svc(schema)
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = ssm.cmd_get(svc, self._args(True), reg, False)
        self.assertEqual(rc, 0)
        self.assertEqual(len(svc.secret_calls), 1)

class TestDotenv(unittest.TestCase):
    """The local KEY=value store: parsing, name resolution, permissions."""

    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp(prefix="secretsmith-test-")
        self.path = os.path.join(self.dir, ".secrets")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, text, mode=0o600):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(self.path, mode)

    def test_parses_values_and_skips_noise(self):
        self._write("# comment\n\nEXA_API_KEY=abc123\nQUOTED=\"q v\"\n")
        values = ssm.load_dotenv(self.path)
        self.assertEqual(values["EXA_API_KEY"], "abc123")
        self.assertEqual(values["QUOTED"], "q v")

    def test_keeps_equals_inside_value(self):
        self._write("TOKEN=a=b=c\n")
        self.assertEqual(ssm.load_dotenv(self.path)["TOKEN"], "a=b=c")

    def test_missing_file_is_empty_not_an_error(self):
        self.assertEqual(ssm.load_dotenv(os.path.join(self.dir, "nope")), {})

    def test_refuses_group_readable_store(self):
        self._write("EXA_API_KEY=x\n", mode=0o644)
        with self.assertRaises(ssm.SecretsmithError):
            ssm.load_dotenv(self.path)

    def test_resolves_namespaced_credential(self):
        self._write("EXA_API_KEY=realkey\n")
        key, value = ssm.resolve_dotenv("custom.exa", environ={},
                                        path=self.path)
        self.assertEqual((key, value), ("EXA_API_KEY", "realkey"))

    def test_process_env_overrides_the_file(self):
        self._write("EXA_API_KEY=from-file\n")
        key, value = ssm.resolve_dotenv("custom.exa",
                                        environ={"EXA_API_KEY": "from-env"},
                                        path=self.path)
        self.assertEqual(value, "from-env")

    def test_unknown_credential_returns_none(self):
        self._write("EXA_API_KEY=x\n")
        self.assertEqual(
            ssm.resolve_dotenv("nope.missing", environ={}, path=self.path),
            (None, None))
