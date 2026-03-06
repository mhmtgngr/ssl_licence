"""Tests for safe I/O utilities."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from sslcert.utils.safe_io import (
    atomic_write_json,
    validate_port,
    validate_hostname,
)


class TestAtomicWriteJson(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = Path(self.tmpdir) / "test.json"

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()
        os.rmdir(self.tmpdir)

    def test_writes_valid_json(self):
        data = {"key": "value", "number": 42}
        atomic_write_json(self.path, data)
        loaded = json.loads(self.path.read_text())
        self.assertEqual(loaded, data)

    def test_writes_list(self):
        data = [1, 2, 3]
        atomic_write_json(self.path, data)
        loaded = json.loads(self.path.read_text())
        self.assertEqual(loaded, data)

    def test_overwrites_existing(self):
        self.path.write_text('{"old": true}')
        atomic_write_json(self.path, {"new": True})
        loaded = json.loads(self.path.read_text())
        self.assertEqual(loaded, {"new": True})

    def test_no_temp_files_left(self):
        atomic_write_json(self.path, {"test": 1})
        files = list(Path(self.tmpdir).glob(".*"))
        self.assertEqual(len(files), 0)

    def test_creates_parent_dirs(self):
        nested = Path(self.tmpdir) / "a" / "b" / "c" / "test.json"
        atomic_write_json(nested, {"nested": True})
        self.assertTrue(nested.exists())
        loaded = json.loads(nested.read_text())
        self.assertEqual(loaded, {"nested": True})
        # Cleanup
        nested.unlink()
        nested.parent.rmdir()
        nested.parent.parent.rmdir()
        nested.parent.parent.parent.rmdir()


class TestValidatePort(unittest.TestCase):

    def test_valid_port(self):
        self.assertEqual(validate_port(443), 443)
        self.assertEqual(validate_port(8443), 8443)
        self.assertEqual(validate_port(1), 1)
        self.assertEqual(validate_port(65535), 65535)

    def test_string_port(self):
        self.assertEqual(validate_port("993"), 993)

    def test_invalid_port_returns_default(self):
        self.assertEqual(validate_port(0), 443)
        self.assertEqual(validate_port(-1), 443)
        self.assertEqual(validate_port(65536), 443)
        self.assertEqual(validate_port("abc"), 443)
        self.assertEqual(validate_port(None), 443)
        self.assertEqual(validate_port(""), 443)

    def test_custom_default(self):
        self.assertEqual(validate_port("bad", default=8443), 8443)


class TestValidateHostname(unittest.TestCase):

    def test_valid_hostnames(self):
        self.assertTrue(validate_hostname("example.com"))
        self.assertTrue(validate_hostname("sub.example.com"))
        self.assertTrue(validate_hostname("a.b.c.example.com"))
        self.assertTrue(validate_hostname("example.co.uk"))

    def test_valid_wildcard(self):
        self.assertTrue(validate_hostname("*.example.com"))

    def test_invalid_hostnames(self):
        self.assertFalse(validate_hostname(""))
        self.assertFalse(validate_hostname(" "))
        self.assertFalse(validate_hostname("a" * 254))
        self.assertFalse(validate_hostname("-invalid.com"))
        self.assertFalse(validate_hostname("invalid-.com"))

    def test_ip_not_hostname(self):
        # IPs are not valid hostnames for our purpose
        self.assertFalse(validate_hostname("192.168.1.1"))


if __name__ == "__main__":
    unittest.main()
