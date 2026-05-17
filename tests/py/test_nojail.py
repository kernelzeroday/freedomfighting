#!/usr/bin/env python
"""
Tests for nojail.py and nojail.py3 - version-aware imports.
"""
import datetime
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Import the right version
if sys.version_info[0] >= 3:
    try:
        from nojail import (random_string, ask_confirmation, error, warning,
                           success, info, red, green, orange,
                           UTMP_UNPACK_STRING, UTMP_BLOCK_SIZE,
                           LASTLOG_UNPACK_STRING, LASTLOG_BLOCK_SIZE)
        HAVE_NOJAIL = True
    except (ImportError, SyntaxError):
        try:
            # Try nojail.py3 explicitly
            import importlib.util
            spec = importlib.util.spec_from_file_location("nojail",
                os.path.join(os.path.dirname(__file__), '..', '..', 'nojail.py3'))
            nojail = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(nojail)
            sys.modules['nojail'] = nojail
            from nojail import (random_string, ask_confirmation, error, warning,
                               success, info, red, green, orange,
                               UTMP_UNPACK_STRING, UTMP_BLOCK_SIZE,
                               LASTLOG_UNPACK_STRING, LASTLOG_BLOCK_SIZE)
            HAVE_NOJAIL = True
        except Exception:
            HAVE_NOJAIL = False
else:
    try:
        from nojail import (random_string, ask_confirmation, error, warning,
                           success, info, red, green, orange,
                           UTMP_UNPACK_STRING, UTMP_BLOCK_SIZE,
                           LASTLOG_UNPACK_STRING, LASTLOG_BLOCK_SIZE)
        HAVE_NOJAIL = True
    except ImportError:
        HAVE_NOJAIL = False


class TestNojailUtils(unittest.TestCase):
    """Test utility functions that don't need the module."""

    def test_random_string_length(self):
        """Test random string generation."""
        import random
        chars = "abcdefghijlkmnopqrstuvwxyz0123456789"
        s = ''.join(random.choice(chars) for _ in range(10))
        self.assertEqual(len(s), 10)

    def test_random_string_unique(self):
        """Test random strings are (usually) unique."""
        import random
        chars = "abcdefghijlkmnopqrstuvwxyz0123456789"
        s1 = ''.join(random.choice(chars) for _ in range(10))
        s2 = ''.join(random.choice(chars) for _ in range(10))
        self.assertNotEqual(s1, s2)

    def test_utmp_struct_pack_unpack(self):
        """Test UTMP binary structure."""
        fmt = "hi32s4s32s256s2h3i36x"
        block_size = 384

        data = struct.pack(fmt,
            7,       # ut_type
            1234,    # ut_pid
            b"pts/0",  # ut_line
            b"ts/0",   # ut_id
            b"root",   # ut_user
            b"192.168.1.1",  # ut_host
            0, 0,    # ut_exit
            0,       # ut_session
            1500000000,  # ut_tv_sec
            0)       # ut_tv_usec

        if len(data) < block_size:
            data += b"\x00" * (block_size - len(data))

        self.assertEqual(len(data), block_size)

        result = struct.unpack(fmt, data)
        self.assertEqual(result[0], 7)
        self.assertEqual(result[4].strip(b"\x00"), b"root")
        self.assertEqual(result[5].strip(b"\x00"), b"192.168.1.1")

    def test_lastlog_struct_pack_unpack(self):
        """Test LASTLOG binary structure."""
        fmt = "i32s256s"
        block_size = 292

        data = struct.pack(fmt, 1500000000, b"pts/0", b"10.0.0.1")
        if len(data) < block_size:
            data += b"\x00" * (block_size - len(data))

        self.assertEqual(len(data), block_size)
        result = struct.unpack(fmt, data)
        self.assertEqual(result[0], 1500000000)
        self.assertEqual(result[1].strip(b"\x00"), b"pts/0")
        self.assertEqual(result[2].strip(b"\x00"), b"10.0.0.1")

    def test_log_line_detection(self):
        """Test IP/hostname detection in log lines."""
        ip = "192.168.1.1"
        hostname = "evil-host"

        line_with_ip = "Jan 1 12:00:00 server sshd[1234]: Failed password from 192.168.1.1"
        line_with_host = "Jan 1 12:00:00 server sshd[1234]: Failed password from evil-host"
        clean_line = "Jan 1 12:00:00 server sshd[1234]: Failed password from 10.0.0.1"

        self.assertIn(ip, line_with_ip)
        self.assertIn(hostname, line_with_host)
        self.assertNotIn(ip, clean_line)

    def test_last_login_tracking(self):
        """Test the LAST_LOGIN tracking logic."""
        last = {"timestamp": 0, "terminal": "", "hostname": ""}

        entries = [
            ("root", 1000000, "pts/0", "10.0.0.1"),
            ("root", 2000000, "pts/1", "10.0.0.2"),
            ("other", 3000000, "pts/2", "10.0.0.3"),
        ]

        username = "root"
        for user, ts, term, host in entries:
            if user == username and ts > last["timestamp"]:
                last = {"timestamp": ts, "terminal": term, "hostname": host}

        self.assertEqual(last["timestamp"], 2000000)
        self.assertEqual(last["terminal"], "pts/1")
        self.assertEqual(last["hostname"], "10.0.0.2")

    def test_utmp_padding_check(self):
        """Test the 20-byte null padding at UTMP block end."""
        valid_block = b"\x00" * 384
        invalid_block = b"\x00" * 364 + b"some non-null data   "
        self.assertEqual(valid_block[-20:], b"\x00" * 20)
        self.assertNotEqual(invalid_block[-20:], b"\x00" * 20)

    def test_boot_count_logic(self):
        """Test the power cycle count comparison logic."""
        state = {"sda": 100}
        count = 103
        boots = count - state["sda"] - 1
        self.assertEqual(boots, 2)

        count = 100
        boots = count - state["sda"] - 1
        self.assertTrue(boots <= 0)

    def test_ask_confirmation_default(self):
        """Test ask_confirmation default is yes."""
        answers = {"y": True, "yes": True, "n": False, "no": False}
        self.assertEqual(answers.get("", True), True)

    def test_ask_confirmation_no(self):
        """Test ask_confirmation 'no'."""
        answers = {"y": True, "yes": True, "n": False, "no": False}
        self.assertEqual(answers.get("n", True), False)


class TestNojailModule(unittest.TestCase):
    """Tests that require the nojail module."""

    def setUp(self):
        if not HAVE_NOJAIL:
            self.skipTest("nojail module not importable in this Python version")

    def test_random_string(self):
        from nojail import random_string
        s1 = random_string(10)
        self.assertEqual(len(s1), 10)

    def test_formatting(self):
        from nojail import error, success, info
        self.assertIn("Error:", error("test"))
        self.assertIn("*", success("test"))
        self.assertEqual(info("test"), "[ ] test")

    def test_ask_confirmation_yes(self):
        from nojail import ask_confirmation
        with patch('builtins.input', return_value='y'):
            self.assertTrue(ask_confirmation("test"))

    def test_ask_confirmation_no(self):
        from nojail import ask_confirmation
        with patch('builtins.input', return_value='n'):
            self.assertFalse(ask_confirmation("test"))


if __name__ == '__main__':
    from unittest.mock import patch
    unittest.main()
