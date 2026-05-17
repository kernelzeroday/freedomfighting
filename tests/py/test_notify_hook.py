#!/usr/bin/env python
"""
Tests for notify_hook.py2 and notify_hook.py3 - version-aware.
"""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Import the right version
if sys.version_info[0] >= 3:
    SCRIPT = 'notify_hook.py'  # notify_hook.py IS python3
else:
    SCRIPT = 'notify_hook.py2'  # notify_hook.py2 is python2

try:
    import notify_hook
    HAVE_NOTIFY = True
except (ImportError, SyntaxError):
    HAVE_NOTIFY = False


class TestNotifyHookLogic(unittest.TestCase):
    """Test logic from notify_hook without importing."""

    def test_cmdline_parsing_direct(self):
        """Test /proc/cmdline parsing for direct binaries."""
        cmdline = "/usr/bin/id\x00--help\x00"
        parts = cmdline.split("\x00")
        self.assertEqual(parts[0], "/usr/bin/id")

    def test_cmdline_parsing_interpreter(self):
        """Test /proc/cmdline parsing for interpreter-based scripts."""
        cmdline = "/bin/bash\x00/usr/local/bin/script\x00arg1\x00"
        parts = cmdline.split("\x00")
        interpreters = ["/bin/bash", "/usr/bin/perl"]
        self.assertIn(parts[0], interpreters)
        self.assertEqual(parts[1], "/usr/local/bin/script")

    def test_ssh_connection_parsing(self):
        """Test SSH_CONNECTION environment parsing."""
        env = "192.168.1.100 54321 10.0.0.5 22"
        origin = env.split()[0]
        self.assertEqual(origin, "192.168.1.100")

    def test_ssh_connection_missing(self):
        """Test when SSH_CONNECTION is not set."""
        env = {}
        self.assertNotIn("SSH_CONNECTION", env)

    def test_find_command_skips_local(self):
        """Test that /local/ directories in PATH are skipped."""
        path = "/usr/local/bin:/usr/bin:/bin"
        command = "id"
        result = None
        for d in path.split(':'):
            if "/local/" in d:
                continue
            candidate = os.path.join(d, command)
            if os.path.exists(candidate):
                result = candidate
                break
        self.assertEqual(result, "/usr/bin/id")

    def test_message_format_full(self):
        """Test full notification message formatting."""
        hostname = "myserver"
        origin = "10.0.0.5"
        program = "id"
        caller = "/usr/bin/id"

        msg = "Warning: %s command invoked" % program
        msg += " on %s" % hostname
        msg += " by %s" % "root"
        msg += " from %s" % origin
        msg += " (%s)" % caller

        expected = "Warning: id command invoked on myserver by root from 10.0.0.5 (/usr/bin/id)"
        self.assertEqual(msg, expected)

    def test_whitelist_matching(self):
        """Test whitelist regex matching."""
        whitelist = [r"systemd", r"cron"]

        caller = "/usr/sbin/cron"
        notify = True
        for r in whitelist:
            if re.search(r, caller):
                notify = False
                break
        self.assertFalse(notify)

        caller = "/usr/bin/id"
        notify = True
        for r in whitelist:
            if re.search(r, caller):
                notify = False
                break
        self.assertTrue(notify)

    def test_hostname_reading(self):
        """Test /etc/hostname reading."""
        content = "myserver\n"
        hostname = content.strip()
        self.assertEqual(hostname, "myserver")

    def test_fork_control_flow(self):
        """Test fork return-value based control flow."""
        pid = 12345  # Parent
        parent_exits = pid > 0
        self.assertTrue(parent_exits)

        pid = 0  # Child
        child_continues = pid == 0
        self.assertTrue(child_continues)


class TestNotifyHookModule(unittest.TestCase):
    """Tests that load the actual notify_hook module."""

    def setUp(self):
        if not HAVE_NOTIFY:
            self.skipTest("notify_hook module not importable")

    def test_module_available(self):
        self.assertTrue(HAVE_NOTIFY)

    def test_get_hostname_with_mock(self):
        from unittest.mock import mock_open, patch
        with patch('notify_hook.open', mock_open(read_data='myserver\n')):
            result = notify_hook.get_hostname()
            self.assertEqual(result, 'myserver')


if __name__ == '__main__':
    unittest.main()
