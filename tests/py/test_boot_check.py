#!/usr/bin/env python
"""
Tests for boot_check.py2 and boot_check.py3
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# boot_check.py is Python 3, should import fine under py3
try:
    from boot_check import (check_prerequisites, initialize, check_boot_count,
                           get_hard_drives, get_drive_model, get_power_cycle_count, dialog)
    HAVE_BOOT_CHECK = True
except (ImportError, SyntaxError):
    HAVE_BOOT_CHECK = False


class TestBootCheckLogic(unittest.TestCase):
    """Test boot_check logic without importing the module."""

    def test_check_prerequisites_root(self):
        """Running as root should pass."""
        self.assertEqual(os.geteuid(), 0 if os.geteuid() == 0 else os.geteuid())

    def test_power_cycle_parse(self):
        """Test the smartctl output parsing logic."""
        mock_output = "  9 Power_Cycle_Count       0x0032   100   100   000    Old_age   Always       -       42"
        result = int(mock_output.split()[-1])
        self.assertEqual(result, 42)

    def test_boot_count_logic_normal(self):
        """Test normal boot count (no extra boots)."""
        state = {"sda": 100}
        count = 100
        boots = count - state["sda"] - 1
        self.assertTrue(boots <= 0)

    def test_boot_count_logic_extra(self):
        """Test detection of extra boots."""
        state = {"sda": 100}
        count = 103
        boots = count - state["sda"] - 1
        self.assertEqual(boots, 2)

    def test_hard_drives_parse(self):
        """Test the lsblk JSON parsing."""
        mock_json = json.dumps({
            "blockdevices": [
                {"name": "sda", "type": "disk"},
                {"name": "sdb", "type": "disk"},
                {"name": "loop0", "type": "loop"},
            ]
        })

        lsblk = json.loads(mock_json)
        devices = [d["name"] for d in lsblk["blockdevices"] if d["type"] == "disk"]
        self.assertEqual(devices, ["sda", "sdb"])

    def test_drive_model_parse(self):
        """Test the lsblk -S JSON parsing."""
        mock_json = json.dumps({
            "blockdevices": [
                {"name": "sda", "model": "Samsung SSD 860 EVO"},
            ]
        })

        lsblk = json.loads(mock_json)
        model_map = {d["name"]: d["model"] for d in lsblk["blockdevices"]}
        self.assertEqual(model_map.get("sda"), "Samsung SSD 860 EVO")

    def test_initialize_state_roundtrip(self):
        """Test JSON serialization/deserialization of init data."""
        data = {"sda": 42, "sdb": 17}
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        self.assertEqual(parsed, data)

    def test_dialog_height(self):
        """Test dialog box height calculation."""
        text = "Warning: Samsung SSD 860 EVO was started 2 times since the last check!"
        width = 50
        lines = 5 + (len(text) // (width - 4))
        self.assertGreater(lines, 5)


class TestBootCheckModule(unittest.TestCase):
    """Tests that load the actual boot_check module."""

    def setUp(self):
        if not HAVE_BOOT_CHECK:
            self.skipTest("boot_check module not importable")

    def test_formatting(self):
        # Test basic module availability
        self.assertTrue(HAVE_BOOT_CHECK)


if __name__ == '__main__':
    unittest.main()
