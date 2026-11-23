"""Tests for rathunter. Run with:  python3 -m unittest discover tests"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import rathunter  # noqa: E402
from simulated import SimulatedMac  # noqa: E402


class InfectedMacTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.mac = SimulatedMac(cls.tmp.name, infected=True)
        cls.result = rathunter.scan(cls.mac)
        cls.findings = cls.result["findings"]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def find(self, text, severity=None):
        hits = [f for f in self.findings if text in f["title"] + " " + f["detail"]
                and (severity is None or f["severity"] == severity)]
        self.assertTrue(hits, f"nothing about {text!r} ({severity}) in:\n" +
                        "\n".join(f"{f['severity']}: {f['title']}: {f['detail']}" for f in self.findings))
        return hits[0]

    def test_verdict_is_danger(self):
        self.assertEqual(self.result["verdict"]["level"], "danger")

    def test_startup_item_disguised_as_apple_running_a_telegram_rat(self):
        f = self.find("com.apple.softwareupdate.helper", "danger")
        self.assertIn("pretends to be part of macOS", f["detail"])
        self.assertIn("Telegram", f["detail"])
        self.assertIn("records keystrokes", f["detail"])
        self.assertTrue(f["where"].startswith("~/"), "home paths are hidden behind ~")
        self.assertIn('launchctl bootout gui/$(id -u) "$HOME/Library/LaunchAgents/', f["fix"])  # ~ wouldn't expand in quotes

    def test_sudo_alias_in_zshrc(self):
        f = self.find(".zshrc, line 2", "danger")
        self.assertIn("sudo", f["detail"])

    def test_keyboard_permission_for_a_hidden_script(self):
        f = self.find("agent.py", "danger")
        self.assertIn("read every key you type", f["detail"])

    def test_running_script_connected_to_telegram(self):
        f = self.find("is talking to Telegram", "danger")
        self.assertIn("~/.local-sync/agent.py", f["where"])

    def test_no_finding_reveals_the_home_folder(self):
        self.assertNotIn(str(self.mac.home), json.dumps(self.findings))

    def test_fake_system_process(self):
        f = self.find("Fake system process \"kernel_task\"", "danger")
        self.assertIn("/private/tmp/.x/kernel_task", f["where"])

    def test_traffic_interception(self):
        self.find("Configuration profile net.securewifi.config.4471", "warning")
        self.find("Trusted certificate: SecureWiFi Root CA", "warning")
        self.find("Web proxy is on", "warning")
        self.find("/etc/hosts redirects www.paypal.com", "danger")
        self.find("/etc/hosts blocks www.virustotal.com", "warning")

    def test_screen_time_profile_is_not_reported(self):
        self.assertFalse([f for f in self.findings if "ManagedSettings" in f["title"]])

    def test_remote_access(self):
        self.find("Remote Login (SSH) is on", "warning")
        f = self.find("SSH key is allowed", "warning")
        self.assertIn("support@remote-helpdesk", f["detail"])
        self.find("AnyDesk.app", "warning")

    def test_sideloaded_extension(self):
        f = self.find("PDF Converter Pro", "warning")
        self.assertIn("every website", f["detail"])

    def test_defenses(self):
        self.find("System Integrity Protection is off", "warning")

    def test_every_finding_names_its_check(self):
        for f in self.findings:
            self.assertIn(f["check"], self.result["checked"])


class CleanMacTest(unittest.TestCase):
    def test_a_clean_mac_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = rathunter.scan(SimulatedMac(tmp, infected=False))
        self.assertEqual(result["verdict"]["level"], "clean", json.dumps(result["findings"], indent=1))
        zoom = [f for f in result["findings"] if f["title"] == "us.zoom.xos"]
        self.assertEqual(zoom[0]["severity"], "info")   # listed so you can see it, but not alarming
        self.assertIn("see everything on your screen", zoom[0]["detail"])


class SkippedCheckTest(unittest.TestCase):
    def test_unreadable_privacy_database_is_reported_as_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            mac = SimulatedMac(tmp, infected=False)
            (mac.home / "Library/Application Support/com.apple.TCC/TCC.db").unlink()
            result = rathunter.scan(mac)
        skipped = [f for f in result["findings"] if f.get("skipped")]
        self.assertEqual([f["check"] for f in skipped], ["Privacy permissions"])
        self.assertIn("Full Disk Access", skipped[0]["fix"])


class HelperTest(unittest.TestCase):
    def test_split_command(self):
        self.assertEqual(rathunter.split_command(["/usr/bin/python3", "-u", "/x/a.py"]), ("python3", "/x/a.py", None))
        self.assertEqual(rathunter.split_command(["/bin/bash", "-c", "curl x | sh"]), ("bash", None, "curl x | sh"))
        self.assertEqual(rathunter.split_command(["/usr/bin/env", "FOO=1", "python3.12", "a.py"]), ("python3.12", "a.py", None))
        self.assertEqual(rathunter.split_command(["/Applications/X.app/Contents/MacOS/X"]), ("X", None, None))

    def test_shady_places(self):
        self.assertTrue(rathunter.is_shady_place("/tmp/x"))
        self.assertTrue(rathunter.is_shady_place("/Users/sam/.hidden/agent"))
        self.assertTrue(rathunter.is_shady_place("/Users/Shared/run"))
        self.assertFalse(rathunter.is_shady_place("/Users/sam/.nvm/versions/node/bin/node"))
        self.assertFalse(rathunter.is_shady_place("/Applications/Zoom.app/Contents/MacOS/zoom"))

    def test_signature_parsing(self):
        read = rathunter.read_signature
        self.assertEqual(read("Authority=Software Signing\n", "/bin/ls"), ("apple", "Apple"))
        self.assertEqual(read("Authority=Developer ID Application: Adobe Inc. (JQ525L2MZD)\n", "/bin/ls"),
                         ("developer", "Adobe Inc"))
        self.assertEqual(read("Signature=adhoc\n", "/bin/ls"), ("adhoc", None))
        self.assertEqual(read("/bin/ls: code object is not signed at all\n", "/bin/ls"), ("unsigned", None))
        self.assertEqual(read("/bin/ls: Permission denied\n", "/bin/ls"), ("unreadable", None))
        self.assertEqual(read("", "/definitely/not/here"), ("missing", None))

    def test_rat_signs_in_harmless_code(self):
        self.assertEqual(rathunter.rat_signs("print('hello')\nimport requests\n"), [])

    def test_report_cannot_break_out_of_its_script_tag(self):
        result = {"verdict": {"level": "clean", "headline": "x", "summary": "x"}, "checked": [], "system": "macOS",
                  "scanned_at": "2026-01-01T00:00:00", "version": "0", "findings": [
                      rathunter.finding("info", "Your defenses", "</script><script>alert(1)</script>", "x")]}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.html"
            rathunter.render_html(result, out)
            html = out.read_text(encoding="utf-8")
        self.assertNotIn("</script><script>alert(1)", html)


if __name__ == "__main__":
    unittest.main()
