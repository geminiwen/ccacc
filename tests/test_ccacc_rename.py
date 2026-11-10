"""Fixture-only checks for 'ccacc rename': every file named after the account follows it."""
import json
import os
import unittest

import test_ccacc_shell_integration as integration

os.environ["CCACC_NO_WEEKLY_RESET"] = "1"
os.environ["CCACC_NO_UPDATE_CHECK"] = "1"


class RenameTests(unittest.TestCase):
    def setUp(self):
        self.fixture = integration.ShellIntegrationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.accounts = self.fixture.accounts
        self.mode = self.accounts / ".launch-mode"
        self.active = self.accounts / ".active"

    def seed_mode(self, account, yolo=True):
        self.mode.write_text(json.dumps({"version": 1, "account": account, "yolo": yolo}) + "\n")
        self.mode.chmod(0o600)

    def fill(self, name):
        for suffix in (".credentials", ".surge", ".weekly"):
            (self.accounts / (name + suffix)).write_text(name + suffix)
        (self.accounts / ".aliases").mkdir(exist_ok=True)
        (self.accounts / ".aliases" / (name + ".json")).write_text("{}")
        (self.accounts / name / "projects").mkdir(parents=True)
        (self.accounts / name / "history.jsonl").write_text("history")

    def names(self):
        return sorted(path.relative_to(self.accounts).as_posix()
                      for path in self.accounts.rglob("*") if not path.name.startswith(".profile"))

    def test_dormant_account_moves_every_named_file_and_leaves_markers(self):
        self.fill("tokyo")
        self.seed_mode("sydney")
        mode = self.mode.read_bytes()
        result = self.fixture.cli("rename", "tokyo", "osaka")
        self.assertIn("Renamed tokyo to osaka", result.stdout)
        self.assertEqual(self.names(), [
            ".active", ".aliases", ".aliases/osaka.json", ".launch-mode", ".timezones",
            ".timezones/osaka", ".timezones/sydney", "osaka", "osaka.credentials", "osaka.json",
            "osaka.surge", "osaka.weekly", "osaka/history.jsonl", "osaka/projects", "sydney.json"])
        self.assertEqual((self.accounts / "osaka.credentials").read_text(), "tokyo.credentials")
        self.assertEqual(self.active.read_text(), "sydney\n")
        self.assertEqual(self.mode.read_bytes(), mode)
        self.assertEqual(self.fixture.cli("timezone", "osaka").stdout, "Asia/Tokyo\n")

    def test_active_account_keeps_being_active_with_its_yolo_choice(self):
        self.fixture.startup("bash")
        self.fixture.cli("configure-shell")
        for yolo in (True, False):
            with self.subTest(yolo=yolo):
                old, new = ("sydney", "perth") if yolo else ("perth", "sydney")
                self.seed_mode(old, yolo)
                self.fixture.cli("rename", old, new)
                self.assertEqual(self.active.read_text(), new + "\n")
                self.assertEqual(json.loads(self.mode.read_text()),
                                 {"version": 1, "account": new, "yolo": yolo})
                self.assertEqual(self.mode.stat().st_mode & 0o777, 0o600)
                self.assertEqual(self.fixture.cli("launch-mode").stdout, "true\n" if yolo else "false\n")
                self.assertEqual(self.fixture.cli("timezone").stdout, "Australia/Sydney\n")

    def test_refusals_change_nothing(self):
        self.fill("tokyo")
        (self.accounts / "taken").mkdir()
        cases = ((("rename", "tokyo"), "Usage: ccacc rename <old> <new>"),
                 (("rename", "tokyo", "osaka", "extra"), "Usage: ccacc rename <old> <new>"),
                 (("rename", "missing", "osaka"), "Account 'missing' not found"),
                 (("rename", "tokyo", "tokyo"), "already has that name"),
                 (("rename", "tokyo", "sydney"), "Account 'sydney' already exists"),
                 (("rename", "tokyo", "taken"), "Account 'taken' already exists"),
                 (("rename", "tokyo", ".hidden"), "must start with a letter or digit"),
                 (("rename", "tokyo", "a/b"), "must start with a letter or digit"))
        before = self.fixture.home_snapshot()
        for command, message in cases:
            with self.subTest(command=command):
                result = self.fixture.cli(*command, success=False)
                self.assertIn(message, result.stdout + result.stderr)
                self.assertEqual(self.fixture.home_snapshot(), before)

    def test_unsafe_paths_block_before_any_move(self):
        self.fill("tokyo")
        target = self.fixture.home / "elsewhere"
        target.write_text("x")
        (self.accounts / "tokyo.weekly").unlink()
        (self.accounts / "tokyo.weekly").symlink_to(target)
        before = self.fixture.home_snapshot()
        result = self.fixture.cli("rename", "tokyo", "osaka", success=False)
        self.assertIn("Unsafe or unwritable profile path", result.stderr)
        self.assertEqual(self.fixture.home_snapshot(), before)
        self.assertFalse((self.accounts / "osaka.json").exists())

    def test_failed_move_restores_the_old_name(self):
        self.fill("sydney")
        self.seed_mode("sydney")
        before = self.fixture.home_snapshot()
        result = self.fixture.harness(r'''
mv() { case "$1" in */sydney.weekly) return 1 ;; esac; command mv "$@"; }
main rename sydney perth
''', success=False)
        self.assertIn("Rename failed; 'sydney' keeps its name", result.stderr)
        self.assertEqual(self.fixture.home_snapshot(), before)
        self.assertFalse((self.accounts / "perth").exists())
        self.assertEqual(self.active.read_text(), "sydney\n")


if __name__ == "__main__":
    unittest.main()
