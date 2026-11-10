"""Fixture-only checks for the weekly reset recorded on save and shown by list/use/current."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

# list/current/use refresh the latest Release from GitHub; fixtures forbid the network.
os.environ["CCACC_NO_UPDATE_CHECK"] = "1"

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "ccacc").read_text().rsplit('main "$@"', 1)[0]
TOKEN = "sk-ant-oat01-fixture_token"
WEEK = 7 * 86400
# Thu 03 Jan 2030 11:00 UTC, given with a +02:00 offset and fractional seconds.
RESET = 1893668400
USAGE = {"five_hour": {"utilization": 2.0, "resets_at": "2030-01-01T05:30:00Z"},
         "seven_day": {"utilization": 85.0, "resets_at": "2030-01-03T13:00:00.375803+02:00"}}


class WeeklyResetTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".orca").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / ".orca", prefix="weekly-reset-")
        self.addCleanup(self.temp.cleanup)
        self.fixture = Path(self.temp.name)
        self.home = self.fixture / "home"
        self.accounts = self.home / ".claude/accounts"
        self.accounts.mkdir(parents=True)
        (self.home / ".claude.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "a@example.com"}}))
        self.bin = self.fixture / "bin"
        self.bin.mkdir()
        self.calls = self.fixture / "curl.log"
        self.stdin = self.fixture / "curl.stdin"
        self.response = self.fixture / "response.json"
        self.response.write_text(json.dumps(USAGE))
        curl = self.bin / "curl"
        curl.write_text('#!/bin/bash\nprintf "%s\\n" "$@" >> "$CALLS"\ncat > "$STDIN"\n'
                        '[ -s "$RESPONSE" ] || exit 22\ncat "$RESPONSE"\n')
        curl.chmod(0o700)
        self.env = dict(os.environ, HOME=str(self.home), TZ="UTC", CALLS=str(self.calls),
                        STDIN=str(self.stdin), RESPONSE=str(self.response),
                        PATH=str(self.bin) + ":" + os.environ["PATH"])
        self.env.pop("CCACC_NO_WEEKLY_RESET", None)

    def bash(self, body, credentials=None):
        if credentials is None:
            credentials = self.login()
        mocks = "read_credentials() { printf '%s' " + repr(json.dumps(credentials)) + "; }\n"
        # Labels use the computer's timezone; pin it to UTC so expectations hold anywhere.
        mocks += 'in_system_timezone() { TZ=UTC "$@"; }\n'
        result = subprocess.run(["/bin/bash", "-c", SOURCE + mocks + body],
                                env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def login(self, expires_in=3600):
        return {"claudeAiOauth": {"accessToken": TOKEN,
                                  "expiresAt": int((time.time() + expires_in) * 1000)}}

    def record(self, name, value):
        (self.accounts / (name + ".weekly")).write_text(value)

    def test_prefetch_reads_weekly_reset_without_putting_token_in_argv(self):
        self.assertEqual(self.bash('prefetch_weekly_reset; record_weekly_reset tokyo'), "")
        self.assertEqual((self.accounts / "tokyo.weekly").read_text(), f"{RESET}\n")
        self.assertEqual((self.accounts / "tokyo.weekly").stat().st_mode & 0o777, 0o600)
        argv = self.calls.read_text()
        self.assertIn("https://api.anthropic.com/api/oauth/usage", argv)
        self.assertNotIn(TOKEN, argv)
        self.assertEqual(self.stdin.read_text(), "Authorization: Bearer " + TOKEN + "\n")

    def test_expired_login_is_not_sent_and_failures_keep_the_earlier_record(self):
        self.record("tokyo", "1000000000\n")
        self.bash('prefetch_weekly_reset; record_weekly_reset tokyo', self.login(expires_in=-60))
        self.assertFalse(self.calls.exists())
        for body in ("", "not json", json.dumps({"seven_day": None})):
            self.response.write_text(body)
            self.bash('prefetch_weekly_reset; record_weekly_reset tokyo')
            self.assertEqual((self.accounts / "tokyo.weekly").read_text(), "1000000000\n")

    def test_label_rolls_a_past_reset_forward_by_whole_weeks(self):
        past = RESET - 300 * WEEK  # Same weekday and time, long ago.
        self.record("tokyo", f"{past}\n")
        label = self.bash('weekly_reset_label tokyo').strip()
        self.assertRegex(label, r"^Thu \d\d \w{3} 11:00$")
        expected = past + -(-(int(time.time()) - past) // WEEK) * WEEK
        self.assertEqual(label, time.strftime("%a %d %b %H:%M", time.gmtime(expected)))
        self.record("tokyo", f"{RESET}\n")
        self.assertEqual(self.bash('weekly_reset_label tokyo'), "Thu 03 Jan 11:00\n")

    def test_label_ignores_the_session_timezone(self):
        self.record("tokyo", f"{RESET}\n")
        env = dict(self.env, TZ="Australia/Sydney")
        result = subprocess.run(["/bin/bash", "-c", SOURCE + 'weekly_reset_label tokyo'],
                                env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        system = subprocess.run(["env", "-u", "TZ", "date", "-r", str(RESET), "+%a %d %b %H:%M"],
                                text=True, capture_output=True, check=True).stdout
        self.assertEqual(result.stdout, system)

    def test_missing_or_invalid_record_shows_nothing(self):
        (self.accounts / "tokyo.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "t@example.com"}}))
        (self.accounts / ".active").write_text("tokyo\n")
        for value in (None, "", "soon\n", "\x1b[31m1\n"):
            if value is None:
                (self.accounts / "tokyo.weekly").unlink(missing_ok=True)
            else:
                self.record("tokyo", value)
            self.assertEqual(self.bash('weekly_reset_label tokyo'), "")
            self.assertNotRegex(self.bash('list_accounts'), r"\w{3} \d\d \w{3} \d\d:\d\d")
            self.assertNotIn("Weekly", self.bash('show_current'))
        self.record("tokyo", f"{RESET}\n")
        self.assertIn("Thu 03 Jan 11:00", self.bash('list_accounts'))
        self.assertIn("Weekly:     resets Thu 03 Jan 11:00", self.bash('show_current'))
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
