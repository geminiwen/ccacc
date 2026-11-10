"""Automatic outgoing backups with real file transitions and fake system IO only."""
import json
import os
import pty
import select
import shlex
import signal
import time
import unittest

import test_ccacc_shell_integration as integration

# save/use read the weekly reset from Keychain and network; fixtures forbid both.
os.environ["CCACC_NO_WEEKLY_RESET"] = "1"
# list/current/use refresh the latest Release from GitHub; fixtures forbid the network.
os.environ["CCACC_NO_UPDATE_CHECK"] = "1"


MOCKS = r'''
source "$FIXTURE_CORE" help >/dev/null
read_credentials() { printf 'read\n' >> "$OPS"; cat "$STRAY_CREDENTIALS_FILE"; }
write_credentials() { printf 'write\n' >> "$OPS"; printf '%s\n' "$1" > "$STRAY_CREDENTIALS_FILE"; }
delete_credentials() { printf 'delete\n' >> "$OPS"; rm -f "$STRAY_CREDENTIALS_FILE"; }
migrate_encrypted_backups() { printf 'password\n' >> "$OPS"; }
stop_claude() { printf 'stop\n' >> "$OPS"; }
# Real process checks are covered by test_ccacc_close_prompt.
confirm_close_claude() { :; }
note_device_keys() { :; }
apply_surge() { printf 'surge\n' >> "$OPS"; }
mktemp() { printf 'stage\n' >> "$OPS"; command mktemp "$@"; }
'''


class UseConfirmationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = integration.ShellIntegrationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.home = self.fixture.home
        self.accounts = self.fixture.accounts
        self.fixture.startup("bash")
        self.fixture.cli("configure-shell")
        self.ops = self.fixture.fixture / "operations"
        self.fixture.env["OPS"] = str(self.ops)
        self.credentials = self.home / ".claude/.credentials.json"
        self.credentials.write_text(json.dumps({"claudeAiOauth": {"accessToken": "latest-login-secret"},
                                               "mcpOAuth": {"shared": "shared-secret"}}))
        (self.home / ".claude.json").write_text(json.dumps({"userID": "latest-id-secret",
            "numStartups": 42, "projects": {"private-project-secret": {}},
            "mcpServers": {"shared": {"url": "shared-url-secret"}}}))
        (self.accounts / "sydney.json").write_text('{"userID":"old-saved-id"}')
        (self.accounts / "sydney.credentials").write_text('{"claudeAiOauth":{"accessToken":"old-secret"}}')
        (self.accounts / "tokyo.json").write_text('{"userID":"target-id"}')
        (self.accounts / "tokyo.credentials").write_text('{"claudeAiOauth":{"accessToken":"target-secret"}}')
        for name in ("sydney", "tokyo"):
            (self.accounts / (name + ".surge")).write_text('{"Claude":"saved-route"}')
        (self.accounts / ".launch-mode").write_text('{"version":1,"account":"sydney","yolo":true}\n')
        (self.accounts / ".launch-mode").chmod(0o600)
        (self.home / ".claude/history.jsonl").write_text("latest-history-secret\n")
        drafts = self.home / ".claude/feedback/drafts"
        drafts.mkdir(parents=True)
        (drafts / "draft").write_text("draft-secret")
        cache = self.home / "Library/Caches/claude-cli-nodejs"
        cache.mkdir(parents=True)
        (cache / "cache").write_text("cache-secret")
        self.sessions = self.home / ".claude/sessions"
        self.sessions.mkdir()
        self.session_bytes = {
            "fixture-session.json": b'{"id":"synthetic-sydney-session","pid":12345}\n',
            "fixture-session.key": b"\x00\xffsynthetic-session-key\x01\n",
        }
        for name, content in self.session_bytes.items():
            (self.sessions / name).write_bytes(content)
        # Exercise the same presence predicate as stash_paths, including broken links.
        (self.home / ".claude/plans").symlink_to("absent-fixture-plan")
        # Preserve real implementations while observing ordering at their boundaries.
        self.mocks = MOCKS
        for name in ("save_account", "load_account", "stash_paths", "report_outgoing_backup", "unstash_paths"):
            self.mocks += '\neval "$(declare -f ' + name + " | sed '1s/" + name + "/original_" + name + "/')\"\n"
            self.mocks += name + '() { printf "' + name + '\\n" >> "$OPS"; original_' + name + ' "$@"; }\n'

    def snapshot(self):
        result = {}
        for p in self.home.rglob("*"):
            stat = p.lstat()
            value = os.readlink(p) if p.is_symlink() else p.read_bytes() if p.is_file() else None
            result[str(p.relative_to(self.home))] = (value, stat.st_mtime_ns, stat.st_ino, stat.st_mode)
        return result

    def operations(self):
        return self.ops.read_text().splitlines() if self.ops.exists() else []

    def run_body(self, body, success=True, stdin="password-stdin-sentinel\n"):
        return self.fixture.run_process(["/bin/bash", "-c", self.mocks + "\n" + body],
                                        success=success, stdin=stdin)

    def run_pty(self, args, yolo_answer=None):
        code = self.mocks + "\nmain use " + shlex.join(args)
        stdout = self.fixture.fixture / "pty.stdout"
        before = self.snapshot()
        pid, master = pty.fork()
        if pid == 0:
            output = os.open(stdout, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(output, 1)
            os.close(output)
            os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-c", code], self.fixture.env)
        data = b""
        status = None
        yolo_sent = False
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.05)
                if ready:
                    try:
                        data += os.read(master, 65536)
                    except OSError:
                        pass
                if not yolo_sent and b"YOLO? (y/N) " in data:
                    self.assertIsNotNone(yolo_answer, data.decode(errors="replace"))
                    self.assertEqual(self.snapshot(), before)
                    self.assertEqual(self.operations(), [])
                    os.write(master, yolo_answer)
                    yolo_sent = True
                done, result = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = os.waitstatus_to_exitcode(result)
                    while select.select([master], [], [], 0)[0]:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        data += chunk
                    break
            self.assertIsNotNone(status, data.decode(errors="replace"))
        finally:
            if status is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(master)
        self.assertFalse(self.fixture.forbidden.exists())
        return status, data.decode(errors="replace"), stdout.read_text()

    def assert_switched(self):
        self.assertEqual((self.accounts / ".active").read_text(), "tokyo\n")
        saved = json.loads((self.accounts / "sydney.json").read_text())
        self.assertEqual(saved["userID"], "latest-id-secret")
        self.assertEqual(saved["numStartups"], 42)
        self.assertNotIn("mcpServers", saved)
        self.assertEqual(json.loads((self.accounts / "sydney.credentials").read_text()),
                         {"claudeAiOauth": {"accessToken": "latest-login-secret"}})
        self.assertEqual((self.accounts / "sydney/history.jsonl").read_text(), "latest-history-secret\n")
        self.assertFalse((self.home / ".claude/history.jsonl").exists())
        self.assertEqual((self.accounts / "sydney/feedback-drafts/draft").read_text(), "draft-secret")
        self.assertEqual((self.accounts / "sydney/cli-nodejs-cache/cache").read_text(), "cache-secret")
        self.assertEqual({p.name: p.read_bytes() for p in (self.accounts / "sydney/sessions").iterdir()},
                         self.session_bytes)
        self.assertFalse(self.sessions.exists())
        self.assertTrue((self.accounts / "sydney/plans").is_symlink())
        self.assertEqual(json.loads(self.credentials.read_text())["mcpOAuth"], {"shared": "shared-secret"})
        self.assertEqual(json.loads((self.home / ".claude.json").read_text())["mcpServers"],
                         {"shared": {"url": "shared-url-secret"}})
        self.assertEqual((self.accounts / ".timezones/sydney").read_text(), "Australia/Sydney\n")
        self.assertEqual((self.accounts / "sydney.surge").read_text(), '{"Claude":"saved-route"}')
        ops = self.operations()
        for earlier, later in zip(("password", "stop", "save_account", "load_account", "stash_paths", "report_outgoing_backup"),
                                  ("stop", "save_account", "load_account", "stash_paths", "report_outgoing_backup", "unstash_paths")):
            self.assertLess(ops.index(earlier), ops.index(later))

    def test_terminal_saves_latest_state_with_precise_secret_free_report(self):
        # A stale outgoing path is cleared by stashing, and target-only archives
        # are restored later; neither belongs in the completed outgoing report.
        (self.accounts / "sydney/telemetry").mkdir(parents=True)
        target = self.accounts / "tokyo/debug"
        target.mkdir(parents=True)
        (target / "target-only").write_text("target-history-secret")
        status, stderr, stdout = self.run_pty(["tokyo", "--no-yolo"])
        self.assertEqual(status, 0, stderr + stdout)
        self.assert_report(stderr)
        self.assertNotIn("telemetry:", stderr)
        self.assertNotIn("debug:", stderr)
        self.assertEqual((self.home / ".claude/debug/target-only").read_text(), "target-history-secret")
        self.assert_switched()
        self.assertFalse(json.loads((self.accounts / ".launch-mode").read_text())["yolo"])

    def assert_report(self, stderr):
        # One summary line by default: what was saved and where, no per-path list.
        self.assertEqual(stderr.count("Backed up sydney: login, config, 5 history items"
                                      " \u2192 ~/.claude/accounts/sydney"), 1)
        for label in ("history.jsonl", "feedback-drafts", "plans", "sessions", "cli-nodejs-cache"):
            self.assertNotIn(label + ": ", stderr)
        self.assertNotIn("~/Library/Caches/claude-cli-nodejs", stderr)
        self.assertNotIn("remain unchanged", stderr)
        for secret in ("latest-login-secret", "shared-secret", "latest-id-secret", "private-project-secret",
                       "latest-history-secret", "draft-secret", "cache-secret", "shared-url-secret", "target-secret",
                       "target-history-secret", "userID", "numStartups", "mcpServers"):
            self.assertNotIn(secret, stderr)

    def test_sessions_roundtrip_moves_exact_json_and_key_bytes(self):
        target = self.accounts / "tokyo/sessions"
        target.mkdir(parents=True)
        target_bytes = {
            "target.json": b'{"id":"synthetic-tokyo-session"}\n',
            "target.key": b"\xfe\x00synthetic-target-key\x02",
        }
        for name, content in target_bytes.items():
            (target / name).write_bytes(content)
        self.run_body("main use tokyo --no-yolo")
        self.assertFalse(target.exists())
        self.assertEqual({p.name: p.read_bytes() for p in self.sessions.iterdir()}, target_bytes)
        self.assertEqual({p.name: p.read_bytes() for p in (self.accounts / "sydney/sessions").iterdir()},
                         self.session_bytes)
        target_bytes["next.json"] = b'{"id":"synthetic-new-tokyo-session"}\n'
        (self.sessions / "next.json").write_bytes(target_bytes["next.json"])
        self.run_body("main use sydney --no-yolo")
        self.assertEqual({p.name: p.read_bytes() for p in self.sessions.iterdir()}, self.session_bytes)
        self.assertEqual({p.name: p.read_bytes() for p in target.iterdir()}, target_bytes)
        self.assertFalse((self.accounts / "sydney/sessions").exists())

    def test_use_isolates_account_caches_with_legacy_and_current_backups(self):
        caches = {
            "cachedArtifactRoster": {"accountWuid": "outgoing-account", "orgWuid": "outgoing-org"},
            "cachedUsageUtilization": {"orgWuid": "outgoing-org", "utilization": 42},
        }
        target_caches = {
            "cachedArtifactRoster": {"accountWuid": "target-account", "orgWuid": "target-org"},
            "cachedUsageUtilization": {"orgWuid": "target-org", "utilization": 7},
        }
        config_path = self.home / ".claude.json"
        for incoming in ({}, target_caches):
            with self.subTest(incoming=incoming):
                config = json.loads(config_path.read_text())
                config.update(caches)
                config_path.write_text(json.dumps(config))
                (self.accounts / "tokyo.json").write_text(json.dumps({"userID": "target-id", **incoming}))
                self.run_body("main use tokyo --no-yolo")
                saved = json.loads((self.accounts / "sydney.json").read_text())
                switched = json.loads(config_path.read_text())
                for key, value in caches.items():
                    self.assertEqual(saved[key], value)
                    if key in incoming:
                        self.assertEqual(switched[key], incoming[key])
                    else:
                        self.assertNotIn(key, switched)
                self.assertEqual(switched["mcpServers"], config["mcpServers"])
                self.run_body("main use sydney --no-yolo")
                restored = json.loads(config_path.read_text())
                for key, value in caches.items():
                    self.assertEqual(restored[key], value)

    def test_yolo_no_blank_eof_mean_normal_mode_without_backup_consent(self):
        for answer in (b"n\n", b"\n", b"\x04", b"unexpected\n"):
            with self.subTest(answer=answer):
                status, stderr, _ = self.run_pty(["tokyo"], yolo_answer=answer)
                self.assertEqual(status, 0, stderr)
                self.assert_report(stderr)
                self.assert_switched()
                self.assertFalse(json.loads((self.accounts / ".launch-mode").read_text())["yolo"])
                self.run_body("main use sydney --no-yolo")
                self.ops.unlink()

    def test_yolo_ctrl_c_cancels_before_mutations(self):
        before = self.snapshot()
        status, stderr, _ = self.run_pty(["tokyo"], yolo_answer=b"\x03")
        self.assertEqual(status, 130, stderr)
        self.assertNotIn("Backed up ", stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.operations(), [])

    def test_nonterminal_without_yes_password_reads_stdin_once(self):
        result = self.run_body(r'''
migrate_encrypted_backups() {
    printf 'password\n' >> "$OPS"
    IFS= read -r password
    [ "$password" = password-stdin-sentinel ] || return 98
}
main use tokyo
IFS= read -r remaining
printf '%s\n' "$remaining"
''', stdin="password-stdin-sentinel\nremaining-sentinel\n")
        self.assertTrue(result.stdout.endswith("remaining-sentinel\n"), result.stdout)
        self.assert_report(result.stderr)
        self.assert_switched()
        self.assertEqual(self.operations().count("password"), 1)
        self.assertFalse(json.loads((self.accounts / ".launch-mode").read_text())["yolo"])

    def test_removed_yes_option_is_rejected_without_changes(self):
        for args in ("tokyo --yes", "--yes tokyo", "tokyo --yes --no-yolo"):
            with self.subTest(args=args):
                before = self.snapshot()
                result = self.run_body("main use " + args, success=False)
                self.assertIn("Unknown use option '--yes'; expected --yolo, --no-yolo or --verbose", result.stderr)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.operations(), [])
                self.assertEqual((self.accounts / ".active").read_text(), "sydney\n")

    def test_logged_out_named_profile_reports_no_encrypted_login_backup(self):
        self.credentials.write_text('{"mcpOAuth":{"shared":"shared-secret"}}')
        result = self.run_body("main use tokyo --no-yolo")
        self.assertIn("Backed up sydney: no login (logged out), config", result.stderr)
        self.assertNotIn("Encrypted Claude login backup:", result.stderr)
        self.assertFalse((self.accounts / "sydney.credentials").exists())
        self.assertNotIn("login:  ", self.run_body("main use sydney --no-yolo && main use tokyo --no-yolo -v").stderr)
        self.assertEqual(json.loads(self.credentials.read_text())["mcpOAuth"], {"shared": "shared-secret"})

    def test_logged_out_backup_delete_failure_blocks_switch_and_report(self):
        self.credentials.write_text('{"mcpOAuth":{"shared":"shared-secret"}}')
        stale_login = (self.accounts / "sydney.credentials").read_bytes()
        before = {path: metadata for path, metadata in self.snapshot().items() if metadata[0] is not None}
        result = self.run_body(r'''
rm() {
    if [ "$#" = 2 ] && [ "$1" = -f ] && [ "$2" = "$ACCOUNTS_DIR/sydney.credentials" ]; then
        printf 'delete_backup_failed\n' >> "$OPS"
        return 91
    fi
    command rm "$@"
}
main use tokyo --no-yolo
''', success=False)
        self.assertIn("delete_backup_failed", self.operations())
        for operation in ("load_account", "stash_paths", "report_outgoing_backup", "unstash_paths", "surge"):
            self.assertNotIn(operation, self.operations())
        self.assertNotIn("Backed up ", result.stderr)
        self.assertNotIn("Switched to", result.stdout)
        self.assertEqual((self.accounts / "sydney.credentials").read_bytes(), stale_login)
        self.assertEqual({path: metadata for path, metadata in self.snapshot().items() if metadata[0] is not None}, before)

    def test_report_reads_only_metadata_and_leaves_files_unchanged(self):
        result = self.run_body(r'''
stash_paths sydney
read_credentials() { return 98; }
read_backup() { return 99; }
report_outgoing_backup sydney
''')
        self.assert_report(result.stderr)
        self.assertEqual(self.operations(), ["stash_paths", "report_outgoing_backup"])
        before = self.snapshot()
        self.run_body("report_outgoing_backup sydney")
        self.assertEqual(self.snapshot(), before)

    def test_no_archive_paths_reports_none(self):
        self.run_body(r'''
for entry in "${ACCOUNT_PATHS[@]}"; do rm -rf "${entry#*|}"; done
''')
        result = self.run_body("main use tokyo --no-yolo")
        self.assertIn("Backed up sydney: login, config, 0 history items", result.stderr)
        self.assertNotIn("(none archived)", result.stderr)

    def test_verbose_lists_every_saved_path(self):
        result = self.run_body("main use tokyo --no-yolo --verbose")
        self.assertIn("Backed up sydney: login, config, 5 history items", result.stderr)
        self.assertIn("login:  ~/.claude/accounts/sydney.credentials (plain file, not encrypted)", result.stderr)
        self.assertIn("config: ~/.claude/accounts/sydney.json", result.stderr)
        for label in ("history.jsonl", "feedback-drafts", "plans", "sessions", "cli-nodejs-cache"):
            self.assertIn(label + ": ~/.claude/accounts/sydney/" + label, result.stderr)
        self.assertNotIn("latest-history-secret", result.stderr)

    def test_verbose_without_archives_says_none(self):
        self.run_body(r'''
for entry in "${ACCOUNT_PATHS[@]}"; do rm -rf "${entry#*|}"; done
''')
        self.assertIn("history: (none archived)", self.run_body("main use tokyo -v --no-yolo").stderr)

    def test_clean_unnamed_profile_has_no_outgoing_backup_or_report(self):
        result = self.run_body(r'''
rm -f "$ACTIVE_FILE"
printf '{"mcpServers":{"shared":{}}}' > "$CLAUDE_JSON"
printf '{"mcpOAuth":{"shared":"shared-secret"}}' > "$STRAY_CREDENTIALS_FILE"
for entry in "${ACCOUNT_PATHS[@]}"; do rm -rf "${entry#*|}"; done
main use tokyo --no-yolo
''')
        self.assertNotIn("Backed up ", result.stderr)
        for operation in ("save_account", "stash_paths", "report_outgoing_backup"):
            self.assertNotIn(operation, self.operations())
        for operation in ("password", "stop", "load_account", "unstash_paths", "surge"):
            self.assertEqual(self.operations().count(operation), 1)
        self.assertEqual((self.accounts / ".active").read_text(), "tokyo\n")

    def test_backup_failure_blocks_load_stash_report_and_switch_success(self):
        result = self.run_body('backup_active() { printf "backup_failed\\n" >> "$OPS"; return 91; }; '
                               'main use tokyo --no-yolo', success=False)
        self.assertEqual(self.operations(), ["stage", "password", "stop", "backup_failed"])
        self.assertNotIn("Backed up ", result.stderr)
        self.assertNotIn("Switched to", result.stdout)
        self.assertEqual((self.accounts / ".active").read_text(), "sydney\n")

    def test_login_save_failure_blocks_load_stash_report(self):
        result = self.run_body("write_plain_backup() { return 91; }; main use tokyo --no-yolo", success=False)
        self.assertIn("save_account", self.operations())
        for operation in ("load_account", "stash_paths", "report_outgoing_backup", "unstash_paths", "surge"):
            self.assertNotIn(operation, self.operations())
        self.assertNotIn("Backed up ", result.stderr)
        self.assertNotIn("Switched to", result.stdout)

    def test_stash_failure_blocks_report_and_target_path_restore(self):
        result = self.run_body('stash_paths() { printf "stash_failed\\n" >> "$OPS"; return 91; }; '
                               'main use tokyo --no-yolo', success=False)
        self.assertIn("load_account", self.operations())
        self.assertEqual(self.operations()[-1], "stash_failed")
        self.assertNotIn("report_outgoing_backup", self.operations())
        self.assertNotIn("unstash_paths", self.operations())
        self.assertNotIn("Backed up ", result.stderr)
        self.assertNotIn("Switched to", result.stdout)
        self.assertEqual((self.accounts / ".active").read_text(), "sydney\n")

    def test_later_restore_failure_keeps_truthful_backup_report_without_switch_success(self):
        target = self.accounts / "tokyo/debug"
        target.mkdir(parents=True)
        (target / "target-only").write_text("target-history-secret")
        mode = (self.accounts / ".launch-mode").read_bytes()
        result = self.run_body(r'''
unstash_paths() {
    printf 'unstash_paths\n' >> "$OPS"
    original_unstash_paths "$@" || return 1
    return 91
}
main use tokyo --no-yolo
''', success=False)
        self.assert_report(result.stderr)
        self.assertNotIn("debug:", result.stderr)
        self.assertNotIn("Switched to", result.stdout)
        self.assertEqual((self.accounts / ".active").read_text(), "sydney\n")
        self.assertEqual((self.accounts / ".launch-mode").read_bytes(), mode)
        self.assertEqual((self.home / ".claude/debug/target-only").read_text(), "target-history-secret")
        self.assertEqual((self.accounts / "sydney/history.jsonl").read_text(), "latest-history-secret\n")
        for operation in ("save_account", "load_account", "stash_paths", "report_outgoing_backup", "unstash_paths"):
            self.assertEqual(self.operations().count(operation), 1)
        self.assertNotIn("surge", self.operations())

    def write_settings(self, content):
        settings = self.home / ".ccacc/settings.json"
        settings.parent.mkdir(exist_ok=True)
        settings.write_text(content)
        return settings

    def launch_yolo(self):
        return json.loads((self.accounts / ".launch-mode").read_text())["yolo"]

    def test_always_yolo_skips_prompt_on_terminal_and_noninteractive(self):
        self.write_settings('{"alwaysYOLO": true, "unrelatedFutureKey": {"ignored": 1}}')
        # run_pty fails if the YOLO prompt appears without an answer to send.
        status, stderr, _ = self.run_pty(["tokyo"])
        self.assertEqual(status, 0, stderr)
        self.assertNotIn("YOLO?", stderr)
        self.assertIn("YOLO enabled by alwaysYOLO in " + str(self.home / ".ccacc/settings.json"), stderr)
        self.assert_switched()
        self.assertIs(self.launch_yolo(), True)
        self.run_body("main use sydney --no-yolo")
        result = self.run_body("main use tokyo")
        self.assertNotIn("YOLO?", result.stderr)
        self.assertIs(self.launch_yolo(), True)

    def test_explicit_no_yolo_overrides_always_yolo(self):
        self.write_settings('{"alwaysYOLO": true}')
        status, stderr, _ = self.run_pty(["tokyo", "--no-yolo"])
        self.assertEqual(status, 0, stderr)
        self.assertNotIn("YOLO", stderr)
        self.assertIs(self.launch_yolo(), False)
        self.run_body("main use sydney --no-yolo")
        self.assertIs(self.launch_yolo(), False)

    def test_false_or_absent_always_yolo_keeps_prompt(self):
        for content in (None, "{}", '{"alwaysYOLO": false}', '{"other": true}'):
            with self.subTest(content=content):
                if content is not None:
                    self.write_settings(content)
                status, stderr, _ = self.run_pty(["tokyo"], yolo_answer=b"n\n")
                self.assertEqual(status, 0, stderr)
                self.assertIn("YOLO? (y/N)", stderr)
                self.assertIs(self.launch_yolo(), False)
                self.run_body("main use sydney --no-yolo")
                self.ops.unlink()
                self.run_body("main use tokyo")
                self.assertIs(self.launch_yolo(), False)
                self.run_body("main use sydney --no-yolo")
                self.ops.unlink()

    def test_invalid_settings_abort_use_before_any_change(self):
        settings = self.home / ".ccacc/settings.json"
        cases = ["", "{", "[]", "null", "true", '{"alwaysYOLO": "true"}', '{"alwaysYOLO": null}',
                 '{"alwaysYOLO": 1}', "{} {}", "directory", "unreadable", "dangling"]
        for case in cases:
            with self.subTest(case=case):
                if settings.is_symlink() or settings.is_file():
                    settings.unlink()
                elif settings.is_dir():
                    settings.rmdir()
                settings.parent.mkdir(exist_ok=True)
                if case == "directory":
                    settings.mkdir()
                elif case == "dangling":
                    settings.symlink_to(self.home / "missing-settings.json")
                else:
                    settings.write_text('{"alwaysYOLO": true}' if case == "unreadable" else case)
                before = self.snapshot()
                if case == "unreadable":
                    mode = settings.stat().st_mode & 0o777
                    settings.chmod(0)
                try:
                    for args in ("tokyo", "tokyo --yolo", "tokyo --no-yolo", "sydney"):
                        result = self.run_body("main use " + args, success=False)
                        self.assertIn("Invalid settings file " + str(settings), result.stderr)
                        self.assertNotIn("YOLO?", result.stderr)
                        self.assertEqual(self.operations(), [])
                finally:
                    if case == "unreadable":
                        settings.chmod(mode)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual((self.accounts / ".active").read_text(), "sydney\n")

    def test_options_in_either_order_and_explicit_yolo(self):
        for args, expected in (("tokyo --no-yolo", False), ("--no-yolo tokyo", False),
                               ("tokyo --yolo", True), ("--yolo tokyo", True)):
            with self.subTest(args=args):
                self.run_body("main use " + args)
                self.assertEqual(json.loads((self.accounts / ".launch-mode").read_text())["yolo"], expected)
                self.run_body("main use sydney --no-yolo")

    def test_bad_options_fail_before_any_system_boundary(self):
        for args in ("tokyo --yolo --yolo", "tokyo --no-yolo --no-yolo",
                     "tokyo --yolo --no-yolo", "tokyo --no-yolo --yolo",
                     "tokyo --unknown", "tokyo --yes", "tokyo extra", "tokyo ''"):
            with self.subTest(args=args):
                before = self.snapshot()
                self.run_body('require_shell_hook() { printf hook >> "$OPS"; }; main use ' + args, success=False)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.operations(), [])

    def test_same_active_skips_backup_and_restore_but_selects_yolo_and_reapplies_surge(self):
        before = {p: p.read_bytes() for p in (self.credentials, self.home / ".claude.json",
                  self.accounts / "sydney.json", self.accounts / "sydney.credentials")}
        result = self.run_body("main use sydney --yolo")
        self.assertNotIn("Confirm outgoing backup", result.stderr)
        self.assertNotIn("Backed up ", result.stderr)
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        self.assertEqual(self.operations(), ["stage", "surge"])
        self.assertTrue(json.loads((self.accounts / ".launch-mode").read_text())["yolo"])


if __name__ == "__main__":
    unittest.main()
