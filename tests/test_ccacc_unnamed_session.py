"""Unnamed-session transitions with fixture files and fake crypto/login/processes."""
import json
import shlex
import os
import pty
import select
import shutil
import signal
import time
import unittest

import test_ccacc_shell_integration as integration

# save/use read the weekly reset from Keychain and network; fixtures forbid both.
os.environ["CCACC_NO_WEEKLY_RESET"] = "1"
# list/current/use refresh the latest Release from GitHub; fixtures forbid the network.
os.environ["CCACC_NO_UPDATE_CHECK"] = "1"


class UnnamedSessionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = integration.ShellIntegrationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.home = self.fixture.home
        self.accounts = self.fixture.accounts
        shutil.rmtree(self.home / ".claude")
        (self.home / ".claude.json").unlink()
        _, self.rcs = self.fixture.startup("bash")
        self.fixture.cli("configure-shell")
        self.ops = self.fixture.fixture / "session-operations"
        self.fixture.env["SESSION_OPERATIONS"] = str(self.ops)
        self.pending = self.accounts / ".pending-timezone"
        self.selection = self.accounts / ".unnamed-session"
        self.credentials = self.home / ".claude/.credentials.json"
        self.config = self.home / ".claude.json"
        self.active = self.accounts / ".active"
        self.shared = {"mcpOAuth": {"fixture": {"accessToken": "shared"}}, "futureField": {"keep": True}}

    def run_body(self, body, success=True, stdin="", process_mocks=True):
        return self.fixture.run_process(["/bin/bash", "-c", self.mocks(process_mocks) + "\n" + body],
                                        success=success, stdin=stdin)

    def mocks(self, process_mocks=True):
        # Only these boundaries are fake. All metadata, backup staging, bounded
        # config reset, history stashing and installation checks use real code.
        mocks = r'''
source "$FIXTURE_CORE" help >/dev/null
read_credentials() {
    printf 'read\n' >> "$SESSION_OPERATIONS"
    if [ -f "$STRAY_CREDENTIALS_FILE" ]; then cat "$STRAY_CREDENTIALS_FILE"; fi
}
write_credentials() { printf 'write\n' >> "$SESSION_OPERATIONS"; printf '%s\n' "$1" > "$STRAY_CREDENTIALS_FILE"; }
delete_credentials() { printf 'delete\n' >> "$SESSION_OPERATIONS"; rm -f "$STRAY_CREDENTIALS_FILE"; }
# Deliberately plaintext fixture backups: never use real credentials or encryption.
migrate_encrypted_backups() { printf 'password\n' >> "$SESSION_OPERATIONS"; }
stop_claude() { printf 'stop\n' >> "$SESSION_OPERATIONS"; }
# Real process checks are covered by test_ccacc_close_prompt.
confirm_close_claude() { :; }
note_device_keys() { :; }
setup_surge() { printf 'setup-surge\n' >> "$SESSION_OPERATIONS"; }
apply_surge() { printf 'apply-surge\n' >> "$SESSION_OPERATIONS"; }
new_identity() { printf '{"userID":"new-fixture-id","anonymousId":"new-anonymous","machineID":"new-machine"}'; }
'''
        if process_mocks:
            mocks += "\ncleanup_stop_processes() { stop_claude; }\ncleanup_runtime_is_safe() { :; }\n"
        return mocks

    def run_pty(self, body, prompt=None, answer=None):
        """Run body on a terminal. Before answering prompt, nothing may have changed."""
        output = self.fixture.fixture / "pty.stdout"
        before = self.snapshot()
        pid, master = pty.fork()
        if pid == 0:
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(descriptor, 1)
            os.close(descriptor)
            os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-c", self.mocks() + "\n" + body],
                      self.fixture.env)
        data = b""
        status = None
        sent = False
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.05)[0]:
                    try:
                        data += os.read(master, 65536)
                    except OSError:
                        pass
                if prompt is not None and not sent and prompt.encode() in data:
                    self.assertIsNotNone(answer, data.decode(errors="replace"))
                    self.assertEqual(self.snapshot(), before)
                    self.assertNotIn("stop", self.operations())
                    os.write(master, answer)
                    sent = True
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
        if prompt is not None and answer is not None:
            self.assertTrue(sent, data.decode(errors="replace"))
        return status, data.decode(errors="replace"), output.read_text()

    def snapshot(self):
        return {p.relative_to(self.home): (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino)
                for p in integration.home_files(self.home)}

    def hook_snapshot(self):
        paths = list(self.rcs) + list((self.home / ".ccacc-shell").iterdir())
        return {p: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in paths}

    def operations(self):
        return self.ops.read_text().splitlines() if self.ops.exists() else []

    def new_input(self, zone_answer=""):
        # The confirmation is asked only for a login no matching profile owns.
        plan = self.run_body("new_cleanup_plan").stdout.strip()
        return ("" if plan == "clean" or plan.startswith("save:") else "yes\n") + zone_answer

    def mismatch_active(self):
        config = json.loads(self.config.read_text())
        config["userID"] = "different-unsaved-login"
        self.config.write_text(json.dumps(config))

    def test_new_cancellation_and_rollback_preserve_launch_mode(self):
        self.saved_active()
        mode = self.accounts / ".launch-mode"
        mode.write_text('{"version":1,"account":"kept","yolo":true}\n')
        mode.chmod(0o600)
        before = mode.read_bytes(), mode.stat().st_mtime_ns, mode.stat().st_mode
        self.run_body("main new", success=False, stdin="n\n")
        self.assertEqual((mode.read_bytes(), mode.stat().st_mtime_ns, mode.stat().st_mode), before)
        self.run_body(r'''
rm() {
    if [ "$2" = "$LAUNCH_MODE_FILE" ] && [ ! -f "$HOME/mode-remove-failed" ]; then
        printf failed > "$HOME/mode-remove-failed"
        return 91
    fi
    command rm "$@"
}
main new
''', success=False)
        self.assertEqual((mode.read_bytes(), mode.stat().st_mtime_ns, mode.stat().st_mode), before)
        self.assertEqual(self.active.read_text(), "kept\n")
        self.assertEqual(self.fixture.cli("launch-mode").stdout, "true\n")
        self.assertFalse((self.accounts / ".cleanup-recovery").exists())

    def test_successful_new_removes_launch_mode(self):
        self.saved_active()
        mode = self.accounts / ".launch-mode"
        mode.write_text('{"version":1,"account":"kept","yolo":true}\n')
        result = self.run_body("main new")
        self.assertNotIn("YOLO", result.stderr)
        self.assertFalse(mode.exists())
        self.assertEqual(self.fixture.cli("launch-mode").stdout, "false\n")

    def login(self, name="fixture@example.invalid"):
        self.credentials.write_text(json.dumps({**self.shared, "claudeAiOauth": {"accessToken": "fixture-login"}}))
        config = json.loads(self.config.read_text())
        config["oauthAccount"] = {"emailAddress": name}
        self.config.write_text(json.dumps(config))

    def saved_active(self):
        self.accounts.mkdir(parents=True, exist_ok=True)
        self.config.write_text(json.dumps({"userID": "old-id", "mcpServers": {"shared": {}},
                                           "projects": {"old": {}}, "settings": {"keep": True}}))
        self.login()
        (self.accounts / "kept.json").write_bytes(self.config.read_bytes())
        (self.accounts / "kept.credentials").write_text('{"claudeAiOauth":{"accessToken":"prior-backup"}}')
        metadata = self.accounts / ".timezones"
        metadata.mkdir()
        (metadata / "kept").write_text("UTC\n")
        (self.accounts / "kept.surge").write_text('{"Claude":"retained route"}')
        self.active.write_text("kept\n")
        projects = self.home / ".claude/projects"
        projects.mkdir()
        (projects / "history.json").write_text("fixture history")
        (self.home / ".claude/settings.json").write_text("shared settings")

    def seed_sessions(self):
        sessions = self.home / ".claude/sessions"
        sessions.mkdir()
        contents = {
            "synthetic-session.json": b'{"id":"fixture-session","pid":12345}\n',
            "synthetic-session.key": b"\x00\xfffixture-key-bytes\x02\n",
        }
        for name, content in contents.items():
            (sessions / name).write_bytes(content)
        return contents

    def test_fresh_bootstrap_new_fake_login_and_named_save(self):
        for rc in self.rcs:
            rc.chmod(0o444)
        hook = self.hook_snapshot()
        self.assertFalse(self.config.exists())
        self.run_body("main new")
        self.assertFalse(self.active.exists())
        self.assertEqual(list(self.accounts.glob("*.json")), [])
        self.assertFalse(self.credentials.exists())
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.accounts.stat().st_mode & 0o777, 0o700)
        self.assertNotIn("password", self.operations())
        self.assertNotIn("setup-surge", self.operations())
        self.assertNotIn("apply-surge", self.operations())
        self.assertIn("No accounts saved", self.fixture.cli("ls").stdout)
        before = self.snapshot()
        self.assertEqual(self.fixture.cli("timezone", success=False).returncode, 3)
        self.fixture.cli("timezone", "nonexistent", success=False)
        self.assertEqual(self.snapshot(), before)
        # Fake Claude can log in before any profile/timezone is selected.
        self.fixture.executable("claude", r'''#!/bin/bash
command jq -cn --args '{tz:env.TZ,browser:env.BROWSER,args:$ARGS.positional}' -- "$@" >> "$LAUNCHES"
[ "$1" = /login ] || exit 0
printf '{"claudeAiOauth":{"accessToken":"fixture-login"},"mcpOAuth":{"fixture":{"accessToken":"shared"}}}\n' > "$HOME/.claude/.credentials.json"
command jq '.oauthAccount={emailAddress:"fixture@example.invalid"}' "$HOME/.claude.json" > "$HOME/logged-in.json"
mv "$HOME/logged-in.json" "$HOME/.claude.json"
''')
        source = shlex.quote(str(self.home / ".ccacc-shell/hook.sh"))
        self.fixture.interactive("bash", f". {source}\nclaude /login\n", startup=False)
        launched = self.fixture.records(self.fixture.launches)[0]
        self.assertEqual(launched, {"tz": None, "browser": "false", "args": ["/login"]})
        self.assertFalse(self.active.exists())
        self.run_body("main save personal --timezone Asia/Tokyo")
        self.assertEqual(self.active.read_text(), "personal\n")
        self.assertEqual(self.fixture.cli("timezone", "personal").stdout, "Asia/Tokyo\n")
        self.assertFalse(self.pending.exists())
        self.assertEqual([p.name for p in self.accounts.glob("*.json")], ["personal.json"])
        backup = json.loads((self.accounts / "personal.credentials").read_text())
        self.assertEqual(backup, {"claudeAiOauth": {"accessToken": "fixture-login"}})
        self.assertEqual(json.loads(self.credentials.read_text())["mcpOAuth"],
                         {"fixture": {"accessToken": "shared"}})
        self.assertEqual(self.hook_snapshot(), hook)

    def test_active_profile_is_saved_and_stashed_before_clean(self):
        self.saved_active()
        sessions = self.seed_sessions()
        hook = self.hook_snapshot()
        policies = (self.accounts / "kept.surge").read_bytes()
        drafts = self.home / ".claude/feedback/drafts"
        drafts.mkdir(parents=True)
        (drafts / "draft.txt").write_text("saved feedback draft")
        self.run_body("main new")
        self.assertFalse(self.active.exists())
        self.assertEqual([p.name for p in self.accounts.glob("*.json")], ["kept.json"])
        self.assertEqual(json.loads((self.accounts / "kept.json").read_text())["userID"], "old-id")
        self.assertEqual(json.loads((self.accounts / "kept.credentials").read_text()),
                         {"claudeAiOauth": {"accessToken": "fixture-login"}})
        self.assertEqual((self.accounts / "kept/projects/history.json").read_text(), "fixture history")
        self.assertFalse((self.home / ".claude/projects").exists())
        self.assertFalse((self.home / ".claude/sessions").exists())
        self.assertEqual({p.name: p.read_bytes() for p in (self.accounts / "kept/sessions").iterdir()}, sessions)
        self.assertEqual((self.accounts / "kept/feedback-drafts/draft.txt").read_text(), "saved feedback draft")
        self.assertEqual(json.loads(self.credentials.read_text()), self.shared)
        self.assertEqual((self.accounts / "kept.surge").read_bytes(), policies)
        self.assertEqual(self.fixture.cli("timezone", "kept").stdout, "UTC\n")
        self.assertEqual(self.fixture.cli("timezone", success=False).returncode, 3)
        self.assertEqual((self.home / ".claude/settings.json").read_text(), "shared settings")
        self.assertEqual(json.loads(self.config.read_text())["mcpServers"], {"shared": {}})
        operations = self.operations()
        self.assertLess(operations.index("stop"), operations.index("write"))
        self.assertNotIn("setup-surge", operations)
        self.assertNotIn("apply-surge", operations)
        self.assertEqual(self.hook_snapshot(), hook)

    def test_matching_new_archives_sessions_and_restores_them_on_use(self):
        self.saved_active()
        sessions = self.seed_sessions()
        self.run_body("main save kept --timezone UTC")
        # Save writes profile metadata, leaving the live session files in place.
        live = self.home / ".claude/sessions"
        self.assertEqual({p.name: p.read_bytes() for p in live.iterdir()}, sessions)
        self.assertFalse((self.accounts / "kept/sessions").exists())
        self.run_body("main new", stdin="3\n")
        self.assertFalse(live.exists())
        self.assertEqual({p.name: p.read_bytes() for p in (self.accounts / "kept/sessions").iterdir()}, sessions)
        self.run_body("main use kept")
        self.assertEqual({p.name: p.read_bytes() for p in live.iterdir()}, sessions)
        self.assertFalse((self.accounts / "kept/sessions").exists())

    def test_new_sessions_cancellation_conflict_and_rollback_preserve_bytes(self):
        self.saved_active()
        sessions = self.seed_sessions()
        before = self.snapshot()
        self.run_body("main new", success=False, stdin="n\n")
        self.assertEqual(self.snapshot(), before)
        self.run_body("main new", success=False, stdin="q\n")
        self.assertEqual(self.snapshot(), before)
        stash = self.accounts / "kept/sessions"
        stash.mkdir(parents=True)
        (stash / "existing.key").write_bytes(b"synthetic-existing-stash")
        before = self.snapshot()
        self.run_body("main new", success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("stop", self.operations())
        self.assertNotIn("write", self.operations())
        (stash / "existing.key").unlink()
        stash.rmdir()
        self.run_body(r'''
rm() {
    if [ "$2" = "$ACTIVE_FILE" ]; then return 1; fi
    command rm "$@"
}
main new
''', success=False)
        self.assertEqual({p.name: p.read_bytes() for p in (self.home / ".claude/sessions").iterdir()}, sessions)
        self.assertFalse(stash.exists())
        self.assertFalse((self.accounts / ".cleanup-recovery").exists())

    def test_unmatched_and_unnamed_new_clear_synthetic_sessions(self):
        self.saved_active()
        profile = (self.accounts / "kept.json").read_bytes()
        for active in ("mismatched", "unnamed"):
            with self.subTest(active=active):
                self.seed_sessions()
                if active == "mismatched":
                    config = json.loads(self.config.read_text())
                    config["userID"] = "different-unsaved-identity"
                    self.config.write_text(json.dumps(config))
                else:
                    self.active.unlink(missing_ok=True)
                self.run_body("main new", stdin=self.new_input())
                self.assertFalse((self.home / ".claude/sessions").exists())
                self.assertFalse((self.accounts / "kept/sessions").exists())
                self.assertFalse((self.accounts / ".cleanup-recovery").exists())
                self.assertEqual((self.accounts / "kept.json").read_bytes(), profile)

    def test_clean_unnamed_empty_sessions_registry_can_use_saved_profile(self):
        self.saved_active()
        self.run_body("main new")
        (self.home / ".claude/sessions").mkdir()
        self.run_body("main use kept")
        self.assertEqual(self.active.read_text(), "kept\n")

    def test_unnamed_sessions_entries_and_unsafe_registry_still_block_use(self):
        self.saved_active()
        self.run_body("main new")
        self.ops.unlink(missing_ok=True)
        sessions = self.home / ".claude/sessions"
        sessions.mkdir()
        for name in ("session.json", "session.key", ".hidden.key", "nested", "dangling.key"):
            entry = sessions / name
            if name == "nested":
                entry.mkdir()
            elif name == "dangling.key":
                entry.symlink_to("absent-synthetic-session-key")
            else:
                entry.write_bytes(b"synthetic-unowned-session-data")
            before = self.snapshot()
            self.run_body("main use kept --no-yolo", success=False)
            self.assertEqual(self.snapshot(), before)
            if entry.is_dir():
                entry.rmdir()
            else:
                entry.unlink()
        sessions.chmod(0o000)
        try:
            self.run_body("main use kept --no-yolo", success=False)
            self.assertFalse(self.active.exists())
        finally:
            sessions.chmod(0o700)
        sessions.rmdir()
        sessions.symlink_to(self.fixture.fixture, target_is_directory=True)
        self.run_body("main use kept --no-yolo", success=False)
        self.assertFalse(self.active.exists())
        self.assertNotIn("password", self.operations())

    DISCARD_PROMPT = "Discard them and switch to 'kept'? (y/N) "
    NOT_SAVED = "Error: Current login/history is not saved; run 'ccacc save <name>' first"

    def logged_out_leftovers(self):
        # new, then a Claude launch that quits at its login screen.
        self.saved_active()
        self.run_body("main new")
        self.ops.unlink(missing_ok=True)
        leftovers = {}
        for relative in (".claude/backups/claude.json.backup", ".claude/statsig/statsig.stable_id",
                         ".claude/session-env/fixture/env", ".claude/sessions/synthetic.json",
                         "Library/Caches/claude-cli-nodejs/fixture/log.txt"):
            path = self.home / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic logged-out leftover")
            leftovers[relative] = path
        # Claude Code's own debug/latest link is ordinary leftover data.
        debug = self.home / ".claude/debug"
        debug.mkdir()
        (debug / "latest").symlink_to("absent-debug-log")
        return leftovers

    def test_loggedout_leftovers_terminal_yes_discards_with_new_cleanup_and_switches(self):
        leftovers = self.logged_out_leftovers()
        status, stderr, stdout = self.run_pty("main use kept --no-yolo", self.DISCARD_PROMPT, b"y\n")
        self.assertEqual(status, 0, stderr)
        self.assertIn("This session is not logged in, but Claude Code left files behind: ", stderr)
        self.assertIn("~/.claude/backups, ~/.claude/debug, ", stderr)
        self.assertIn("~/Library/Caches/claude-cli-nodejs", stderr)
        self.assertNotIn(str(self.home), stderr)
        self.assertIn("Switched", stdout)
        for path in leftovers.values():
            self.assertFalse(path.exists(), path)
        for name in ("backups", "statsig", "session-env", "sessions", "debug"):
            self.assertFalse((self.home / ".claude" / name).exists(), name)
        self.assertEqual(self.active.read_text(), "kept\n")
        login = json.loads(self.credentials.read_text())
        self.assertEqual(login["claudeAiOauth"], {"accessToken": "fixture-login"})
        self.assertEqual(login["mcpOAuth"], self.shared["mcpOAuth"])
        self.assertEqual(json.loads(self.config.read_text())["oauthAccount"],
                         {"emailAddress": "fixture@example.invalid"})
        self.assertEqual((self.home / ".claude/projects/history.json").read_text(), "fixture history")
        self.assertFalse((self.accounts / ".cleanup-recovery").exists())
        self.assertFalse((self.accounts / "kept/backups").exists())
        # new's machinery: processes stopped, login reset, then the target loaded.
        operations = self.operations()
        # The shared MCP login keeps the item, so the reset is a write, not a delete.
        self.assertIn("stop", operations)
        self.assertEqual(operations.count("write"), 2)
        self.assertLess(operations.index("stop"), operations.index("write"))
        self.assertEqual(self.fixture.cli("launch-mode").stdout, "false\n")

    def test_loggedout_leftovers_terminal_no_or_blank_changes_nothing(self):
        self.logged_out_leftovers()
        for answer in (b"n\n", b"\n", b"no\n"):
            with self.subTest(answer=answer):
                before = self.snapshot()
                status, stderr, stdout = self.run_pty("main use kept --no-yolo", self.DISCARD_PROMPT, answer)
                self.assertNotEqual(status, 0)
                self.assertIn("Cancelled; nothing changed.", stderr)
                self.assertNotIn("Switched", stdout)
                self.assertEqual(self.snapshot(), before)
                self.assertFalse(self.active.exists())
                for operation in ("stop", "write", "delete", "password"):
                    self.assertNotIn(operation, self.operations())

    def test_loggedout_leftovers_without_terminal_refuse_with_new_hint(self):
        self.logged_out_leftovers()
        before = self.snapshot()
        for options in ("", " --no-yolo"):
            result = self.run_body("main use kept" + options, success=False, stdin="y\n")
            self.assertIn("Error: This session is not logged in but has leftover Claude Code files; "
                          "run 'ccacc new' to discard them, then 'ccacc use kept'", result.stderr)
            self.assertNotIn("Discard them", result.stderr)
            self.assertEqual(self.snapshot(), before)
            self.assertFalse(self.active.exists())
            for operation in ("stop", "write", "delete", "password"):
                self.assertNotIn(operation, self.operations())

    def test_unsaved_login_with_leftovers_keeps_original_refusal(self):
        self.logged_out_leftovers()
        self.login("unsaved@example.invalid")
        before = self.snapshot()
        result = self.run_body("main use kept --no-yolo", success=False)
        self.assertIn(self.NOT_SAVED, result.stderr)
        self.assertEqual(self.snapshot(), before)
        status, stderr, _ = self.run_pty("main use kept --no-yolo")
        self.assertNotEqual(status, 0)
        self.assertIn(self.NOT_SAVED, stderr)
        self.assertNotIn("Discard them", stderr)
        self.assertEqual(self.snapshot(), before)
        # A Keychain-only login (no oauthAccount in the config) is still a login.
        self.credentials.unlink()
        self.run_body("main new", stdin="yes\n")
        self.ops.unlink(missing_ok=True)
        self.logged_out_leftovers_again()
        before = self.snapshot()
        status, stderr, _ = self.run_pty(
            "read_credentials() { printf '{\"claudeAiOauth\":{\"accessToken\":\"unsaved\"}}'; }; main use kept --no-yolo")
        self.assertNotEqual(status, 0)
        self.assertIn(self.NOT_SAVED, stderr)
        self.assertNotIn("Discard them", stderr)
        self.assertEqual(self.snapshot(), before)
        for operation in ("stop", "write", "delete", "password"):
            self.assertNotIn(operation, self.operations())

    def logged_out_leftovers_again(self):
        statsig = self.home / ".claude/statsig"
        statsig.mkdir(parents=True, exist_ok=True)
        (statsig / "statsig.stable_id").write_text("synthetic logged-out leftover")

    def test_loggedout_unsafe_sessions_registry_keeps_original_refusal(self):
        self.logged_out_leftovers()
        sessions = self.home / ".claude/sessions"
        cases = []
        link = sessions / "dangling.key"
        cases.append(("link", lambda: link.symlink_to("absent-synthetic-session-key"), link.unlink))
        cases.append(("unreadable", lambda: sessions.chmod(0o000), lambda: sessions.chmod(0o700)))
        nested = sessions / "nested"
        def unreadable_nested():
            nested.mkdir()
            nested.chmod(0o300)
        def restore_nested():
            nested.chmod(0o700)
            nested.rmdir()
        cases.append(("unreadable nested", unreadable_nested, restore_nested))
        for label, apply, restore in cases:
            with self.subTest(case=label):
                apply()
                try:
                    before = self.snapshot()
                    result = self.run_body("main use kept --no-yolo", success=False)
                    self.assertIn(self.NOT_SAVED, result.stderr)
                    status, stderr, _ = self.run_pty("main use kept --no-yolo")
                    self.assertNotEqual(status, 0)
                    self.assertIn(self.NOT_SAVED, stderr)
                    self.assertNotIn("Discard them", stderr)
                    self.assertEqual(self.snapshot(), before)
                    self.assertFalse(self.active.exists())
                finally:
                    restore()
        shutil.rmtree(sessions)
        sessions.symlink_to(self.fixture.fixture, target_is_directory=True)
        status, stderr, _ = self.run_pty("main use kept --no-yolo")
        self.assertNotEqual(status, 0)
        self.assertIn(self.NOT_SAVED, stderr)
        self.assertFalse(self.active.exists())
        for operation in ("stop", "write", "delete", "password"):
            self.assertNotIn(operation, self.operations())

    def test_loggedout_discard_failure_rolls_back_and_keeps_selection(self):
        leftovers = self.logged_out_leftovers()
        self.selection.write_text('{"version":1,"timezone":"Asia/Tokyo"}\n')
        contents = {relative: path.read_bytes() for relative, path in leftovers.items()}
        config = self.config.read_bytes()
        status, stderr, stdout = self.run_pty("reset_account_state() { return 1; }; main use kept --no-yolo",
                                              self.DISCARD_PROMPT, b"yes\n")
        self.assertNotEqual(status, 0)
        self.assertIn("previous account, credentials and history restored", stderr)
        self.assertNotIn("Switched", stdout)
        self.assertEqual({relative: path.read_bytes() for relative, path in leftovers.items()}, contents)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertFalse(self.active.exists())
        self.assertFalse((self.accounts / ".cleanup-recovery").exists())
        self.assertEqual(self.fixture.cli("timezone").stdout, "Asia/Tokyo\n")
        self.assertNotIn("password", self.operations())

    def test_loggedout_discard_keeps_selection_when_later_switch_fails(self):
        self.logged_out_leftovers()
        self.selection.write_text('{"version":1,"timezone":"Asia/Tokyo"}\n')
        status, _, stdout = self.run_pty("load_account() { return 1; }; main use kept --no-yolo",
                                         self.DISCARD_PROMPT, b"y\n")
        self.assertNotEqual(status, 0)
        self.assertNotIn("Switched", stdout)
        self.assertFalse((self.home / ".claude/statsig").exists())
        self.assertFalse(self.active.exists())
        self.assertEqual(self.fixture.cli("timezone").stdout, "Asia/Tokyo\n")

    def test_login_while_stopping_claude_is_never_discarded(self):
        leftovers = self.logged_out_leftovers()
        contents = {relative: path.read_bytes() for relative, path in leftovers.items()}
        body = r"""
cleanup_stop_processes() {
    stop_claude
    printf '{"claudeAiOauth":{"accessToken":"late-login"}}' > "$STRAY_CREDENTIALS_FILE"
}
main use kept --no-yolo
"""
        status, stderr, stdout = self.run_pty(body, self.DISCARD_PROMPT, b"y\n")
        self.assertNotEqual(status, 0)
        self.assertIn("logged in while preparing to discard its files; nothing discarded", stderr)
        self.assertNotIn("Switched", stdout)
        self.assertEqual({relative: path.read_bytes() for relative, path in leftovers.items()}, contents)
        self.assertEqual(json.loads(self.credentials.read_text()), {"claudeAiOauth": {"accessToken": "late-login"}})
        self.assertFalse(self.active.exists())
        self.assertFalse((self.accounts / ".cleanup-recovery").exists())

    def test_save_records_account_caches_and_new_removes_them(self):
        self.saved_active()
        caches = {
            "cachedArtifactRoster": {"accountWuid": "fixture-account", "orgWuid": "fixture-org", "artifacts": []},
            "cachedUsageUtilization": {"orgWuid": "fixture-org", "utilization": 42},
        }
        config = json.loads(self.config.read_text())
        config.update(caches)
        self.config.write_text(json.dumps(config))
        self.run_body("main save kept --timezone UTC")
        saved = (self.accounts / "kept.json").read_bytes()
        for key, value in caches.items():
            self.assertEqual(json.loads(saved)[key], value)
        self.run_body("main new")
        cleaned = json.loads(self.config.read_text())
        for key in caches:
            self.assertNotIn(key, cleaned)
        self.assertEqual((self.accounts / "kept.json").read_bytes(), saved)
        self.assertEqual(cleaned["mcpServers"], config["mcpServers"])
        self.assertEqual(cleaned["settings"], config["settings"])

    def test_save_new_use_roundtrip_preserves_previously_reset_only_fields(self):
        self.saved_active()
        keys = (
            "additionalModelCostsCache additionalModelOptionsAnsweredAt announcementImpressions "
            "apiCreditLinkStatusCache autoCompactWindowsCache bridgeOauthDeadExpiresAt "
            "bridgeOauthDeadFailCount cachedChromeExtensionInstalled cachedExperimentData "
            "cachedExperimentFeatures cachedExtraUsageDisabledReason claudeAiMcpEverConnected "
            "githubWebConnectionStatusCache groveChoiceSeenAt hasAvailableSubscription "
            "hasRemoteEnvironment mcpNeedsAuthNoticed modelAccessCache orgModelDefaultCache "
            "penguinModeOrgEnabled promoStartupSeenCount promoStartupStatusCache "
            "rcLongTurnNudgeSeenCount rcLongTurnNudgeSeenKey seenNotifications tipsHistoryByCommand"
        ).split()
        values = [False, 0, {}, [], "fixture-state", {"fixture": [False, 0, "fixture-org"]}]
        state = {key: values[index % len(values)] for index, key in enumerate(keys)}
        config = json.loads(self.config.read_text())
        config.update(state)
        self.config.write_text(json.dumps(config))
        self.run_body("main save kept --timezone UTC")
        saved = (self.accounts / "kept.json").read_bytes()
        for key, value in state.items():
            self.assertEqual(json.loads(saved)[key], value)
        self.run_body("main new")
        cleaned = json.loads(self.config.read_text())
        for key in keys:
            self.assertNotIn(key, cleaned)
        self.assertEqual((self.accounts / "kept.json").read_bytes(), saved)
        self.run_body("main use kept")
        restored = json.loads(self.config.read_text())
        for key, value in state.items():
            self.assertEqual(restored[key], value)
        self.assertEqual(restored["mcpServers"], config["mcpServers"])
        self.assertEqual(restored["settings"], config["settings"])
        self.assertEqual(json.loads(self.credentials.read_text())["mcpOAuth"], self.shared["mcpOAuth"])

    def test_new_resets_onboarding_and_use_restores_saved_state(self):
        self.saved_active()
        for completed in (True, False):
            with self.subTest(completed=completed):
                config = json.loads(self.config.read_text())
                config["hasCompletedOnboarding"] = completed
                self.config.write_text(json.dumps(config))
                self.run_body("main save kept --timezone UTC")
                saved = (self.accounts / "kept.json").read_bytes()
                self.assertIs(json.loads(saved)["hasCompletedOnboarding"], completed)
                self.run_body("main new")
                self.assertIs(json.loads(self.config.read_text())["hasCompletedOnboarding"], False)
                self.assertEqual((self.accounts / "kept.json").read_bytes(), saved)
                self.run_body("main use kept")
                self.assertIs(json.loads(self.config.read_text())["hasCompletedOnboarding"], completed)
        config = json.loads(self.config.read_text())
        config.pop("hasCompletedOnboarding")
        self.config.write_text(json.dumps(config))
        self.run_body("main new")
        self.assertIs(json.loads(self.config.read_text())["hasCompletedOnboarding"], False)

    def test_saved_account_uuid_can_prove_history_ownership_without_user_id(self):
        self.saved_active()
        config = json.loads(self.config.read_text())
        config.pop("userID")
        config["oauthAccount"]["accountUuid"] = "same-saved-account"
        self.config.write_text(json.dumps(config))
        (self.accounts / "kept.json").write_bytes(self.config.read_bytes())
        self.run_body("main new")
        self.assertEqual((self.accounts / "kept/projects/history.json").read_text(), "fixture history")
        self.assertFalse(self.active.exists())

    def test_clean_preserves_meaningful_project_mcp_and_false_selections(self):
        self.saved_active()
        project_mcp = {
            "mcpServers": {"local": {"command": "fixture-server"}},
            "disabledMcpServers": ["disabled"],
            "enabledMcpServers": ["enabled"],
            "enabledMcpjsonServers": ["selected"],
            "disabledMcpjsonServers": ["unselected"],
            "enableAllProjectMcpServers": False,
        }
        config = json.loads(self.config.read_text())
        config["projects"] = {
            "/fixture/keep": {**project_mcp, "history": ["private prompt"], "hasTrustDialogAccepted": True},
            "/fixture/false": {"enableAllProjectMcpServers": False, "lastCost": 42},
            "/fixture/drop": {"mcpServers": {}, "enabledMcpServers": [], "hasTrustDialogAccepted": True},
            "/fixture/null": {"enableAllProjectMcpServers": None},
            "/fixture/malformed": "ignored malformed record",
        }
        self.config.write_text(json.dumps(config))
        (self.accounts / "kept.json").write_bytes(self.config.read_bytes())
        self.run_body("main new")
        cleaned = json.loads(self.config.read_text())
        self.assertEqual(cleaned["projects"], {
            "/fixture/keep": project_mcp,
            "/fixture/false": {"enableAllProjectMcpServers": False},
        })
        self.assertEqual(cleaned["mcpServers"], {"shared": {}})
        self.assertEqual(json.loads(self.credentials.read_text()), self.shared)
        self.assertEqual(json.loads((self.accounts / "kept.json").read_text())["projects"], config["projects"])

    def test_matching_login_is_saved_to_active_profile_without_asking(self):
        self.saved_active()
        surge = (self.accounts / "kept.surge").read_bytes()
        result = self.run_body("main new")
        self.assertNotIn("Have you already run", result.stderr)
        self.assertIn("will be saved before cleanup", result.stderr)
        self.assertIn("Saved current login to profile 'kept'", result.stderr)
        self.assertEqual(json.loads((self.accounts / "kept.credentials").read_text()),
                         {"claudeAiOauth": {"accessToken": "fixture-login"}})
        self.assertEqual(json.loads((self.accounts / "kept.json").read_text())["oauthAccount"],
                         {"emailAddress": "fixture@example.invalid"})
        self.assertEqual((self.accounts / "kept.surge").read_bytes(), surge)
        self.assertFalse(self.active.exists())
        operations = self.operations()
        # Backups migrate before Claude stops; the login is read for the save only after it.
        self.assertLess(operations.index("password"), operations.index("stop"))
        self.assertEqual(operations[operations.index("stop") + 1], "read")

    def test_failed_save_cleans_nothing(self):
        self.saved_active()
        before = self.snapshot()
        result = self.run_body("save_account() { return 98; }; main new", success=False)
        self.assertIn("Could not save profile 'kept'; nothing cleaned", result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("write", self.operations())

    def test_mismatched_or_unowned_login_asks_and_never_saves(self):
        self.saved_active()
        profiles = {p: p.read_bytes() for p in self.accounts.glob("kept.*")}
        self.mismatch_active()
        result = self.run_body(r'''
save_account() { printf 'unexpected-save' >> "$SESSION_OPERATIONS"; return 98; }
migrate_encrypted_backups() { printf 'unexpected-password' >> "$SESSION_OPERATIONS"; return 98; }
main new
''', stdin="yes\n")
        self.assertIn("Have you already run", result.stderr)
        self.assertEqual({p: p.read_bytes() for p in profiles}, profiles)
        self.assertFalse(self.active.exists())
        self.assertNotIn("unexpected-save", self.operations())
        self.assertNotIn("unexpected-password", self.operations())

    def test_logged_out_new_cleans_without_asking(self):
        self.saved_active()
        self.run_body("main new")
        self.ops.unlink(missing_ok=True)
        profiles = {p: p.read_bytes() for p in self.accounts.glob("kept.*")}
        result = self.run_body("main new")
        self.assertIn("Not logged in; cleaning without a backup.", result.stderr)
        self.assertNotIn("Have you already run", result.stderr)
        self.assertNotIn("password", self.operations())
        self.assertEqual({p: p.read_bytes() for p in profiles}, profiles)

    def logout_keeping_active(self):
        credentials = json.loads(self.credentials.read_text())
        credentials.pop("claudeAiOauth")
        self.credentials.write_text(json.dumps(credentials))
        config = json.loads(self.config.read_text())
        config.pop("oauthAccount")
        self.config.write_text(json.dumps(config))

    def test_logged_out_with_active_profile_asks_and_never_saves(self):
        self.saved_active()
        self.logout_keeping_active()
        before = self.snapshot()
        result = self.run_body("main new", success=False, stdin="n\n")
        self.assertIn("Not logged in, but profile 'kept' is active", result.stderr)
        self.assertIn("Cleanup cancelled", result.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("stop", self.operations())
        profiles = {p: p.read_bytes() for p in self.accounts.glob("kept.*")}
        result = self.run_body(r'''
save_account() { printf 'unexpected-save' >> "$SESSION_OPERATIONS"; return 98; }
main new
''', stdin="yes\n")
        self.assertIn("Cleaned current account", result.stdout)
        self.assertNotIn("unexpected-save", self.operations())
        self.assertNotIn("password", self.operations())
        self.assertEqual({p: p.read_bytes() for p in profiles}, profiles)
        self.assertFalse(self.active.exists())

    def test_surge_command_repicks_and_applies_for_the_active_profile(self):
        self.saved_active()
        self.run_body("find_surge() { :; }\nsurge_groups() { printf '{}'; }\nmain surge kept")
        self.assertEqual(self.operations(), ["setup-surge", "apply-surge"])

    def test_cancellation_precedes_credentials_prompts_processes_and_writes(self):
        self.saved_active()
        self.mismatch_active()
        before = self.snapshot()
        for answer in ("", "\n", "n\n", "no\n", "YES\n", "sure\n"):
            result = self.run_body("main new", success=False, stdin=answer)
            self.assertIn("does not match active profile 'kept'", result.stderr)
            self.assertIn("Cleanup cancelled", result.stderr)
            self.assertNotIn("Choose timezone", result.stderr)
            self.assertEqual(self.operations(), [])
            self.assertEqual(self.snapshot(), before)

    def test_confirmed_unsaved_login_is_discarded_without_named_profile(self):
        self.accounts.mkdir(parents=True)
        self.config.write_text("{}")
        self.login()
        self.run_body("main new", stdin="Y\n")
        self.assertFalse(self.active.exists())
        self.assertEqual(list(self.accounts.glob("*.json")), [])
        self.assertEqual(json.loads(self.credentials.read_text()), self.shared)

    def test_mismatched_active_identity_never_overwrites_profile_history(self):
        self.saved_active()
        config = json.loads(self.config.read_text())
        config["userID"] = "different-unsaved-login"
        self.config.write_text(json.dumps(config))
        stash = self.accounts / "kept/projects"
        stash.mkdir(parents=True)
        (stash / "saved.txt").write_text("existing saved history")
        profile = (self.accounts / "kept.json").read_bytes()
        self.run_body("main new", stdin="yes\n")
        self.assertEqual((stash / "saved.txt").read_text(), "existing saved history")
        self.assertFalse((stash / "history.json").exists())
        self.assertEqual((self.accounts / "kept.json").read_bytes(), profile)
        self.assertFalse((self.home / ".claude/projects").exists())

    def test_loggedout_remnants_are_cleaned_with_optional_timezone_selection(self):
        self.accounts.mkdir(parents=True)
        self.config.write_text('{"projects":{"old":{}},"mcpServers":{"shared":{}}}')
        remnants = self.home / ".claude/projects"
        remnants.mkdir()
        (remnants / "unowned.txt").write_text("retain this unowned history")
        self.pending.write_text("Europe/Paris\n")
        result = self.run_body("main new", stdin="8\nEurope/Paris\n")
        self.assertIn("Choose timezone", result.stderr)
        self.assertEqual(self.fixture.cli("timezone").stdout, "Europe/Paris\n")
        self.assertFalse(self.pending.exists())
        self.assertFalse(remnants.exists())
        hook = self.hook_snapshot()
        self.run_body("main new")
        self.assertEqual(self.hook_snapshot(), hook)
        self.run_body("main new")
        self.assertEqual(self.fixture.cli("timezone", success=False).returncode, 3)
        self.assertEqual([p.name for p in self.accounts.glob("*.json")], [])

    def test_invalid_new_arguments_never_mutate_and_new_needs_no_hook(self):
        before = self.snapshot()
        for command in ("new old-name", "new ''", "new --alias alias", "new --timezone", "new --timezone UTC", "new --timezone UTC --timezone UTC",
                        "new --timezone Invalid/Zone", "new old-name --timezone UTC"):
            self.run_body("main " + command, success=False)
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(self.operations(), [])
        (self.home / ".ccacc-shell/hook.sh").unlink()
        result = self.run_body("new_command")
        self.assertIn("Choose timezone", result.stderr)
        self.assertIn("Cleaned current account", result.stdout)
        self.assertFalse((self.home / ".ccacc-shell/hook.sh").exists())
        self.assertFalse(self.pending.exists())
        self.run_body("new_command", stdin="8\nEurope/Paris\n")
        self.assertEqual(self.fixture.cli("timezone").stdout, "Europe/Paris\n")
        self.assertFalse((self.home / ".ccacc-shell/hook.sh").exists())

    def test_legacy_pending_is_ignored_by_unnamed_getter_and_launch(self):
        self.run_body("main new")
        source = shlex.quote(str(self.home / ".ccacc-shell/hook.sh"))
        for content in ("", "Invalid/Zone\n", "UTC\nAsia/Tokyo\n", "UTC\n\n"):
            self.pending.write_text(content)
            before = self.snapshot()
            result = self.fixture.cli("timezone", success=False)
            self.assertEqual((result.returncode, result.stdout), (3, ""))
            result = self.fixture.interactive("bash", f". {source}\nclaude /login\nexit 0\n", startup=False)
            self.assertNotIn("ccacc: cannot read", result.stderr)
            self.assertIsNone(self.fixture.records(self.fixture.launches)[-1]["tz"])
            self.assertEqual(self.snapshot(), before)

    def test_explicit_zone_wins_legacy_pending_and_failed_activation_keeps_legacy(self):
        self.run_body("main new")
        self.login()
        self.pending.write_text("Asia/Tokyo\n")
        operations = self.operations()
        self.run_body('mkdir "$HOME/activation-directory"; ACTIVE_FILE="$HOME/activation-directory"; main save chosen --timezone UTC', success=False)
        self.assertTrue(self.pending.exists())
        self.assertFalse(self.active.exists())
        self.assertFalse((self.accounts / "chosen.credentials").exists())
        self.assertFalse((self.accounts / "chosen.json").exists())
        self.assertFalse((self.accounts / ".timezones/chosen").exists())
        self.assertEqual(self.operations(), operations)
        self.run_body("main save chosen --timezone UTC")
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.fixture.cli("timezone").stdout, "UTC\n")

    def test_active_zone_is_not_inferred_for_new(self):
        self.saved_active()
        self.fixture.env["TZ"] = "Australia/Sydney"
        self.run_body("main new", stdin="\n")
        self.assertEqual(self.fixture.cli("timezone", success=False).returncode, 3)
        self.assertEqual(self.fixture.cli("timezone", "kept").stdout, "UTC\n")
        self.assertFalse(self.active.exists())

    def test_new_preset_custom_default_and_eof_reset_selection(self):
        self.saved_active()
        for answer, expected in (("3\n", "Asia/Tokyo"), ("8\nEurope/Paris\n", "Europe/Paris"),
                                 ("\n", None), ("1\n", "UTC"), ("", None),
                                 ("2\n", "Asia/Shanghai"), ("8\n\n", None),
                                 ("3\n", "Asia/Tokyo"), ("8\n", None)):
            with self.subTest(answer=answer):
                self.run_body("main new", stdin=answer)
                self.assertFalse(self.active.exists())
                result = self.fixture.cli("timezone", success=expected is not None)
                self.assertEqual((result.returncode, result.stdout),
                                 (0, expected + "\n") if expected else (3, ""))
                if expected:
                    self.assertEqual(json.loads(self.selection.read_text()), {"version": 1, "timezone": expected})
                    self.assertEqual(self.selection.stat().st_mode & 0o777, 0o600)
                else:
                    self.assertFalse(self.selection.exists())
                self.assertEqual(self.fixture.cli("launch-mode").stdout, "false\n")
        self.assertEqual(self.fixture.cli("timezone", "kept").stdout, "UTC\n")

    def test_selected_unnamed_session_ignores_stale_yolo_record(self):
        self.run_body("main new", stdin="3\n")
        (self.accounts / ".launch-mode").write_text('{"version":1,"account":"kept","yolo":true}')
        self.assertEqual(self.fixture.cli("timezone").stdout, "Asia/Tokyo\n")
        result = self.fixture.cli("launch-mode")
        self.assertEqual((result.stdout, result.stderr), ("false\n", ""))

    def test_invalid_and_cancelled_timezone_precede_all_account_mutations(self):
        self.saved_active()
        before = self.snapshot()
        for answer in ("q\n", "Q\n", "9\n", "UTC\n", "8\nInvalid/Zone\n", "\x1b\n", "8\n../UTC\n"):
            with self.subTest(answer=answer):
                self.run_body("main new", success=False, stdin=answer)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.operations(), [])

    def test_selected_timezone_reaches_login_in_bash_and_zsh_without_changing_parent(self):
        # Verify installed-hook validation against unchanged generated v3 bytes.
        self.fixture.env.update(TZ="America/New_York", BROWSER="parent-browser")
        for shell in ("bash", "zsh"):
            with self.subTest(shell=shell):
                self.fixture.startup(shell)
                self.fixture.cli("configure-shell")
                hook = self.hook_snapshot()
                for answer, expected in (("3\n", "Asia/Tokyo"), ("8\nEurope/Paris\n", "Europe/Paris"), ("\n", None)):
                    self.run_body("main new; require_shell_hook", stdin=answer)
                    source = shlex.quote(str(self.home / ".ccacc-shell/hook.sh"))
                    parent = self.home / "parent-env.json"
                    code = (f". {source}\nclaude /login\n"
                            'jq -cn \'{tz:env.TZ,browser:env.BROWSER}\' > "$HOME/parent-env.json"\n')
                    self.fixture.interactive(shell, code, startup=False)
                    launch = self.fixture.records(self.fixture.launches)[-1]
                    self.assertEqual((launch["tz"], launch["browser"], launch["args"]),
                                     (expected, "false", ["/login"]))
                    self.assertEqual(json.loads(parent.read_text()),
                                     {"tz": "America/New_York", "browser": "parent-browser"})
                    self.assertEqual(self.hook_snapshot(), hook)
                    self.assertEqual(self.fixture.cli("launch-mode").stdout, "false\n")

    def test_save_uses_explicit_zone_and_retains_pending_on_failure(self):
        self.run_body("main new", stdin="3\n")
        self.login()
        before = self.selection.read_bytes()
        for failure in ("migrate_encrypted_backups() { return 1; }", "save_account() { return 1; }",
                        'setup_surge() { return 1; }'):
            with self.subTest(failure=failure):
                self.run_body(failure + "; main save chosen --timezone UTC", success=False)
                self.assertEqual(self.selection.read_bytes(), before)
                self.assertEqual(self.fixture.cli("timezone").stdout, "Asia/Tokyo\n")
                self.assertFalse(self.active.exists())
                self.assertFalse((self.accounts / "chosen.json").exists())
                self.fixture.cli("timezone", "chosen", success=False)
        result = self.run_body("main save chosen --timezone UTC", stdin="")
        self.assertNotIn("Choose timezone", result.stderr)
        self.assertEqual(self.fixture.cli("timezone").stdout, "UTC\n")
        self.assertFalse(self.selection.exists())
        self.run_body("main new", stdin="2\n")
        self.login()
        self.run_body("main save other --timezone Europe/Paris")
        self.assertEqual(self.fixture.cli("timezone").stdout, "Europe/Paris\n")
        self.assertFalse(self.selection.exists())

    def test_selected_unnamed_login_then_first_save_requires_its_own_picker(self):
        self.run_body("main new", stdin="8\nEurope/Paris\n")
        source = shlex.quote(str(self.home / ".ccacc-shell/hook.sh"))
        self.fixture.interactive("bash", f". {source}\nclaude /login\n", startup=False)
        launch = self.fixture.records(self.fixture.launches)[-1]
        self.assertEqual((launch["tz"], launch["browser"], launch["args"]),
                         ("Europe/Paris", "false", ["/login"]))
        self.login()
        before = self.snapshot()
        for answer in ("", "\n", "9\n"):
            result = self.run_body("main save first", stdin=answer, success=False)
            self.assertIn("Choose timezone", result.stderr)
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(self.fixture.cli("timezone").stdout, "Europe/Paris\n")
        result = self.run_body("main save first", stdin="3\n")
        self.assertIn("Choose timezone", result.stderr)
        self.assertEqual(self.fixture.cli("timezone").stdout, "Asia/Tokyo\n")
        self.assertFalse(self.selection.exists())

    def test_use_retains_selection_on_failure_and_clears_on_success(self):
        self.saved_active()
        self.run_body("main new", stdin="3\n")
        before = self.selection.read_bytes()
        for failure in ("migrate_encrypted_backups() { return 1; }", "load_account() { return 1; }",
                        "unstash_paths() { return 1; }", "apply_surge() { return 1; }"):
            self.run_body(failure + "; main use kept", success=False)
            self.assertEqual(self.selection.read_bytes(), before)
            # Some existing use failure paths already activate the target; its
            # named timezone still wins a retained stale unnamed selection.
            if self.active.exists():
                self.assertEqual(self.fixture.cli("timezone").stdout, "UTC\n")
            self.run_body("main new", stdin=self.new_input("3\n"))
        self.run_body("main use kept")
        self.assertFalse(self.selection.exists())
        self.assertEqual(self.fixture.cli("timezone").stdout, "UTC\n")

    def test_named_zone_and_save_ignore_stale_unnamed_zone(self):
        self.saved_active()
        self.selection.write_text('{"version":1,"timezone":"Asia/Tokyo"}\n')
        self.assertEqual(self.fixture.cli("timezone").stdout, "UTC\n")
        self.run_body("main save kept")
        self.assertEqual(self.fixture.cli("timezone").stdout, "UTC\n")
        self.assertFalse(self.selection.exists())

    def test_malformed_session_metadata_blocks_getter_launch_and_mutations(self):
        self.run_body("main new")
        for content in ("", "{}", "[]", '{"version":2,"timezone":"UTC"}',
                        '{"version":1,"timezone":"UTC","extra":true}',
                        '{"version":1,"timezone":"Invalid/Zone"}',
                        '{"version":1,"timezone":"UTC\\n"}',
                        '{"version":1,"timezone":null}',
                        '{"version":1,"timezone":"UTC"} {}'):
            with self.subTest(content=content):
                self.selection.write_text(content)
                before = self.snapshot()
                operations = self.operations()
                result = self.fixture.cli("timezone", success=False)
                self.assertEqual((result.returncode, result.stdout), (1, ""))
                for command in ("main new", "main save first --timezone UTC"):
                    self.run_body(command, success=False)
                    self.assertEqual(self.snapshot(), before)
                    self.assertEqual(self.operations(), operations)
                source = shlex.quote(str(self.home / ".ccacc-shell/hook.sh"))
                self.fixture.interactive("bash", f". {source}\nclaude /login\nexit 0\n", startup=False)
                self.assertFalse(self.fixture.launches.exists())

    def test_unsafe_and_readonly_selection_fail_before_cleanup(self):
        self.run_body("main new", stdin="3\n")
        saved = self.selection.read_bytes()
        self.selection.chmod(0o400)
        before = self.snapshot()
        for command in ("main new", "main save first --timezone UTC"):
            self.run_body(command, success=False)
            self.assertEqual(self.snapshot(), before)
        self.selection.chmod(0o600)
        self.selection.unlink()
        outside = self.fixture.fixture / "external-selection"
        outside.write_bytes(saved)
        self.selection.symlink_to(outside)
        before = self.snapshot()
        for command in ("main new", "main save first --timezone UTC"):
            self.run_body(command, success=False)
            self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.fixture.cli("timezone", success=False).returncode, 1)
        self.assertEqual(outside.read_bytes(), saved)

    def test_unnamed_getter_rejects_symlinked_parent_and_nonregular_metadata(self):
        self.run_body("main new", stdin="3\n")
        self.selection.unlink()
        self.selection.mkdir()
        self.assertEqual(self.fixture.cli("timezone", success=False).returncode, 1)
        self.selection.rmdir()
        self.selection.write_text('{"version":1,"timezone":"Asia/Tokyo"}')
        real_accounts = self.home / ".claude/moved-accounts"
        self.accounts.rename(real_accounts)
        self.accounts.symlink_to(real_accounts, target_is_directory=True)
        self.assertEqual(self.fixture.cli("timezone", success=False).returncode, 1)
        before = self.snapshot()
        self.run_body("main new", success=False)
        self.assertEqual(self.snapshot(), before)

    def test_new_metadata_publish_failure_restores_previous_selection(self):
        self.run_body("main new", stdin="3\n")
        before = self.selection.read_bytes(), self.selection.stat().st_mtime_ns
        self.run_body(r'''
mv() {
    if [ "$1" = "$CLEANUP_RECOVERY_DIR/selected-session" ]; then return 1; fi
    command mv "$@"
}
main new
''', success=False, stdin="2\n")
        self.assertEqual((self.selection.read_bytes(), self.selection.stat().st_mtime_ns), before)
        self.assertEqual(self.fixture.cli("timezone").stdout, "Asia/Tokyo\n")
        self.assertFalse((self.accounts / ".cleanup-recovery").exists())

    def test_metadata_rollback_failure_retains_recovery_and_blocks_launch(self):
        self.run_body("main new", stdin="3\n")
        self.run_body(r'''
mv() {
    if [ "$1" = "$CLEANUP_RECOVERY_DIR/selected-session" ]; then return 1; fi
    command mv "$@"
}
cp() {
    if [ "$2" = "$CLEANUP_RECOVERY_DIR/unnamed-session" ]; then return 1; fi
    command cp "$@"
}
main new
''', success=False, stdin="2\n")
        recovery = self.accounts / ".cleanup-recovery"
        self.assertTrue(recovery.exists())
        self.assertEqual(json.loads((recovery / "unnamed-session").read_text())["timezone"], "Asia/Tokyo")
        self.assertEqual(self.fixture.cli("timezone", success=False).returncode, 1)
        self.assertEqual(self.fixture.cli("launch-mode").stdout, "false\n")
        before = self.snapshot()
        for command in ("main new", "main save first --timezone UTC"):
            self.run_body(command, success=False)
            self.assertEqual(self.snapshot(), before)

    def test_stop_and_stash_conflicts_do_not_clear_login(self):
        self.saved_active()
        before = self.snapshot()
        self.run_body("stop_claude() { return 1; }; main new", success=False)
        self.assertEqual(self.snapshot(), before)
        stash = self.accounts / "kept/projects"
        stash.mkdir(parents=True)
        (stash / "previous.txt").write_text("must not overwrite")
        before = self.snapshot()
        self.run_body("main new", success=False)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.pending.exists())

    def test_readonly_config_and_accounts_fail_before_cleanup(self):
        self.saved_active()
        for path, mode in ((self.config, 0o444), (self.credentials, 0o444), (self.accounts, 0o555)):
            old_mode = path.stat().st_mode & 0o777
            path.chmod(mode)
            try:
                before = self.snapshot()
                result = self.run_body("main new", success=False)
                self.assertNotIn("Cleaned current account", result.stdout)
                self.assertEqual(self.snapshot(), before)
                self.assertNotIn("stop", self.operations())
                self.assertNotIn("write", self.operations())
            finally:
                path.chmod(old_mode)

    def test_readonly_stash_parent_fails_before_cleanup(self):
        self.saved_active()
        stash = self.accounts / "kept"
        stash.mkdir()
        stash.chmod(0o555)
        try:
            before = self.snapshot()
            self.run_body("main new", success=False)
            self.assertEqual(self.snapshot(), before)
            self.assertNotIn("stop", self.operations())
        finally:
            stash.chmod(0o700)

    def test_reset_copy_failure_is_propagated(self):
        self.saved_active()
        before = self.config.read_bytes()
        self.run_body('cp() { return 1; }; if reset_account_state; then exit 99; fi')
        self.assertEqual(self.config.read_bytes(), before)

    def test_late_cleanup_failures_restore_history_credentials_and_markers(self):
        self.saved_active()
        self.run_body("save_account kept")
        config = self.config.read_bytes()
        credentials = self.credentials.read_bytes()
        profiles = {p: p.read_bytes() for p in self.accounts.glob("kept.*")}
        recovery_copy = self.home / ".claude_backups/claude_dir_20261031_010101/history"
        recovery_copy.parent.mkdir(parents=True)
        recovery_copy.write_text("existing cleaner recovery history")
        failures = (
            'failed_legacy=no; rm() { if [ "$2" = "$LEGACY_PENDING_TIMEZONE_FILE" ] && [ "$failed_legacy" != yes ]; '
            'then failed_legacy=yes; return 1; fi; command rm "$@"; }',
            'reset_account_state() { printf "{}" > "$CLAUDE_JSON"; return 1; }',
            # The real reset helper runs under !, where Bash disables errexit.
            'cp() { if [ "$1" != -p ] && [ "$2" = "$CLAUDE_JSON" ]; then return 1; fi; command cp "$@"; }',
            # Pending was already replaced when the last metadata write fails.
            'rm() { if [ "$2" = "$ACTIVE_FILE" ]; then return 1; fi; command rm "$@"; }',
            # A failed write can have changed the store; rollback must still run.
            'write_credentials() { printf "%s\\n" "$1" > "$STRAY_CREDENTIALS_FILE"; '
            '[ "$1" != "$(printf "%s" "$1" | jq -c "del(.claudeAiOauth)")" ]; }',
        )
        for failure in failures:
            with self.subTest(failure=failure):
                result = self.run_body(failure + '; main new', success=False)
                self.assertIn("restored", result.stderr)
                self.assertNotIn("Cleaned current account", result.stdout)
                self.assertEqual(self.config.read_bytes(), config)
                self.assertEqual(self.credentials.read_bytes(), credentials)
                self.assertEqual(self.active.read_text(), "kept\n")
                self.assertFalse(self.pending.exists())
                self.assertEqual((self.home / ".claude/projects/history.json").read_text(), "fixture history")
                self.assertFalse((self.accounts / "kept/projects").exists())
                self.assertEqual({p: p.read_bytes() for p in profiles}, profiles)
                self.assertFalse((self.accounts / ".cleanup-recovery").exists())
                self.assertEqual(recovery_copy.read_text(), "existing cleaner recovery history")

    def test_partial_history_move_is_rolled_back_without_overwriting_stashes(self):
        self.saved_active()
        history = self.home / ".claude/history.jsonl"
        history.write_text("another history")
        config = self.config.read_bytes()
        self.run_body(r'''
mv() {
    if [ "$1" = "$CONFIG_DIR/history.jsonl" ]; then return 1; fi
    command mv "$@"
}
main new
''', success=False)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertEqual(history.read_text(), "another history")
        self.assertEqual((self.home / ".claude/projects/history.json").read_text(), "fixture history")
        self.assertEqual(self.active.read_text(), "kept\n")
        self.assertFalse((self.accounts / ".cleanup-recovery").exists())

    def test_failed_rollback_retains_history_and_blocks_same_active_fastpath(self):
        self.saved_active()
        result = self.run_body(r'''
reset_account_state() { printf '{}' > "$CLAUDE_JSON"; return 1; }
mv() {
    case "$1" in */.cleanup-recovery/data/*) return 1 ;; esac
    command mv "$@"
}
main new
''', success=False)
        recovery = self.accounts / ".cleanup-recovery"
        self.assertTrue(recovery.is_dir())
        self.assertIn(str(recovery), result.stderr)
        self.assertIn("fixture history", "".join(p.read_text() for p in recovery.rglob("*") if p.is_file()))
        self.assertNotIn("fixture-login", "".join(p.read_text() for p in recovery.rglob("*") if p.is_file()))
        self.assertEqual(recovery.stat().st_mode & 0o777, 0o700)
        self.assertEqual((recovery / "manifest.json").stat().st_mode & 0o777, 0o600)
        before = self.snapshot()
        result = self.run_body("main use kept", success=False)
        self.assertNotIn("already active", result.stdout)
        self.assertIn("incomplete", result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_failed_move_that_created_destination_restores_history(self):
        self.saved_active()
        self.run_body(r'''
mv() {
    command mv "$@" || return 1
    [ "$1" != "$CONFIG_DIR/projects" ]
}
main new
''', success=False)
        self.assertEqual((self.home / ".claude/projects/history.json").read_text(), "fixture history")
        self.assertEqual(self.active.read_text(), "kept\n")
        self.assertFalse((self.accounts / ".cleanup-recovery").exists())

    def test_keychain_rollback_failure_retains_no_secret_and_blocks_mutation(self):
        self.saved_active()
        keychain = self.fixture.fixture / "keychain.json"
        keychain.write_text(json.dumps({**self.shared, "claudeAiOauth": {"accessToken": "keychain-only-secret"}}))
        self.fixture.env["SESSION_KEYCHAIN"] = str(keychain)
        self.run_body(r'''
read_credentials() { cat "$SESSION_KEYCHAIN"; }
write_credentials() {
    if printf '%s' "$1" | jq -e 'has("claudeAiOauth")' >/dev/null; then return 1; fi
    printf '%s' "$1" > "$SESSION_KEYCHAIN"
}
reset_account_state() { return 1; }
main new
''', success=False)
        recovery = self.accounts / ".cleanup-recovery"
        self.assertTrue(recovery.is_dir())
        self.assertNotIn("keychain-only-secret", "".join(p.read_text() for p in recovery.rglob("*") if p.is_file()))
        self.assertNotIn("claudeAiOauth", json.loads(keychain.read_text()))
        for command in ("main use kept", "main save kept", "main new"):
            before = self.snapshot()
            self.run_body(command, success=False)
            self.assertEqual(self.snapshot(), before)

    def test_failed_new_restores_legacy_selection_and_unsaved_session(self):
        self.run_body("main new")
        self.login("pending@example.invalid")
        self.pending.write_text("Asia/Tokyo\n")
        credentials = self.credentials.read_bytes()
        config = self.config.read_bytes()
        self.run_body(r'''
rm() {
    if [ "$2" = "$ACTIVE_FILE" ] && [ ! -f "$HOME/failed-once" ]; then
        printf once > "$HOME/failed-once"; return 1
    fi
    command rm "$@"
}
main new
''', success=False)
        self.assertEqual(self.pending.read_text(), "Asia/Tokyo\n")
        self.assertEqual(self.credentials.read_bytes(), credentials)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertFalse(self.active.exists())
        self.assertFalse((self.accounts / ".cleanup-recovery").exists())

    def test_new_loggedout_session_can_restore_saved_profile(self):
        self.saved_active()
        self.run_body("main new")
        profiles = {p: p.read_bytes() for p in self.accounts.glob("kept.*")}
        result = self.run_body("main use kept")
        self.assertIn("Switched", result.stdout)
        self.assertEqual(self.active.read_text(), "kept\n")
        self.assertFalse(self.pending.exists())
        self.assertEqual({p: p.read_bytes() for p in profiles}, profiles)
        self.assertEqual([p.name for p in self.accounts.glob("*.json")], ["kept.json"])
        self.assertEqual((self.home / ".claude/projects/history.json").read_text(), "fixture history")
        self.assertEqual(json.loads(self.credentials.read_text())["claudeAiOauth"], {"accessToken": "fixture-login"})
        self.assertEqual(json.loads(self.credentials.read_text())["mcpOAuth"], self.shared["mcpOAuth"])

    def test_new_unsaved_login_refuses_use_without_mutation(self):
        self.saved_active()
        self.run_body("main new")
        self.login("unsaved@example.invalid")
        for options in ("", " --no-yolo"):
            before = self.snapshot()
            operations = self.operations()
            result = self.run_body("main use kept" + options, success=False)
            self.assertIn("save", result.stdout + result.stderr)
            self.assertNotIn("Confirm outgoing backup", result.stderr)
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(self.operations(), operations + ["read"])

    def test_unnamed_restore_config_write_failure_cannot_claim_success(self):
        self.saved_active()
        self.run_body("main new")
        config = self.config.read_bytes()
        result = self.run_body('cp() { return 1; }; main use kept', success=False)
        self.assertIn("Failed to restore", result.stdout + result.stderr)
        self.assertNotIn("Switched", result.stdout)
        self.assertEqual(self.config.read_bytes(), config)
        self.assertFalse(self.active.exists())
        self.assertFalse(self.pending.exists())
        self.assertEqual((self.accounts / "kept/projects/history.json").read_text(), "fixture history")

    def test_unnamed_keychain_login_and_unowned_history_refuse_use(self):
        self.saved_active()
        self.run_body("main new")
        before = self.snapshot()
        self.run_body('read_credentials() { printf \'{"claudeAiOauth":{"accessToken":"unsaved-keychain"}}\'; }; main use kept', success=False)
        self.assertEqual(self.snapshot(), before)
        history = self.home / ".claude/projects"
        history.mkdir()
        (history / "unsaved").write_text("must save first")
        before = self.snapshot()
        for options in ("", " --no-yolo"):
            result = self.run_body("main use kept" + options, success=False)
            self.assertNotIn("Confirm outgoing backup", result.stderr)
            self.assertEqual(self.snapshot(), before)

    def test_full_cleanup_whitelist_preserves_saved_and_shared_assets(self):
        self.accounts.mkdir(parents=True)
        self.config.write_text(json.dumps({"userID": "unsaved", "oauthAccount": {"emailAddress": "discard"},
            "cachedExperimentFeatures": {"old": True}, "seenNotifications": [1],
            "mcpServers": {"shared": {}}, "settings": {"keep": True}}))
        self.login()
        for name in ("backups/.hidden", "file-history/old", "feedback/drafts/draft", "projects/old", "todos/old",
                     "shell-snapshots/old", "statsig/old", "debug/old", "plans/old", "paste-cache/old",
                     "telemetry/old", "session-env/old", "tasks/old", "sessions/old", "daemon/old",
                     "jobs/old", "history.jsonl", "stats-cache.json", "remote-settings.json",
                     "policy-limits.json", "policy-limits.json.stamp.json", "plugins/plugin-directory-cache-v2.json",
                     "plugins/plugin-catalog-cache.json"):
            path = self.home / ".claude" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("discard fixture residue")
        preserved = {}
        for name in ("settings.json", "settings.local.json", "skills/fixture/SKILL.md", "plugins/installed/fixture",
                     "knowledge/keep.md", ".device-keys.json", "commands/keep.md", "mcp-oauth-state.json",
                     "cache/changelog.md", "ide/30067.lock",
                     "accounts/saved.json", "accounts/saved.credentials", "accounts/saved.surge",
                     "accounts/.timezones/saved", "accounts/.aliases/saved.json", "accounts/.check.enc"):
            path = self.home / ".claude" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("preserve fixture shared/profile asset")
            preserved[path] = path.read_bytes()
        other = self.home / "other-config/.credentials.json"
        other.parent.mkdir()
        other.write_text("unrelated credentials")
        preserved[other] = other.read_bytes()
        desktop = self.home / "Library/Application Support/Claude/keep"
        desktop.parent.mkdir(parents=True)
        desktop.write_text("desktop fixture")
        preserved[desktop] = desktop.read_bytes()
        recovery = self.home / ".claude_backups"
        recovery.mkdir()
        (recovery / "claude_.claude.json_20261031_010101").write_text("recognized account recovery")
        (recovery / "claude_dir_20261031_010101").mkdir()
        (recovery / "claude_dir_20261031_010101/secret").write_text("recognized account recovery")
        unrelated = recovery / "keep-manual-backup"
        unrelated.write_text("unrecognized backup")
        preserved[unrelated] = unrelated.read_bytes()
        hook = self.hook_snapshot()
        self.run_body("main new", stdin="yes\n")
        self.assertFalse((recovery / "claude_.claude.json_20261031_010101").exists())
        self.assertFalse((recovery / "claude_dir_20261031_010101").exists())
        self.assertEqual({p: p.read_bytes() for p in preserved}, preserved)
        self.assertEqual(self.hook_snapshot(), hook)
        for name in ("sessions", "daemon", "jobs", "backups", "feedback/drafts", "history.jsonl",
                     "remote-settings.json", "policy-limits.json", "plugins/plugin-catalog-cache.json"):
            self.assertFalse((self.home / ".claude" / name).exists(), name)
        self.assertEqual(json.loads(self.credentials.read_text()), self.shared)
        clean = json.loads(self.config.read_text())
        self.assertNotIn("cachedExperimentFeatures", clean)
        self.assertNotIn("seenNotifications", clean)
        self.assertEqual(clean["mcpServers"], {"shared": {}})

    def test_optional_malformed_file_is_refused_before_default_store_mutation(self):
        self.accounts.mkdir(parents=True)
        self.config.write_text("{}")
        for content in (b"", b"[]", b"{} {}", b'{"claudeAiOauth":"bad"}',
                        b'{"claudeAiOauth":{"accessToken":"fixture"}}\x00'):
            self.credentials.write_bytes(content)
            before = self.snapshot()
            result = self.run_body("main new", success=False)
            self.assertIn("Malformed optional credentials", result.stderr)
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(self.operations(), [])
        self.credentials.write_bytes(b"")
        self.run_body("cleanup_optional_credentials_file", success=False)
        self.assertEqual(self.credentials.read_bytes(), b"")

    def test_default_keychain_and_optional_file_clear_only_login_fields(self):
        self.accounts.mkdir(parents=True)
        self.config.write_text("{}")
        self.login()
        keychain = self.fixture.fixture / "keychain.json"
        keychain.write_text(json.dumps({**self.shared, "claudeAiOauth": {"accessToken": "keychain-fixture"}}))
        self.fixture.env["SESSION_KEYCHAIN"] = str(keychain)
        self.run_body(r'''
read_credentials() { cat "$SESSION_KEYCHAIN"; }
write_credentials() { printf '%s' "$1" > "$SESSION_KEYCHAIN"; }
delete_credentials() { rm -f "$SESSION_KEYCHAIN"; }
main new
''', stdin="yes\n")
        self.assertEqual(json.loads(keychain.read_text()), self.shared)
        self.assertEqual(json.loads(self.credentials.read_text()), self.shared)

    def test_symlinked_cleanup_and_ancestor_paths_fail_without_mutation(self):
        self.accounts.mkdir(parents=True)
        self.config.write_text("{}")
        outside = self.fixture.fixture / "outside"
        outside.mkdir()
        (outside / "keep").write_text("never touch")
        for name in ("sessions", "plugins", "feedback"):
            target = self.home / ".claude" / name
            target.symlink_to(outside, target_is_directory=True)
            before = self.snapshot()
            self.run_body("main new", success=False)
            self.assertEqual(self.snapshot(), before)
            self.assertEqual((outside / "keep").read_text(), "never touch")
            self.assertNotIn("stop", self.operations())
            target.unlink()

    def test_actual_runtime_guard_refuses_live_unverifiable_and_bridge_owners(self):
        self.run_body("main new")
        runtime = self.home / ".claude/sessions"
        runtime.mkdir()
        (runtime / "keep").write_text("runtime fixture")
        for process_body in ("return 1", "printf '321 /bin/claude claude\\n'",
                             "printf 'not-a-valid-process-list\\n'"):
            before = self.snapshot()
            self.run_body(f"claude_process_ids() {{ :; }}; ps() {{ {process_body}; }}; main new", success=False, process_mocks=False)
            self.assertEqual(self.snapshot(), before)
        # Snapshot has no Claude executable, but a live recorded PID still owns
        # runtime state and must block deletion without being signaled.
        config = json.loads(self.config.read_text())
        config["replBridgePlaceholders"] = {"session_fixture": {"pid": 321}}
        self.config.write_text(json.dumps(config))
        before = self.snapshot()
        self.run_body("claude_process_ids() { :; }; ps() { printf '321 /bin/other other\\n'; }; main new",
                      success=False, process_mocks=False)
        self.assertEqual(self.snapshot(), before)

    def test_new_explains_claude_desktop_and_browser_helper_blockers(self):
        self.run_body("main new")
        for executable in ("/Applications/Claude.app/Contents/MacOS/Claude",
                           "/Applications/Claude.app/Contents/Helpers/chrome-native-host"):
            with self.subTest(executable=executable):
                before = self.snapshot()
                result = self.run_body(
                    "ps() { printf '321 " + executable + "\\n'; }; main new",
                    success=False, process_mocks=False)
                self.assertIn("using Claude.app alongside ccacc is not recommended", result.stderr)
                self.assertIn("Fully quit Claude.app and any browser running its extension", result.stderr)
                self.assertEqual(result.stderr.count("Warning: Claude.app"), 1)
                self.assertIn("Live or unverifiable", result.stderr)
                self.assertEqual(self.snapshot(), before)

    def test_new_accepts_non_utf8_process_args_with_absent_bridge_owner(self):
        self.run_body("main new")
        config = json.loads(self.config.read_text())
        config["replBridgePlaceholders"] = {"session_fixture": {"pid": 654}}
        self.config.write_text(json.dumps(config))
        self.fixture.env["LC_ALL"] = "en_US.UTF-8"
        result = self.run_body(r'''
ps() { printf '321 /bin/other other\377\n'; }
main new
''', process_mocks=False)
        self.assertNotIn("towc", result.stderr)
        self.assertNotIn("replBridgePlaceholders", json.loads(self.config.read_text()))

    def test_non_utf8_process_args_still_block_live_runtime_owners(self):
        self.run_body("main new")
        self.fixture.env["LC_ALL"] = "en_US.UTF-8"
        for command in ("/bin/claude", "/bin/other"):
            with self.subTest(command=command):
                config = json.loads(self.config.read_text())
                if command == "/bin/other":
                    config["replBridgePlaceholders"] = {"session_fixture": {"pid": 321}}
                self.config.write_text(json.dumps(config))
                before = self.snapshot()
                result = self.run_body(
                    "ps() { printf '321 " + command + r" other\377\n'; }; main new",
                    success=False, process_mocks=False)
                self.assertIn("Live or unverifiable", result.stderr)
                self.assertNotIn("towc", result.stderr)
                self.assertEqual(self.snapshot(), before)

    def test_claude_process_ids_accepts_non_utf8_executable_paths(self):
        self.fixture.env["LC_ALL"] = "en_US.UTF-8"
        result = self.run_body(r'''
ps() { printf '321 %s /tmp/other\377\n654 %s /bin/claude\n' "$(id -u)" "$(id -u)"; }
claude_process_ids
''', process_mocks=False)
        self.assertEqual(result.stdout, "654\n")
        self.assertNotIn("towc", result.stderr)

    def test_cleanup_never_signals_pid_one(self):
        self.run_body(r'''
source "$FIXTURE_CORE" help >/dev/null
claude_process_ids() { printf '1\n'; }
ps() { printf '1\n'; }
kill() { printf '%s\n' "$*" >> "$SESSION_OPERATIONS"; }
cleanup_stop_processes
''', success=False, process_mocks=False)
        self.assertEqual(self.operations(), [])

    def test_ancestor_check_covers_refreshed_signal_candidates(self):
        self.run_body(r'''
source "$FIXTURE_CORE" help >/dev/null
printf 0 > "$HOME/process-pass"
claude_process_ids() {
    local count=$(cat "$HOME/process-pass")
    printf '%s' "$((count+1))" > "$HOME/process-pass"
    if [ "$count" -eq 0 ]; then printf '101\n'; else printf '%s\n' "$$"; fi
}
ps() { printf '1\n'; }
kill() { printf '%s\n' "$*" >> "$SESSION_OPERATIONS"; }
sleep() { :; }
cleanup_stop_processes
''', success=False, process_mocks=False)
        self.assertEqual(self.operations(), ["-TERM 101"])

    def test_only_save_selects_timezone_and_legacy_cannot_override_it(self):
        self.run_body("main new")
        self.login()
        self.run_body("save_account() { return 1; }; main save intended --timezone Australia/Sydney", success=False)
        self.assertFalse(self.pending.exists())
        self.assertFalse(self.active.exists())
        self.assertFalse((self.accounts / "intended.json").exists())
        self.fixture.cli("timezone", "missing", success=False)
        self.run_body("main save intended --timezone UTC")
        self.assertFalse(self.pending.exists())
        # A pending record cannot override an active profile, even if the named
        # timezone is corrupt or absent.
        self.pending.write_text("Asia/Tokyo\n")
        self.assertEqual(self.fixture.cli("timezone").stdout, "UTC\n")
        (self.accounts / ".timezones/intended").unlink()
        self.assertEqual(self.fixture.cli("timezone", success=False).stdout, "")


if __name__ == "__main__":
    unittest.main()
