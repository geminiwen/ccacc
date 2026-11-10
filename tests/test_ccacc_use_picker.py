"""Picker PTY regressions with isolated HOME and fake credential/process IO."""
import fcntl
import json
import os
import pty
import re
import select
import shlex
import signal
import struct
import termios
import time
import unittest

import test_ccacc_use_confirmation as confirmation

# save/use read the weekly reset from Keychain and network; fixtures forbid both.
os.environ["CCACC_NO_WEEKLY_RESET"] = "1"
# list/current/use refresh the latest Release from GitHub; fixtures forbid the network.
os.environ["CCACC_NO_UPDATE_CHECK"] = "1"


ENTER = '\x1b[?1049h'
LEAVE = '\x1b[0m\x1b[?25h\x1b[?1049l\x1b[0m\x1b[?25h'
# The only colours the picker itself emits; red is deliberately not among them.
PALETTE = ('\x1b[1m', '\x1b[2m', '\x1b[32m', '\x1b[33m', '\x1b[36m', '\x1b[1;35m')


def plain(output):
    """Screen text without colour/reverse codes, for label assertions."""
    return re.sub(r'\x1b\[[0-9;]*m', '', output)


def rendered_frames(output, rows, columns):
    """Model the emitted VT subset, including delayed wrap and reverse cells.

    Reject cursor overflow/newlines/scrolls instead of accepting clipped output.
    This deliberately has no runtime or third-party dependency.
    """
    frames = []
    for screen in output.split('\x1b[2J\x1b[H')[1:]:
        screen = screen.split('\x1b[?1049l')[0]
        cells = [[(' ', False) for _ in range(columns)] for _ in range(rows)]
        row = col = 0
        reverse = False
        for token in re.findall(r'\x1b\[[0-9;?]*[A-Za-z]|[^\x1b]', screen):
            if token.startswith('\x1b['):
                if token.endswith('H'):
                    position = token[2:-1].split(';')
                    row, col = (int(position[0] or 1) - 1,
                                int(position[1]) - 1 if len(position) > 1 else 0)
                    assert 0 <= row < rows and 0 <= col < columns, token
                elif token == '\x1b[7m':
                    reverse = True
                elif token == '\x1b[0m':
                    reverse = False
                elif token in PALETTE:
                    pass
                else:
                    assert token == '\x1b[?25h', token
            else:
                assert token >= ' ' and col < columns, (token, row, col)
                cells[row][col] = (token, reverse)
                col += 1
        frames.append(cells)
    return frames


class ProfilePickerTests(unittest.TestCase):
    def setUp(self):
        self.case = confirmation.UseConfirmationTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.fixture = self.case.fixture
        self.accounts = self.case.accounts
        (self.accounts / "sydney.json").write_text(json.dumps({"userID": "old-saved-id",
            "oauthAccount": {"emailAddress": "saved-sydney@example.test"}}))
        (self.accounts / "tokyo.json").write_text(json.dumps({"userID": "target-id",
            "oauthAccount": {"emailAddress": "saved-tokyo@example.test"}}))

    def run_pty(self, args=(), keys=b"q", yolo=None, body=None,
                before_select=None, size=(24, 110),
                ready_marker=b"Profiles ", menu_action=None, on_output=None, tty_setup=None):
        code = self.case.mocks + "\n" + (body or "main use " + shlex.join(args))
        stdout = self.fixture.fixture / "picker.stdout"
        before = self.case.snapshot()
        pid, master = pty.fork()
        if pid == 0:
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", *size, 0, 0))
            if tty_setup:
                termios.tcsetattr(0, termios.TCSANOW, tty_setup(termios.tcgetattr(0)))
            output = os.open(stdout, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.dup2(output, 1)
            os.close(output)
            os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-c", code], self.fixture.env)
        original = termios.tcgetattr(master)
        if tty_setup:
            original = tty_setup(original)
        data = b""
        sent = yolo_sent = False
        status = None
        try:
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.025)
                if ready:
                    try:
                        data += os.read(master, 65536)
                    except OSError:
                        pass
                if not sent and ready_marker in data:
                    # Discovery must not stage mode, read passwords/credentials,
                    # stop processes, or alter any profile/session file.
                    self.assertEqual(self.case.snapshot(), before)
                    self.assertEqual(self.case.operations(), [])
                    if before_select:
                        before_select()
                    if menu_action:
                        menu_action(pid, master, data)
                    os.write(master, keys)
                    sent = True
                if on_output:
                    on_output(pid, master, data)
                if not yolo_sent and b"YOLO? (y/N) " in data:
                    self.assertIn(LEAVE.encode(), data)
                    self.assertLess(data.index(LEAVE.encode()), data.index(b"YOLO?"))
                    self.assertIsNotNone(yolo, data.decode(errors="replace"))
                    self.assertEqual(self.case.operations(), [])
                    os.write(master, yolo)
                    yolo_sent = True
                done, result = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = os.waitstatus_to_exitcode(result)
                    # Drain remaining bytes after process exit.
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
            restored = termios.tcgetattr(master)
            # Window dimensions may differ; all terminal input/output modes and
            # control characters must match, including echo, canonical and ISIG.
            self.assertEqual(restored, original)
        finally:
            if status is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(master)
        self.assertFalse(self.fixture.forbidden.exists())
        if ENTER.encode() in data:
            self.assertEqual(data.count(ENTER.encode()), 1)
            self.assertEqual(data.count(LEAVE.encode()), 1)
            self.assertIn(b'\x1b[?25l', data)
        return status, data.decode(errors="replace"), stdout.read_text()

    def test_full_viewport_reverse_video_and_bottom_footer(self):
        for index in range(30):
            self.fixture.account("account%02d" % index, "UTC")
        (self.accounts / '.active').unlink()
        before = self.case.snapshot()
        status, menu, stdout = self.run_pty(body='pick_saved_account', keys=b'j\r')
        self.assertEqual((status, stdout), (0, 'account01\n'))
        frames = rendered_frames(menu, 24, 110)
        self.assertGreaterEqual(len(frames), 2)
        first, last = frames[0], frames[-1]
        self.assertTrue(all(reverse for _, reverse in first[2]))
        self.assertTrue(all(reverse for _, reverse in last[3]))
        self.assertFalse(any(reverse for _, reverse in last[2]))
        self.assertTrue(''.join(c for c, _ in first[21]).startswith('  account19'))
        self.assertTrue(''.join(c for c, _ in last[22]).startswith('Profiles 1-20 of 32'))
        self.assertTrue(''.join(c for c, _ in last[23]).startswith('Up/Down j/k: move'))
        self.assertEqual(self.case.snapshot(), before)
        self.assertEqual(self.case.operations(), [])

    def test_tiny_and_narrow_screens_never_wrap_or_scroll(self):
        for size in ((1, 1), (2, 8), (3, 16), (4, 1), (6, 24)):
            with self.subTest(size=size):
                before = self.case.snapshot()
                status, menu, stdout = self.run_pty(body='pick_saved_account', keys=b'j\r',
                    size=size, ready_marker=b'\x1b[0m\x1b[2J\x1b[H')
                self.assertEqual((status, stdout), (0, 'tokyo\n'))
                frames = rendered_frames(menu, *size)
                self.assertTrue(frames)
                self.assertTrue(any(all(reverse for _, reverse in row) for row in frames[-1]))
                self.assertEqual(self.case.snapshot(), before)

    def test_resize_redraws_while_idle_and_keeps_selection(self):
        state = {}

        def resize(pid, master, data):
            state['frames'] = data.count(b'\x1b[2J\x1b[H')
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 5, 18, 0, 0))
            os.killpg(pid, signal.SIGWINCH)

        def accept(pid, master, data):
            if state and not state.get('accepted') and data.count(b'\x1b[2J\x1b[H') > state['frames']:
                state['accepted'] = True
                os.write(master, b'j\r')

        status, menu, stdout = self.run_pty(body='pick_saved_account', keys=b'',
            menu_action=resize, on_output=accept)
        self.assertEqual((status, stdout), (0, 'tokyo\n'), menu)
        self.assertTrue(state.get('accepted'))
        # The last frame uses the new viewport and pins help to its bottom row.
        final = '\x1b[2J\x1b[H' + menu.rsplit('\x1b[2J\x1b[H', 1)[1]
        cells = rendered_frames(final, 5, 18)[0]
        self.assertTrue(all(reverse for _, reverse in cells[2]))
        self.assertEqual(''.join(c for c, _ in cells[4]), 'Up/Down j/k: move ')
        self.assertEqual(self.case.operations(), [])

    def test_idle_timeout_does_not_cancel_or_repaint(self):
        state = {}

        def idle(pid, master, data):
            state['started'] = time.monotonic()

        def accept(pid, master, data):
            if state and not state.get('accepted') and time.monotonic() - state['started'] > 2.2:
                state['accepted'] = True
                os.write(master, b'\r')

        before = self.case.snapshot()
        status, menu, stdout = self.run_pty(body='pick_saved_account', keys=b'',
            menu_action=idle, on_output=accept)
        self.assertEqual((status, stdout), (0, 'sydney\n'), menu)
        self.assertEqual(menu.count('\x1b[2J\x1b[H'), 1)
        self.assertEqual(self.case.snapshot(), before)

    def test_password_prompt_follows_primary_screen_restore(self):
        body = r'''migrate_encrypted_backups() {
            printf 'Fixture password? ' >&2
            printf 'password\n' >> "$OPS"
        }; main use --no-yolo'''
        status, menu, _ = self.run_pty(body=body, keys=b'j\r')
        self.assertEqual(status, 0, menu)
        self.assertLess(menu.index(LEAVE), menu.index('Fixture password?'))
        self.case.assert_switched()

    def test_nondefault_terminal_modes_are_preserved_exactly(self):
        def custom(attributes):
            attributes[0] &= ~termios.IXON
            attributes[1] &= ~termios.ONLCR
            attributes[3] &= ~termios.ECHO
            attributes[6][termios.VERASE] = b'\x08'
            return attributes

        for keys in (b'q', b'\x03', b'\r'):
            with self.subTest(keys=keys):
                before = self.case.snapshot()
                status, menu, stdout = self.run_pty(body='pick_saved_account', keys=keys,
                    tty_setup=custom)
                self.assertEqual(status, 130 if keys == b'\x03' else 1 if keys == b'q' else 0, menu)
                self.assertEqual(stdout, 'sydney\n' if keys == b'\r' else '')
                self.assertEqual(self.case.snapshot(), before)

    def test_hup_term_and_read_render_failures_restore_terminal(self):
        for sig in (signal.SIGHUP, signal.SIGTERM):
            with self.subTest(signal=sig):
                before = self.case.snapshot()
                # Record the actual picker subshell PID, since Bash 3.2 keeps
                # $$ unchanged in subshells and has no BASHPID. This child only
                # reports its own PPID; no process-table discovery is needed.
                pidfile = self.fixture.fixture / 'menu.pid'
                body = ('stty() { if [ "$1" = -echo ]; then /bin/bash -c '
                        + shlex.quote('printf "%s" "$PPID"') + ' > '
                        + shlex.quote(str(pidfile)) + '; fi; command stty "$@"; }; pick_saved_account')
                def interrupt(pid, master, data):
                    os.kill(int(pidfile.read_text()), sig)
                status, menu, stdout = self.run_pty(body=body, keys=b'', menu_action=interrupt)
                self.assertEqual(status, 128 + sig, menu)
                self.assertEqual(stdout, '')
                self.assertEqual(self.case.snapshot(), before)
        for failure in ('read() { return 1; }; ',
                        'printf() { if [ "$1" = "\\033[%s;1H" ]; then return 1; fi; builtin printf "$@"; }; '):
            with self.subTest(failure=failure):
                before = self.case.snapshot()
                status, menu, stdout = self.run_pty(body=failure + 'pick_saved_account', keys=b'')
                self.assertEqual(status, 1, menu)
                self.assertEqual(stdout, '')
                self.assertIn(LEAVE, menu)
                self.assertEqual(self.case.snapshot(), before)
                self.assertEqual(self.case.operations(), [])

    def test_initial_current_saved_labels_and_enter_fast_path(self):
        status, menu, stdout = self.run_pty(["--no-yolo"], b"\r")
        self.assertEqual(status, 0, menu + stdout)
        self.assertIn("> sydney (active) | saved-sydney@example.test | Australia/Sydney", plain(menu))
        self.assertIn("  tokyo | saved-tokyo@example.test | Asia/Tokyo", plain(menu))
        self.assertNotIn("Confirm outgoing backup", menu)
        self.assertEqual(self.case.operations(), ["stage", "surge"])
        self.assertNotIn("Choose saved profile", stdout)
        self.assertFalse(json.loads((self.accounts / ".launch-mode").read_text())["yolo"])

    def test_arrows_and_jk_reach_automatic_backup_and_separate_yolo_flow(self):
        for keys in (b"\x1b[B\x1b[A\x1b[B\r", b"jkj\r", b"\x1bOB\r"):
            with self.subTest(keys=keys):
                status, menu, stdout = self.run_pty(keys=keys, yolo=b"n\n")
                self.assertEqual(status, 0, menu + stdout)
                self.assertIn("> tokyo | saved-tokyo@example.test", plain(menu))
                self.assertNotIn("Confirm outgoing backup", menu)
                self.assertLess(menu.index(LEAVE), menu.index("YOLO?"))
                self.assertLess(menu.index("YOLO?"), menu.index("Backed up "))
                self.case.assert_report(menu)
                self.case.assert_switched()
                self.case.run_body("main use sydney --no-yolo")
                self.case.ops.unlink()

    def test_q_escape_ctrl_c_and_eof_cancel_without_side_effects(self):
        for keys in (b"q", b"\x1b", b"\x03", b"\x04"):
            with self.subTest(keys=keys):
                before = self.case.snapshot()
                status, menu, stdout = self.run_pty(["--yolo"], keys)
                self.assertEqual(status, 130 if keys == b"\x03" else 1, menu + stdout)
                self.assertNotIn("YOLO?", menu)
                self.assertEqual(self.case.snapshot(), before)
                self.assertEqual(self.case.operations(), [])

    def test_ctrl_c_at_yolo_preserves_everything_after_picker(self):
        before = self.case.snapshot()
        status, menu, _ = self.run_pty(keys=b"j\r", yolo=b"\x03")
        self.assertEqual(status, 130, menu)
        self.assertNotIn("Backed up ", menu)
        self.assertEqual(self.case.snapshot(), before)
        self.assertEqual(self.case.operations(), [])

    def test_picker_stdout_is_name_only(self):
        status, menu, stdout = self.run_pty(body="pick_saved_account", keys=b"j\r")
        self.assertEqual(status, 0, menu)
        self.assertEqual(stdout, "tokyo\n")
        self.assertEqual(self.case.operations(), [])

    def test_no_name_launch_flags_skip_yolo_prompt(self):
        for args, expected in ((["--yolo"], True), (["--no-yolo"], False)):
            with self.subTest(args=args):
                status, menu, _ = self.run_pty(args, b"\r")
                self.assertEqual(status, 0, menu)
                self.assertNotIn("YOLO?", menu)
                self.assertEqual(json.loads((self.accounts / ".launch-mode").read_text())["yolo"], expected)
                self.case.ops.unlink()

    def test_hook_and_recovery_guards_precede_picker_and_account_operations(self):
        hook = self.case.home / ".ccacc-shell/hook.sh"
        saved = hook.read_bytes()
        hook.write_text("# invalid fixture hook\n")
        before = self.case.snapshot()
        status, menu, _ = self.run_pty()
        self.assertEqual(status, 1, menu)
        self.assertIn("Shell hook is not installed correctly", menu)
        self.assertEqual(self.case.snapshot(), before)
        self.assertEqual(self.case.operations(), [])
        hook.write_bytes(saved)
        for name in (".cleanup-recovery", ".profile-transaction.fixture"):
            with self.subTest(name=name):
                recovery = self.accounts / name
                recovery.mkdir()
                before = self.case.snapshot()
                status, menu, _ = self.run_pty()
                self.assertEqual(status, 1, menu)
                self.assertNotIn("Choose saved profile", menu)
                self.assertIn("recovery data retained", menu)
                self.assertEqual(self.case.snapshot(), before)
                self.assertEqual(self.case.operations(), [])
                recovery.rmdir()

    def test_nonterminal_never_consumes_password_stdin(self):
        for args in ("", "--yolo", "--no-yolo"):
            with self.subTest(args=args):
                before = self.case.snapshot()
                result = self.case.run_body("if main use " + args + "; then exit 99; fi\n"
                    'IFS= read -r remaining; printf "%s\\n" "$remaining"')
                self.assertEqual(result.stdout, "password-stdin-sentinel\n")
                self.assertIn("requires a terminal", result.stderr)
                self.assertEqual(self.case.snapshot(), before)
                self.assertEqual(self.case.operations(), [])

    def test_no_saved_profiles_has_save_instructions_without_mutation(self):
        for path in self.accounts.glob("*.json"):
            path.unlink()
        before = self.case.snapshot()
        status, menu, _ = self.run_pty()
        self.assertEqual(status, 1, menu)
        self.assertIn("ccacc save <name> --timezone <ZONE>", menu)
        self.assertEqual(self.case.snapshot(), before)
        self.assertEqual(self.case.operations(), [])

    def test_invalid_json_symlinks_and_unsafe_names_are_excluded(self):
        for name, value in (("malformed", "{bad"), ("array", "[]"), ("multiple", "{} {}"),
                            ("empty", ""), ("bad name", "{}"), (".hidden", "{}")):
            (self.accounts / (name + ".json")).write_text(value)
        (self.accounts / "linked.json").symlink_to(self.accounts / "tokyo.json")
        status, menu, _ = self.run_pty()
        self.assertEqual(status, 1)
        self.assertIn("Profiles 1-2 of 2", menu)
        for name in ("malformed", "array", "multiple", "empty", "bad name", ".hidden", "linked"):
            self.assertNotIn(name, menu)

    def test_saved_metadata_is_sanitized_and_never_evaluated(self):
        (self.accounts / "tokyo.json").write_text(json.dumps({"oauthAccount": {"emailAddress":
            "$(touch $HOME/injected)\u001b[31m\n\r\t\u007f\u009b\u202e"}}))
        status, menu, _ = self.run_pty()
        self.assertEqual(status, 1)
        self.assertIn("$(touch $HOME/injected)?[31m??????", menu)
        self.assertNotIn("\x1b[31m", menu)
        self.assertFalse((self.case.home / "injected").exists())

    def test_plan_label_comes_from_saved_metadata_and_is_sanitized(self):
        for name, account, label in (
                ("sydney", {"planDisplayName": "Ultra", "organizationType": "claude_max"}, "Ultra"),
                ("tokyo", {"organizationType": "claude_team"}, "Team")):
            path = self.accounts / f"{name}.json"
            saved = json.loads(path.read_text())
            saved["oauthAccount"].update(account)
            path.write_text(json.dumps(saved))
        status, menu, _ = self.run_pty()
        self.assertEqual(status, 1)
        self.assertIn("> sydney (active) | Ultra | saved-sydney@example.test", plain(menu))
        self.assertIn("  tokyo | Team | saved-tokyo@example.test", plain(menu))
        # The plan is display-only metadata: never credentials, never raw escapes.
        saved = json.loads((self.accounts / "tokyo.json").read_text())
        saved["oauthAccount"] = {"emailAddress": "saved-tokyo@example.test", "planDisplayName": "Ul\u001b[31mtra"}
        (self.accounts / "tokyo.json").write_text(json.dumps(saved))
        status, menu, _ = self.run_pty()
        self.assertIn("  tokyo | Ul?[31mtra | saved-tokyo@example.test", plain(menu))
        self.assertNotIn("\x1b[31m", menu)
        self.assertEqual(self.case.operations(), [])

    def test_rows_are_coloured_unless_no_color_is_set(self):
        status, menu, _ = self.run_pty()
        self.assertEqual(status, 1)
        self.assertIn("\x1b[1msydney", menu)
        self.assertIn("\x1b[32m (active)", menu)
        self.assertIn("\x1b[36msaved-tokyo@example.test", menu)
        self.assertIn("\x1b[33mAsia/Tokyo", menu)
        self.fixture.env["NO_COLOR"] = "1"
        try:
            status, menu, _ = self.run_pty()
        finally:
            del self.fixture.env["NO_COLOR"]
        self.assertEqual(status, 1)
        self.assertIn("> sydney (active) | saved-sydney@example.test", plain(menu))
        for colour in PALETTE:
            self.assertNotIn(colour, menu)

    def test_missing_or_invalid_timezone_display_and_selection_validation(self):
        for zone in (None, "bad\u001b[31m"):
            with self.subTest(zone=zone):
                path = self.accounts / ".timezones/tokyo"
                if path.exists():
                    path.unlink()
                if zone is not None:
                    path.write_text(zone)
                before = self.case.snapshot()
                status, menu, _ = self.run_pty(keys=b"j\r")
                self.assertEqual(status, 1, menu)
                self.assertIn("No valid saved timezone for 'tokyo'", menu)
                self.assertEqual(self.case.snapshot(), before)
                self.assertEqual(self.case.operations(), [])

    def test_target_revalidated_after_menu(self):
        def corrupt():
            (self.accounts / "tokyo.json").write_text("[]")
        status, menu, _ = self.run_pty(keys=b"j\r", before_select=corrupt)
        self.assertEqual(status, 1, menu)
        self.assertIn("Invalid saved account 'tokyo'", menu)
        self.assertEqual(self.case.operations(), [])

    def test_no_current_highlights_first_and_large_list_is_bounded(self):
        (self.accounts / ".active").unlink()
        for index in range(20):
            self.fixture.account("account%02d" % index, "UTC")
        status, menu, stdout = self.run_pty(body="pick_saved_account", keys=b"j" * 9 + b"\r",
                                            size=(9, 45))
        self.assertEqual(status, 0, menu)
        self.assertEqual(stdout, "account09\n")
        self.assertIn("> account00 | UTC", plain(menu))
        self.assertIn("Profiles 6-10 of 22", menu)
        self.assertNotIn("account19", menu)

    def test_invalid_arguments_fail_before_any_read_boundary(self):
        for args in ("--yes", "--yolo --yolo", "--no-yolo --no-yolo", "--yolo --no-yolo",
                     "--unknown", "--no-yolo --yolo", "--no-yolo ''", "--yolo ../bad",
                     "--yolo tokyo extra", "--no-yolo tokyo --unknown"):
            with self.subTest(args=args):
                before = self.case.snapshot()
                self.case.run_body('require_shell_hook() { printf hook >> "$OPS"; }; '
                    'jq() { printf jq >> "$OPS"; return 99; }; main use ' + args, success=False)
                self.assertEqual(self.case.snapshot(), before)
                self.assertEqual(self.case.operations(), [])

    def test_explicit_target_accepts_options_on_either_side_without_menu(self):
        for args in ("tokyo --no-yolo", "--no-yolo tokyo"):
            with self.subTest(args=args):
                result = self.case.run_body("main use " + args)
                self.assertNotIn("Choose saved profile", result.stderr)
                self.assertEqual((self.accounts / ".active").read_text(), "tokyo\n")
                self.case.run_body("main use sydney --no-yolo")
                self.case.ops.unlink()


if __name__ == "__main__":
    unittest.main()
