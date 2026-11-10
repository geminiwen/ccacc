"""Deploy the real final artifacts through fake curl, without network or live HOME."""
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

# save/use read the weekly reset from Keychain and network; fixtures forbid both.
os.environ["CCACC_NO_WEEKLY_RESET"] = "1"
# list/current/use refresh the latest Release from GitHub; fixtures forbid the network.
os.environ["CCACC_NO_UPDATE_CHECK"] = "1"


ROOT = Path(__file__).resolve().parents[1]


class InstallEndToEndTests(unittest.TestCase):
    def test_real_artifact_bootstrap_launch_and_idempotent_reinstall(self):
        scratch = ROOT / ".orca" / "installer-end-to-end"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="home with spaces ", dir=scratch) as temporary:
            home = Path(temporary).resolve()
            fakebin = home / "fakebin"
            fakebin.mkdir()
            curl = fakebin / "curl"
            curl.write_text(
                f"#!{sys.executable}\n"
                "import os, shutil, sys\nfrom pathlib import Path\n"
                "args=sys.argv[1:]\n"
                "output=Path(args[args.index('--output')+1])\n"
                "name=args[-1].rsplit('/',1)[-1]\n"
                "if name not in ('ccacc','ccacc_shell.sh'): raise SystemExit(99)\n"
                "shutil.copyfile(Path(os.environ['CCACC_E2E_SOURCE'])/name, output)\n"
            )
            curl.chmod(0o700)
            prefix = home / ".local" / "bin"
            prefix.mkdir(parents=True)
            claude = prefix / "claude"
            claude.write_text(
                '#!/bin/bash\nprintf "CLIENT_BROWSER=%s\\nCLIENT_TZ=%s\\nCLIENT_TZ_SET=%s\\n" '
                '"${BROWSER-}" "${TZ-}" "${TZ+set}"\n'
                'for arg in "$@"; do printf "CLIENT_ARG=%s\\n" "$arg"; done\n'
            )
            claude.chmod(0o700)
            original_claude = claude.read_bytes()
            (home / ".bash_profile").write_text(
                '_op_agent() { TZ=Europe/London "$@"; }\n'
                'alias claude="_op_agent env BROWSER=true TZ=Asia/Tokyo '
                "'$HOME/.local/bin/claude' --retained-flag\"\n"
            )
            (home / ".zshrc").write_text('source "$HOME/.bash_profile"\n')
            env = dict(os.environ, HOME=str(home), SHELL="/bin/zsh",
                       PATH=f"{fakebin}:/opt/homebrew/bin:/usr/bin:/bin",
                       TMPDIR=str(home), XDG_CONFIG_HOME=str(home / ".config"),
                       BASH_ENV="/dev/null", CCACC_E2E_SOURCE=str(ROOT),
                       CCACC_INSTALL_REF="1" * 40, TZ="Asia/Tokyo")
            # zsh -i must not append to the caller's real history file.
            for key in ("ZDOTDIR", "CCACC_INSTALL_REPO", "HISTFILE"):
                env.pop(key, None)

            def install():
                result = subprocess.run(["bash", str(ROOT / "install.sh")], env=env,
                                        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
                                        start_new_session=True)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                self.assertIn("Setup complete", result.stdout)

            install()
            self.assertFalse((home / ".claude").exists())
            self.assertFalse((home / ".claude.json").exists())
            self.assertEqual(claude.read_bytes(), original_claude)
            for name in ("ccacc", "ccacc_shell.sh"):
                self.assertEqual((prefix / name).read_bytes(), (ROOT / name).read_bytes())
            self.assertTrue(os.access(prefix / "ccacc", os.X_OK))
            tracked = [home / ".zshrc", home / ".zlogin", home / ".ccacc-shell/hook.sh",
                       home / ".ccacc-shell/managed.json"]

            def snapshot():
                return {str(path): (hashlib.sha256(path.read_bytes()).hexdigest(),
                                    path.stat().st_mtime_ns, path.stat().st_ino) for path in tracked}

            before = snapshot()
            install()
            self.assertEqual(snapshot(), before)
            for rc in tracked[:2]:
                self.assertEqual(rc.read_text().count("# >>> ccacc shell hook >>>"), 1)
            command = 'printf "SDK_COMMAND=%s\\n" "$(command -v ccacc)"\n'
            command += "eval " + shlex.quote('claude --probe "two words"')
            result = subprocess.run(["zsh", "-lic", command], env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            lines = result.stdout.splitlines()
            self.assertIn(f"SDK_COMMAND={prefix / 'ccacc'}", lines)
            self.assertIn("CLIENT_BROWSER=false", lines)
            self.assertIn("CLIENT_TZ=", lines)
            self.assertIn("CLIENT_TZ_SET=", lines)
            self.assertNotIn("CLIENT_ARG=--retained-flag", lines)
            self.assertFalse((home / ".ccacc-shell/original-alias.json").exists())
            for arg in ("--probe", "two words"):
                self.assertIn("CLIENT_ARG=" + arg, lines)
            self.assertFalse((home / ".claude").exists())
            self.assertEqual(snapshot(), before)


if __name__ == "__main__":
    unittest.main()
