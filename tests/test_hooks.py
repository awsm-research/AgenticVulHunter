"""Pre-push integration: both tools must receive the same ref input."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from agenticbughunter.cli import _install_hook, _uninstall_hook


class HookTests(unittest.TestCase):
    def test_chained_hook_receives_stdin_and_uninstall_restores_original(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=Test', '-c', 'user.email=t@example.invalid',
                            '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-qm', 'base'], check=True)
            sha = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
            hook = root / '.git/hooks/pre-push'
            original = '#!/bin/sh\ncat > "$ORIGINAL_INPUT"\nprintf "%s\\n" "$@" > "$ORIGINAL_ARGS"\n'
            hook.write_text(original)
            hook.chmod(0o755)
            bindir = root / 'bin'
            bindir.mkdir()
            executable = bindir / 'agenticbughunter'
            executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$ABH_ARGS"\n')
            executable.chmod(0o755)
            _install_hook(root)
            payload = f'refs/heads/main {sha} refs/heads/main {sha}\n'
            env = {**os.environ, 'PATH': str(bindir) + os.pathsep + os.environ['PATH'],
                   'ORIGINAL_INPUT': str(root / 'original-input'), 'ORIGINAL_ARGS': str(root / 'original-args'),
                   'ABH_ARGS': str(root / 'abh-args')}
            process = subprocess.run([str(hook), 'origin', 'example-url'], input=payload, text=True,
                                     cwd=root, env=env, capture_output=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual((root / 'original-input').read_text(), payload)
            self.assertEqual((root / 'original-args').read_text(), 'origin\nexample-url\n')
            self.assertIn('--base\n' + sha, (root / 'abh-args').read_text())
            self.assertTrue(_uninstall_hook(root)[1])
            self.assertEqual(hook.read_text(), original)


if __name__ == '__main__':
    unittest.main()
