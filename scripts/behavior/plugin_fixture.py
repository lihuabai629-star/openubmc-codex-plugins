"""Build a package fixture, or use the final distribution selected by public CI."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]


def package_fixture(base: Path) -> Path:
    selected = os.environ.get('OPENUBMC_TEST_PLUGIN_ROOT')
    if selected:
        return Path(selected).resolve()
    source = base/'source'
    source.mkdir()
    for name in subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0'):
        if name and (ROOT/name).is_file():
            target = source/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT/name, target)
    subprocess.run(['git', 'init', '-q', str(source)], check=True)
    subprocess.run(['git', 'add', '.'], cwd=source, check=True)
    subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'Fixture'], cwd=source, check=True)
    subprocess.run([sys.executable, str(ROOT/'scripts/package_plugin.py'), 'build', '--source', str(source),
                    '--output', str(base/'bundle.tar.gz')], check=True, capture_output=True)
    with tarfile.open(base/'bundle.tar.gz') as archive:
        archive.extractall(base, filter='data')
    return base/'openubmc'
