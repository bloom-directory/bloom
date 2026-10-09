#!/usr/bin/env python3
"""Guard packaging tests against recursive deletion; archive their fresh scratch.

prepare ROOT GUARD_DIR installs rm/find wrappers. Set TMPDIR=ROOT, PATH to the
guard directory, and BLOOM_PRESERVE_TEST_ROOT=ROOT when running a test. Existing
files outside that root cannot be recursively removed through these wrappers.
"""
import os
from pathlib import Path
import sys
import uuid

if sys.argv[1:2] == ['prepare']:
    root, guard = map(Path, sys.argv[2:4])
    assert root.is_absolute() and guard.is_absolute() and not root.exists() and not guard.exists()
    root.mkdir(mode=0o700)
    guard.mkdir(mode=0o755)
    for name in ['rm', 'find']:
        (guard / name).symlink_to(Path(__file__).resolve())
    sys.exit(0)

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
recursive = tool == 'rm' and any(arg == '--recursive' or (arg.startswith('-') and not arg.startswith('--') and ('r' in arg or 'R' in arg)) for arg in args)
deleting_find = tool == 'find' and '-delete' in args
if not recursive and not deleting_find:
    assert tool in ('rm', 'find')
    os.execv('/usr/bin/' + tool, [tool, *args])

root = Path(os.environ['BLOOM_PRESERVE_TEST_ROOT']).resolve()
if deleting_find:
    assert len(args) == 3 and args[1:] == ['-depth', '-delete'], 'Unsupported deleting find; nothing removed'
    paths = args[:1]
else:
    paths = [arg for arg in args if not arg.startswith('-')]
archive = root.parent / (root.name + '.retained')
archive.mkdir(mode=0o700, exist_ok=True)
for value in paths:
    path = Path(os.path.abspath(value))
    if not path.exists() and not path.is_symlink():
        continue
    assert path == root or path.parent.resolve().is_relative_to(root), 'Recursive operation outside fresh test scratch refused'
    destination = archive / (uuid.uuid4().hex + '-' + path.name)
    os.rename(path, destination)
    print('Preserved test scratch: ' + str(destination), file=sys.stderr)
