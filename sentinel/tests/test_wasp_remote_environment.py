import hashlib
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'sentinel' / 'evals' / 'wasp' / 'remote-environment.sh'


def _executable(path: Path, body: str) -> None:
	path.write_text(body)
	path.chmod(0o755)


def _environment(tmp_path: Path) -> tuple[dict[str, str], Path, Path]:
	bin_dir = tmp_path / 'bin'
	bin_dir.mkdir()
	_executable(bin_dir / 'singularity', '#!/bin/sh\nexit 0\n')
	_executable(bin_dir / 'flock', '#!/bin/sh\nexit 0\n')
	_executable(
		bin_dir / 'stat',
		'''#!/bin/sh
if [ "$1" != "-c" ]; then exit 2; fi
case "$2" in
  %s) exec /usr/bin/stat -f %z "$3" ;;
  %s:%Y:%Z:%i) exec /usr/bin/stat -f %z:%m:%c:%i "$3" ;;
  *) exit 2 ;;
esac
''',
	)
	remote_root = tmp_path / 'remote'
	images = remote_root / 'images'
	images.mkdir(parents=True)
	gitlab = images / 'gitlab.tar'
	reddit = images / 'reddit.tar'
	gitlab.write_bytes(b'valid gitlab archive fixture')
	reddit.write_bytes(b'valid reddit archive fixture')
	env = {
		**os.environ,
		'PATH': f'{bin_dir}:{os.environ["PATH"]}',
		'WASP_REMOTE_ROOT': str(remote_root),
		'WASP_CONTAINER_RUNTIME': 'singularity',
		'WASP_GITLAB_TAR': str(gitlab),
		'WASP_REDDIT_TAR': str(reddit),
		'WASP_REQUIRE_ARCHIVE_VERIFICATION': '1',
		'WASP_GITLAB_IMAGE_SHA256': hashlib.sha256(gitlab.read_bytes()).hexdigest(),
		'WASP_REDDIT_IMAGE_SHA256': hashlib.sha256(reddit.read_bytes()).hexdigest(),
		'WASP_GITLAB_IMAGE_BYTES': str(gitlab.stat().st_size),
		'WASP_REDDIT_IMAGE_BYTES': str(reddit.stat().st_size),
	}
	return env, gitlab, reddit


def test_remote_archives_are_verified_once_and_marker_is_reused(tmp_path: Path) -> None:
	env, gitlab, reddit = _environment(tmp_path)
	first = subprocess.run(
		['bash', str(SCRIPT), 'download'], env=env, text=True, capture_output=True
	)
	assert first.returncode == 0, first.stderr
	assert 'GitLab archive bytes and SHA-256 verified' in first.stdout
	assert 'Reddit archive bytes and SHA-256 verified' in first.stdout
	assert list(gitlab.parent.glob('gitlab.tar.verified-*'))
	assert list(reddit.parent.glob('reddit.tar.verified-*'))

	second = subprocess.run(
		['bash', str(SCRIPT), 'download'], env=env, text=True, capture_output=True
	)
	assert second.returncode == 0, second.stderr
	assert second.stdout.count('archive verification marker matches') == 2


def test_remote_archive_mismatch_fails_closed_without_deleting_file(tmp_path: Path) -> None:
	env, gitlab, _reddit = _environment(tmp_path)
	gitlab.write_bytes(b'corrupt')
	result = subprocess.run(
		['bash', str(SCRIPT), 'download'], env=env, text=True, capture_output=True
	)
	assert result.returncode != 0
	assert 'GitLab archive size mismatch' in result.stderr
	assert gitlab.read_bytes() == b'corrupt'
