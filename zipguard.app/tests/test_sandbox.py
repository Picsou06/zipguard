from __future__ import annotations

import json
import pickle
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

from conftest import write_zip
from zipguard import Limits
from zipguard.sandbox import (
	CgroupJail,
	SandboxConfig,
	_filter_program,
	seccomp_supported,
)
from zipguard.service import WorkerFailed, build_server, scan_in_worker_report

SRC = Path(__file__).resolve().parents[1] / "src"
linux_only = pytest.mark.skipif(
	not seccomp_supported(), reason="seccomp exige Linux x86_64 ou aarch64."
)


def _run_sandboxed(code: str, config: str = "SandboxConfig()") -> subprocess.CompletedProcess:
	"""
	Description: Exécute du Python dans un processus neuf, après avoir posé le bac à sable.
	Usage: _run_sandboxed("import socket; socket.socket()").
	Inputs: code (str) à exécuter une fois le bac à sable posé, config (str) expression SandboxConfig.
	Outputs: CompletedProcess avec la sortie standard.

	Un filtre seccomp est irréversible : il ne peut être testé que dans un processus jetable.
	"""

	prelude = (
		"from zipguard.sandbox import SandboxConfig, apply_sandbox\n"
		f"print('rapport', apply_sandbox({config}))\n"
	)
	return subprocess.run(
		[sys.executable, "-c", prelude + code],
		capture_output=True,
		text=True,
		env={"PYTHONPATH": str(SRC)},
		timeout=60,
	)


def test_an_unknown_mode_is_refused() -> None:
	with pytest.raises(ValueError):
		SandboxConfig(mode="parfois")


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_the_filter_program_is_well_formed(machine: str) -> None:
	program = _filter_program(machine)
	assert len(program) < 255
	deny = len(program) - 1
	for index, (code, jt, _jf, _k) in enumerate(program):
		if code in (0x15, 0x35) and index > 1:
			assert index + 1 + jt == deny


@linux_only
def test_the_worker_cannot_open_a_socket() -> None:
	result = _run_sandboxed(
		"import socket\ntry:\n    socket.socket()\n    print('socket autorisé')\n"
		"except PermissionError:\n    print('socket refusé')\n"
	)
	assert "socket refusé" in result.stdout, result.stderr


@linux_only
def test_the_worker_cannot_run_a_program() -> None:
	result = _run_sandboxed(
		"import subprocess\ntry:\n    subprocess.run(['true'])\n    print('exec autorisé')\n"
		"except PermissionError:\n    print('exec refusé')\n"
	)
	assert "exec refusé" in result.stdout, result.stderr


@linux_only
def test_threads_and_a_scan_still_work_inside_the_sandbox(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	result = _run_sandboxed(
		"import threading\nt = threading.Thread(target=print, args=('thread',))\nt.start(); t.join()\n"
		"from pathlib import Path\nfrom zipguard import Scanner\n"
		f"print('sûre', Scanner().inspect(Path({str(archive)!r})).safe)\n"
	)
	assert "thread" in result.stdout, result.stderr
	assert "sûre True" in result.stdout


@linux_only
def test_a_file_beyond_the_size_limit_is_an_error_not_a_crash(tmp_path: Path) -> None:
	target = tmp_path / "gros.bin"
	result = _run_sandboxed(
		f"try:\n    open({str(target)!r}, 'wb').write(b'0' * 3_000_000)\n    print('écrit')\n"
		"except OSError as error:\n    print('refusé', error.errno)\n",
		"SandboxConfig(max_file_bytes=1_000_000)",
	)
	assert "refusé 27" in result.stdout, result.stderr


@linux_only
def test_the_report_lists_what_is_in_place() -> None:
	result = _run_sandboxed("", "SandboxConfig(cpu_seconds=5, max_file_bytes=10**7)")
	report = result.stdout
	for key in ("'seccomp': True", "'memory': True", "'cpu_seconds': True", "'file_size': True"):
		assert key in report, report


def test_off_installs_nothing() -> None:
	result = _run_sandboxed(
		"import socket\nsocket.socket().close()\nprint('socket ok')\n", "SandboxConfig(mode='off')"
	)
	assert "socket ok" in result.stdout, result.stderr
	assert "{'mode': 'off'}" in result.stdout


def test_a_cgroup_jail_writes_its_limits(tmp_path: Path) -> None:
	jail = CgroupJail(tmp_path, max_memory_bytes=500_000_000, pids_max=8)
	assert jail.path.parent == tmp_path
	assert (jail.path / "memory.max").read_text() == "500000000"
	assert (jail.path / "pids.max").read_text() == "8"


def test_the_worker_joins_its_cgroup(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	root = tmp_path / "cgroup"
	root.mkdir()
	config = SandboxConfig(mode="auto", seccomp=False, cgroup_root=str(root))
	verdict, report = scan_in_worker_report(archive, Limits(), timeout=60, sandbox=config)
	assert verdict.safe is True
	assert report["cgroup"] is True
	jails = list(root.iterdir())
	assert len(jails) == 1
	assert (jails[0] / "cgroup.procs").read_text().isdigit()


def test_strict_mode_refuses_without_a_usable_cgroup(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	config = SandboxConfig(mode="strict", cgroup_root=str(tmp_path / "absent"))
	with pytest.raises(WorkerFailed, match="strict"):
		scan_in_worker_report(archive, Limits(), timeout=60, sandbox=config)


def test_auto_mode_goes_on_without_a_cgroup_and_says_so(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	config = SandboxConfig(mode="auto", cgroup_root=str(tmp_path / "absent"))
	verdict, report = scan_in_worker_report(archive, Limits(), timeout=60, sandbox=config)
	assert verdict.safe is True
	assert report["cgroup"] is False
	assert report["cgroup_error"]


def test_a_large_verdict_is_not_mistaken_for_a_timeout(tmp_path: Path) -> None:
	inner = write_zip(tmp_path / "interne.zip", {"a.txt": b"bonjour"})
	files = {f"fille-{index:03d}-{'x' * 400}.zip": inner.read_bytes() for index in range(150)}
	archive = write_zip(tmp_path / "beaucoup.zip", files)
	verdict, _ = scan_in_worker_report(archive, Limits(max_nested_scans=200), timeout=60)
	# Au delà de 64 Kio, le tampon du tube est plein et le worker attend qu'on le lise.
	assert len(pickle.dumps(("ok", verdict.as_dict(), {}))) > 65536
	assert len(verdict.children) == 150


@linux_only
def test_the_service_reports_its_sandbox(tmp_path: Path) -> None:
	archive = write_zip(tmp_path / "ok.zip", {"a.txt": b"bonjour"})
	httpd = build_server(port=0, isolate=True, sandbox="auto")
	thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
	thread.start()
	try:
		host, port = httpd.server_address[0], httpd.server_address[1]
		with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=10) as response:
			health = json.loads(response.read())
		assert health["sandbox"]["mode"] == "auto"
		assert health["sandbox"]["seccomp_supported"] is True

		request = urllib.request.Request(
			f"http://{host}:{port}/scan", data=archive.read_bytes(), method="POST"
		)
		with urllib.request.urlopen(request, timeout=60) as response:
			payload = json.loads(response.read())
		assert payload["safe"] is True
		assert payload["sandbox"]["seccomp"] is True
		assert payload["sandbox"]["rlimits"]["memory"] is True
	finally:
		httpd.shutdown()
		httpd.server_close()
		thread.join(timeout=5)


def test_the_cli_accepts_the_sandbox_flags() -> None:
	from zipguard.__main__ import _build_parser

	args = _build_parser().parse_args(["serve", "--sandbox", "strict", "--cgroup-root", "/x"])
	assert (args.sandbox, args.cgroup_root) == ("strict", "/x")
