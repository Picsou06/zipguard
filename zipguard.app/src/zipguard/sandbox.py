from __future__ import annotations

import contextlib
import ctypes
import os
import platform
import signal
import sys
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

SANDBOX_MODES = ("auto", "strict", "off")

# Appels système refusés au worker, avec EPERM. Le choix est une liste de refus et non une
# liste blanche : l'interpréteur Python et ses extensions font des centaines d'appels
# légitimes selon la version et le système, et une liste blanche trop courte tuerait le
# worker sur une machine qu'on n'a pas testée. La liste vise ce qu'un analyseur compromis
# chercherait en premier : lancer un programme, ouvrir le réseau, observer ou modifier un
# autre processus, toucher au noyau ou aux espaces de noms. Numéros relevés dans
# asm/unistd_64.h (x86_64) et asm-generic/unistd.h (aarch64).
_DENIED = {
	"x86_64": {
		"socket": 41,
		"socketpair": 53,
		"connect": 42,
		"bind": 49,
		"listen": 50,
		"accept": 43,
		"accept4": 288,
		"execve": 59,
		"execveat": 322,
		"fork": 57,
		"vfork": 58,
		"ptrace": 101,
		"process_vm_readv": 310,
		"process_vm_writev": 311,
		"mount": 165,
		"umount2": 166,
		"chroot": 161,
		"pivot_root": 155,
		"reboot": 169,
		"kexec_load": 246,
		"kexec_file_load": 320,
		"init_module": 175,
		"finit_module": 313,
		"delete_module": 176,
		"bpf": 321,
		"unshare": 272,
		"setns": 308,
		"io_uring_setup": 425,
		"io_uring_enter": 426,
		"io_uring_register": 427,
		"open_tree": 428,
		"move_mount": 429,
		"fsopen": 430,
		"fsconfig": 431,
		"fsmount": 432,
		"fspick": 433,
	},
	"aarch64": {
		"socket": 198,
		"socketpair": 199,
		"connect": 203,
		"bind": 200,
		"listen": 201,
		"accept": 202,
		"accept4": 242,
		"execve": 221,
		"execveat": 281,
		"ptrace": 117,
		"process_vm_readv": 270,
		"process_vm_writev": 271,
		"mount": 40,
		"umount2": 39,
		"chroot": 51,
		"pivot_root": 41,
		"reboot": 142,
		"kexec_load": 104,
		"kexec_file_load": 294,
		"init_module": 105,
		"finit_module": 273,
		"delete_module": 106,
		"bpf": 280,
		"unshare": 97,
		"setns": 268,
		"io_uring_setup": 425,
		"io_uring_enter": 426,
		"io_uring_register": 427,
		"open_tree": 428,
		"move_mount": 429,
		"fsopen": 430,
		"fsconfig": 431,
		"fsmount": 432,
		"fspick": 433,
	},
}

_AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
_X32_SYSCALL_BIT = 0x40000000

_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_EPERM = 1

_BPF_LD_W_ABS = 0x20
_BPF_JEQ_K = 0x15
_BPF_JGE_K = 0x35
_BPF_RET_K = 0x06


class SandboxError(RuntimeError):
	"""
	Description: Signale qu'un élément du bac à sable exigé en mode strict n'a pas pu être posé.
	Usage: levée par apply_sandbox quand mode == "strict".
	Inputs: message (str) élément manquant.
	Outputs: exception que le worker renvoie comme erreur, donc une réponse 500.
	"""


@dataclass(frozen=True)
class SandboxConfig:
	"""
	Description: Réglages du bac à sable posé autour de chaque worker d'analyse.
	Usage: SandboxConfig(mode="strict", cgroup_root="/sys/fs/cgroup/zipguard").
	Inputs: mode (str) auto, strict ou off ; max_memory_bytes, cpu_seconds, max_file_bytes, max_open_files (int) plafonds, 0 pour aucun ; seccomp (bool) ; cgroup_root (str | None) cgroup v2 délégué ; pids_max (int).
	Outputs: instance immuable, sérialisable pour traverser vers le worker.

	auto pose tout ce que le système permet et rapporte le reste ; strict refuse d'analyser
	si un seul élément manque ; off ne pose rien, pour comparer ou déboguer.
	"""

	mode: str = "auto"
	max_memory_bytes: int = 1_000_000_000
	cpu_seconds: int = 0
	max_file_bytes: int = 0
	max_open_files: int = 128
	seccomp: bool = True
	cgroup_root: str | None = None
	pids_max: int = 32

	def __post_init__(self) -> None:
		if self.mode not in SANDBOX_MODES:
			raise ValueError(f"Mode de bac à sable inconnu : {self.mode}")

	def as_dict(self) -> dict:
		return asdict(self)


def apply_memory_limit(max_bytes: int) -> bool:
	"""
	Description: Plafonne l'espace d'adressage du processus courant, là où le système le permet.
	Usage: appelée en tête du worker, jamais dans le serveur lui même.
	Inputs: max_bytes (int) plafond en octets, 0 pour ne rien limiter.
	Outputs: bool vrai si le plafond a été posé.

	Le délai coupe une analyse trop longue, pas une analyse trop gourmande : sans plafond,
	une archive qui fait gonfler la mémoire peut faire tuer bien plus que son worker par le
	système. Avec, l'allocation fautive échoue en MemoryError dans le worker seul.
	"""

	return _set_rlimit("RLIMIT_AS", max_bytes)


def _set_rlimit(name: str, value: int) -> bool:
	"""
	Description: Abaisse une limite de ressource du processus courant, sans jamais la relever.
	Usage: _set_rlimit("RLIMIT_NOFILE", 128).
	Inputs: name (str) nom de la constante du module resource, value (int) plafond, 0 pour ignorer.
	Outputs: bool vrai si la limite est en place.
	"""

	if value <= 0 and name != "RLIMIT_CORE":
		return False
	try:
		import resource
	except ImportError:  # pragma: no cover - Windows n'a pas de module resource
		return False
	limit = getattr(resource, name, None)
	if limit is None:  # pragma: no cover - dépend du système
		return False
	try:
		_, hard = resource.getrlimit(limit)
		ceiling = value if hard == resource.RLIM_INFINITY else min(value, hard)
		# La limite dure descend avec la souple : le worker ne pourra pas la relever.
		resource.setrlimit(limit, (ceiling, ceiling))
	except (ValueError, OSError):  # pragma: no cover - dépend du système
		return False
	return True


def seccomp_supported() -> bool:
	"""
	Description: Dit si le filtre seccomp de ZipGuard sait s'installer sur cette machine.
	Usage: seccomp_supported().
	Inputs: aucun.
	Outputs: bool vrai sous Linux x86_64 ou aarch64.
	"""

	return sys.platform.startswith("linux") and platform.machine() in _DENIED


class _SockFilter(ctypes.Structure):
	_fields_ = (
		("code", ctypes.c_ushort),
		("jt", ctypes.c_ubyte),
		("jf", ctypes.c_ubyte),
		("k", ctypes.c_uint),
	)


class _SockFprog(ctypes.Structure):
	_fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter)))


def _filter_program(machine: str) -> list[tuple[int, int, int, int]]:
	"""
	Description: Construit le programme BPF du filtre, instruction par instruction.
	Usage: interne à install_seccomp.
	Inputs: machine (str) x86_64 ou aarch64.
	Outputs: list de tuples (code, jt, jf, k).

	Structure : vérifier l'architecture (un appel 32 bits passé par la porte de
	compatibilité aurait d'autres numéros), charger le numéro d'appel, le comparer à chaque
	appel refusé, autoriser sinon. Tous les refus sautent vers la même instruction finale.
	"""

	denied = sorted(set(_DENIED[machine].values()))
	program: list[list[int]] = [
		[_BPF_LD_W_ABS, 0, 0, 4],
		[_BPF_JEQ_K, 1, 0, _AUDIT_ARCH[machine]],
		[_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM],
		[_BPF_LD_W_ABS, 0, 0, 0],
	]
	jumps: list[int] = []
	if machine == "x86_64":
		jumps.append(len(program))
		program.append([_BPF_JGE_K, 0, 0, _X32_SYSCALL_BIT])
	for number in denied:
		jumps.append(len(program))
		program.append([_BPF_JEQ_K, 0, 0, number])
	program.append([_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW])
	deny = len(program)
	program.append([_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO | _EPERM])

	for index in jumps:
		program[index][1] = deny - index - 1
	return [tuple(instruction) for instruction in program]


def install_seccomp() -> bool:
	"""
	Description: Pose no_new_privs puis le filtre seccomp sur le processus courant, pour toujours.
	Usage: appelée dans le worker, juste avant l'analyse.
	Inputs: aucun.
	Outputs: bool vrai si le filtre est actif.

	Irréversible par construction : un processus filtré ne peut ni retirer son filtre ni en
	poser un plus permissif, et ses éventuels enfants en héritent.
	"""

	if not seccomp_supported():
		return False
	program = _filter_program(platform.machine())
	filters = (_SockFilter * len(program))(*(_SockFilter(*instruction) for instruction in program))
	fprog = _SockFprog(len(program), filters)

	libc = ctypes.CDLL(None, use_errno=True)
	ulong = ctypes.c_ulong
	if libc.prctl(_PR_SET_NO_NEW_PRIVS, ulong(1), ulong(0), ulong(0), ulong(0)) != 0:
		return False
	pointer = ctypes.cast(ctypes.pointer(fprog), ctypes.c_void_p)
	return libc.prctl(_PR_SET_SECCOMP, ulong(_SECCOMP_MODE_FILTER), pointer, ulong(0), ulong(0)) == 0


class CgroupJail:
	"""
	Description: Cgroup v2 jetable, créé pour un worker et retiré après lui.
	Usage: jail = CgroupJail(root, memory, pids) ; worker rejoint jail.path ; jail.remove().
	Inputs: root (Path) cgroup délégué où l'on a le droit d'écrire, max_memory_bytes (int), pids_max (int).
	Outputs: objet portant le chemin du cgroup créé.

	Les rlimits plafonnent un processus ; un cgroup plafonne un groupe, compte la mémoire
	réellement utilisée plutôt que l'espace d'adressage, et peut être tué d'un coup. Il
	faut pour cela qu'un administrateur ait délégué un sous arbre du cgroup v2 à
	l'utilisateur du service : c'est donc une option, jamais un prérequis.
	"""

	def __init__(self, root: Path, max_memory_bytes: int, pids_max: int) -> None:
		self.path = Path(root) / f"zipguard-{os.getpid()}-{uuid.uuid4().hex[:8]}"
		self.path.mkdir()
		if max_memory_bytes > 0:
			self._write("memory.max", str(max_memory_bytes))
			self._write("memory.swap.max", "0", required=False)
		if pids_max > 0:
			self._write("pids.max", str(pids_max))

	def _write(self, name: str, value: str, *, required: bool = True) -> None:
		try:
			(self.path / name).write_text(value)
		except OSError:
			if required:
				raise

	def kill(self) -> None:
		"""
		Description: Tue d'un coup tous les processus du cgroup, quand le noyau le permet.
		Usage: jail.kill() après un délai dépassé.
		Inputs: aucun.
		Outputs: None.
		"""

		with contextlib.suppress(OSError):
			(self.path / "cgroup.kill").write_text("1")

	def remove(self) -> None:
		"""
		Description: Retire le cgroup, une fois son worker terminé.
		Usage: jail.remove().
		Inputs: aucun.
		Outputs: None, best effort.
		"""

		with contextlib.suppress(OSError):
			self.path.rmdir()


def join_cgroup(path: Path) -> None:
	"""
	Description: Fait entrer le processus courant dans un cgroup.
	Usage: appelée en tête du worker.
	Inputs: path (Path) cgroup créé par CgroupJail.
	Outputs: None, lève OSError si l'entrée est refusée.
	"""

	(Path(path) / "cgroup.procs").write_text(str(os.getpid()))


def apply_sandbox(config: SandboxConfig, cgroup: str | None = None) -> dict:
	"""
	Description: Pose le bac à sable sur le processus courant et rapporte ce qui est en place.
	Usage: report = apply_sandbox(SandboxConfig(), cgroup="/sys/fs/cgroup/zipguard/zipguard-1-ab").
	Inputs: config (SandboxConfig) réglages, cgroup (str | None) cgroup à rejoindre.
	Outputs: dict décrivant chaque élément posé ou non.

	L'ordre compte : entrer dans le cgroup d'abord, tant que l'écriture est permise ; puis
	les limites de ressources ; seccomp en dernier, car il est irréversible. En mode strict,
	un élément manquant lève SandboxError avant que la moindre archive soit lue.
	"""

	if config.mode == "off":
		return {"mode": "off"}

	report: dict = {"mode": config.mode}
	missing: list[str] = []

	if cgroup:
		try:
			join_cgroup(Path(cgroup))
			report["cgroup"] = True
		except OSError as error:
			report["cgroup"] = False
			missing.append(f"cgroup ({error})")

	limits = {
		"memory": ("RLIMIT_AS", config.max_memory_bytes),
		"cpu_seconds": ("RLIMIT_CPU", config.cpu_seconds),
		"file_size": ("RLIMIT_FSIZE", config.max_file_bytes),
		"open_files": ("RLIMIT_NOFILE", config.max_open_files),
		"core_dumps": ("RLIMIT_CORE", 0),
	}
	applied = {}
	for label, (name, value) in limits.items():
		if value <= 0 and name != "RLIMIT_CORE":
			continue
		applied[label] = _set_rlimit(name, value)
		if not applied[label]:
			missing.append(label)
	report["rlimits"] = applied

	if config.max_file_bytes > 0 and hasattr(signal, "SIGXFSZ"):
		# Sans cela, dépasser RLIMIT_FSIZE tue le worker par un signal ; ignoré, il devient
		# une simple erreur d'écriture, que le scanner traduit en verdict.
		signal.signal(signal.SIGXFSZ, signal.SIG_IGN)

	if config.seccomp:
		report["seccomp"] = install_seccomp()
		if not report["seccomp"]:
			missing.append("seccomp")

	if missing and config.mode == "strict":
		raise SandboxError("Bac à sable incomplet en mode strict : " + ", ".join(missing))
	return report
