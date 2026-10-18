from .demo import build_demo_archive
from .formats import (
	Archive,
	EncryptedArchive,
	Entry,
	ReadCapExceeded,
	UnsupportedArchive,
	detect_kind,
	open_archive,
	sniff_kind,
	supported_kinds,
)
from .limits import REASON_CODES, Limits, Verdict, human_bytes
from .remote import RemoteSource
from .report import render, render_json
from .sarif import render_sarif
from .scanner import ExtractionRefused, QuotaExceeded, Scanner
from .sources import FileSource, MemorySource, Source
from .trust import fingerprint, load_allowlist

__version__ = "2.2.0"

__all__ = [
	"REASON_CODES",
	"Archive",
	"EncryptedArchive",
	"Entry",
	"ExtractionRefused",
	"FileSource",
	"Limits",
	"MemorySource",
	"QuotaExceeded",
	"ReadCapExceeded",
	"RemoteSource",
	"Scanner",
	"Source",
	"UnsupportedArchive",
	"Verdict",
	"__version__",
	"build_demo_archive",
	"detect_kind",
	"fingerprint",
	"human_bytes",
	"load_allowlist",
	"open_archive",
	"render",
	"render_json",
	"render_sarif",
	"sniff_kind",
	"supported_kinds",
]
