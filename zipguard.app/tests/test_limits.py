from __future__ import annotations

from zipguard import Limits, human_bytes


def test_default_limits_are_conservative() -> None:
	limits = Limits()
	assert limits.max_ratio == 100.0
	assert limits.max_entries == 10_000
	assert limits.max_depth == 2


def test_limits_are_immutable() -> None:
	limits = Limits()
	try:
		limits.max_ratio = 1.0
		assert False, "Limits doit être immuable"
	except Exception:
		assert True


def test_human_bytes_scales_units() -> None:
	assert human_bytes(0) == "0.0 o"
	assert human_bytes(1536).endswith("KiB")
	assert human_bytes(5 * 1024**3).endswith("GiB")
