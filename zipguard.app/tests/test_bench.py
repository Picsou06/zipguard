from __future__ import annotations

import json
from pathlib import Path

from zipguard.bench import CORPUS_CAP_BYTES, bench_json, build_corpus, render_bench, run_bench


def test_corpus_covers_every_guard(tmp_path: Path) -> None:
	cases = build_corpus(tmp_path)
	guards = {case.guard for case in cases}
	assert {
		"ratio",
		"max_entries",
		"max_entry_bytes",
		"max_total_bytes",
		"max_depth",
		"imbrication",
		"plafond_de_lecture",
		"format",
	} <= guards


def test_corpus_includes_one_benign_case(tmp_path: Path) -> None:
	cases = build_corpus(tmp_path)
	benign = [case for case in cases if case.expectation is True]
	assert len(benign) >= 1


def test_every_corpus_file_stays_tiny(tmp_path: Path) -> None:
	for case in build_corpus(tmp_path):
		assert case.path.stat().st_size <= CORPUS_CAP_BYTES


def test_corpus_files_all_exist(tmp_path: Path) -> None:
	for case in build_corpus(tmp_path):
		assert case.path.is_file()


def test_bench_returns_one_result_per_case(tmp_path: Path) -> None:
	cases = build_corpus(tmp_path)
	results = run_bench(cases, repeat=1)
	assert len(results) == len(cases)


def test_bench_measures_a_duration(tmp_path: Path) -> None:
	results = run_bench(build_corpus(tmp_path), repeat=1)
	assert all(result.elapsed_ms >= 0 for result in results)


def test_every_guard_fires_as_expected(tmp_path: Path) -> None:
	results = run_bench(build_corpus(tmp_path), repeat=1)
	failed = [result.name for result in results if not result.ok]
	assert failed == []


def test_bench_reports_the_refusal_reason(tmp_path: Path) -> None:
	results = run_bench(build_corpus(tmp_path), repeat=1)
	refused = [result for result in results if not result.safe]
	assert refused
	assert all(result.reason for result in refused)


def test_bench_reports_bytes_read_before_refusal(tmp_path: Path) -> None:
	results = run_bench(build_corpus(tmp_path), repeat=1)
	capped = [result for result in results if result.guard == "plafond_de_lecture"]
	assert capped
	assert capped[0].archive_bytes > 0


def test_rendered_table_names_every_case(tmp_path: Path) -> None:
	cases = build_corpus(tmp_path)
	text = render_bench(run_bench(cases, repeat=1), color=False)
	for case in cases:
		assert case.name in text


def test_rendered_table_shows_the_verdict_column(tmp_path: Path) -> None:
	text = render_bench(run_bench(build_corpus(tmp_path), repeat=1), color=False)
	assert "verdict" in text.lower()


def test_bench_json_is_valid_and_lists_cases(tmp_path: Path) -> None:
	results = run_bench(build_corpus(tmp_path), repeat=1)
	payload = json.loads(bench_json(results))
	assert payload["schema_version"] == 1
	assert len(payload["cases"]) == len(results)
	assert payload["cases"][0]["name"]


def test_bench_json_summarises_the_outcome(tmp_path: Path) -> None:
	results = run_bench(build_corpus(tmp_path), repeat=1)
	payload = json.loads(bench_json(results))
	assert payload["summary"]["cases"] == len(results)
	assert payload["summary"]["unexpected"] == 0


def test_long_case_names_do_not_collide_with_the_next_column() -> None:
	from zipguard.bench import Result

	results = [
		Result(
			name="un-nom-de-cas-vraiment-tres-long.tar.gz",
			guard="max_depth",
			kind="zip",
			safe=False,
			expected=False,
			elapsed_ms=1.0,
			archive_bytes=10,
			read_bytes=10,
			reason="raison",
		)
	]
	line = [row for row in render_bench(results, color=False).splitlines() if "un-nom" in row][0]
	assert "un-nom-de-cas-vraiment-tres-long.tar.gzmax_depth" not in line
	assert "un-nom-de-cas-vraiment-tres-long.tar.gz " in line


def test_read_cap_case_reports_what_it_read_before_cutting(tmp_path: Path) -> None:
	results = run_bench(build_corpus(tmp_path), repeat=1)
	capped = [result for result in results if result.guard == "plafond_de_lecture"][0]
	assert capped.read_bytes > 0
