"""Small, runner-aware parsers for supplemental test metadata.

The process exit status remains authoritative.  These parsers only annotate a
test result and deliberately return partial data when output is incomplete.
"""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_COUNT = re.compile(
    r"(?P<count>\d+)\s+(?P<label>passed|failed|skipped|ignored|xfailed|xpassed|errors?)\b",
    re.IGNORECASE,
)


def _counts(text: str, labels: set[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for match in _COUNT.finditer(text):
        label = match.group("label").lower()
        label = "errors" if label.startswith("error") else label
        if label in labels:
            result[label] = int(match.group("count"))
    return result


def _pytest(text: str) -> tuple[dict[str, int], str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    summary = next((line for line in reversed(lines) if " in " in line and _COUNT.search(line)), "")
    result = _counts(summary, {"passed", "failed", "skipped", "xfailed", "xpassed", "errors"})
    return result, "high" if result else "low"


def _cargo(text: str) -> tuple[dict[str, int], str]:
    lines = [line for line in text.splitlines() if line.strip().startswith("test result:")]
    result: dict[str, int] = {}
    for line in lines:
        result.update(_counts(line, {"passed", "failed", "ignored"}))
    if result:
        result["skipped"] = result.pop("ignored") if "ignored" in result else 0
    return result, "high" if result else "low"


def _node(text: str) -> tuple[dict[str, int], str]:
    result: dict[str, int] = {}
    for line in text.splitlines():
        if re.match(r"\s*Tests?:", line, re.IGNORECASE):
            result.update(_counts(line, {"passed", "failed", "skipped", "errors"}))
        elif re.match(r"\s*Test Files?", line, re.IGNORECASE):
            result.update(_counts(line, {"passed", "failed", "skipped"}))
    return result, "high" if result else "low"


def _go(text: str) -> tuple[dict[str, int], str]:
    result = {
        "passed": len(re.findall(r"^--- PASS:", text, re.MULTILINE)),
        "failed": len(re.findall(r"^--- FAIL:", text, re.MULTILINE)),
        "skipped": len(re.findall(r"^--- SKIP:", text, re.MULTILINE)),
    }
    result = {key: value for key, value in result.items() if value}
    return result, "high" if result else "low"


def _ctest(text: str) -> tuple[dict[str, int], str]:
    result: dict[str, int] = {}
    match = re.search(r"(?P<total>\d+)% tests passed,\s*(?P<failed>\d+) tests failed out of (?P<count>\d+)", text, re.IGNORECASE)
    if match:
        result["failed"] = int(match.group("failed"))
        result["passed"] = int(match.group("count")) - result["failed"]
        result["total"] = int(match.group("count"))
    return result, "high" if result else "low"


def parse_test_output(suite: str, stdout: str, stderr: str) -> dict[str, object]:
    text = _ANSI.sub("", f"{stdout}\n{stderr}")
    parsers = {
        "pytest": _pytest,
        "cargo": _cargo,
        "node": _node,
        "go": _go,
        "cmake": _ctest,
    }
    parser = suite if suite in parsers else "none"
    counts, confidence = parsers[suite](text) if suite in parsers else ({}, "none")
    if "total" not in counts and counts:
        counts["total"] = sum(value for key, value in counts.items() if key != "total")
    result: dict[str, object] = {**counts, "parser": parser, "parser_confidence": confidence}
    if not counts:
        result["diagnostic"] = "runner output did not contain a recognized summary"
    return result
