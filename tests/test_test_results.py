from mncs_control_mcp.test_results import parse_test_output


def test_runner_aware_fixture_parsers() -> None:
    pytest_result = parse_test_output("pytest", "================ 21 passed, 2 skipped in 0.12s ================", "")
    assert pytest_result["passed"] == 21 and pytest_result["skipped"] == 2
    cargo_result = parse_test_output("cargo", "test result: FAILED. 3 passed; 1 failed; 2 ignored; 0 measured; 0 filtered out", "")
    assert cargo_result["passed"] == 3 and cargo_result["failed"] == 1 and cargo_result["skipped"] == 2
    node_result = parse_test_output("node", "Tests:       1 failed, 4 passed, 1 skipped, 6 total", "")
    assert node_result["total"] == 6
    go_result = parse_test_output("go", "--- PASS: TestOne (0.01s)\n--- SKIP: TestTwo (0.00s)\n--- FAIL: TestThree (0.02s)", "")
    assert go_result["passed"] == 1 and go_result["failed"] == 1 and go_result["skipped"] == 1
    ctest_result = parse_test_output("cmake", "100% tests passed, 0 tests failed out of 5", "")
    assert ctest_result["passed"] == 5 and ctest_result["total"] == 5


def test_parser_is_partial_and_never_decides_process_status() -> None:
    result = parse_test_output("pytest", "\x1b[32moutput truncated\x1b[0m", "")
    assert result["parser"] == "pytest"
    assert "passed" not in result
    unknown = parse_test_output("unknown", "21 passed", "")
    assert unknown["parser"] == "none"
