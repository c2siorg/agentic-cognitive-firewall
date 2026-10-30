from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import harness  # noqa: E402


def test_arms_cover_every_enforcement_combination():
    assert list(harness.ARMS) == [
        "none", "gate-global", "gate-task", "detect", "full-global", "full-task"
    ]
    assert harness.ARMS["none"].detect is False and harness.ARMS["none"].gate is None
    assert harness.ARMS["full-task"].detect is True and harness.ARMS["full-task"].gate == "task"


def test_csv_choices_rejects_unknown_and_empty():
    assert harness.csv_choices("none, detect", list(harness.ARMS), "arms") == ["none", "detect"]
    with pytest.raises(SystemExit):
        harness.csv_choices("none,nope", list(harness.ARMS), "arms")
    with pytest.raises(SystemExit):
        harness.csv_choices("", list(harness.ARMS), "arms")


def test_rate_and_percent_handle_empty_denominators():
    assert harness.rate(3, 4) == 0.75
    assert harness.rate(0, 0) is None
    assert harness.percent(harness.rate(0, 0)) == "n/a"
    assert harness.percent(0.5) == "50.0%"


def test_replace_top_level_yaml_list_replaces_one_key():
    text = "tool_allowlist:\n  - old\nmemory_key_allowlist:\n  - keep\n"
    updated = harness.replace_top_level_yaml_list(text, "tool_allowlist", ["a", "b"])
    assert updated == 'tool_allowlist:\n  - "a"\n  - "b"\nmemory_key_allowlist:\n  - keep\n'
    with pytest.raises(RuntimeError):
        harness.replace_top_level_yaml_list("other: 1\n", "tool_allowlist", ["a"])


def test_prepare_sidecar_config_copies_policies_and_sets_allowlist(tmp_path):
    config = harness.prepare_sidecar_config(tmp_path / "sidecar-00", ("SearchTool",))
    assert config.exists()
    assert '"SearchTool"' in config.read_text(encoding="utf-8")
    policy_config = tmp_path / "sidecar-00" / "policies" / "v1" / "data" / "policy_config.yaml"
    assert '"SearchTool"' in policy_config.read_text(encoding="utf-8")
    # The rest of the policy bundle comes along unchanged.
    assert (tmp_path / "sidecar-00" / "policies" / "v1" / "prompt.rego").exists()


def test_fetch_pinned_refuses_an_unpinned_manifest(tmp_path):
    manifest = {"repository": "owner/repo", "commit": None, "files": {"data": {"path": "d.json"}}}
    with pytest.raises(RuntimeError, match="not pinned"):
        harness.fetch_pinned(manifest, "data", tmp_path)


def test_fetch_pinned_returns_the_cached_file_when_the_hash_matches(tmp_path):
    payload = b'{"cases": []}'
    digest = harness.sha256_bytes(payload)
    manifest = {"repository": "owner/repo", "commit": "abc123",
                "files": {"data": {"path": "data/d.json", "sha256": digest}}}
    cached = tmp_path / "upstream" / "abc123" / "data" / "d.json"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(payload)
    assert harness.fetch_pinned(manifest, "data", tmp_path) == cached


def test_provenance_records_the_run_inputs(tmp_path):
    runner = tmp_path / "run_x.py"
    runner.write_text("print()\n", encoding="utf-8")
    prov = harness.provenance(runner, None, None, {"model": "gpt-4o"})
    assert prov["runner_sha256"] == harness.sha256_file(runner)
    assert prov["model"] == "gpt-4o"
    assert prov["policy_config_sha256"] and prov["jailbreak_patterns_sha256"]
    assert prov["manifest_sha256"] is None and prov["sidecar_binary_sha256"] is None


def test_write_summary_and_records(tmp_path):
    harness.write_records(tmp_path / "records.jsonl", [{"a": 1}, {"a": 2}])
    lines = (tmp_path / "records.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["a"] for line in lines] == [1, 2]

    harness.write_summary(tmp_path, {"scores": {}}, "# title\n")
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8")) == {"scores": {}}
    assert (tmp_path / "summary.md").read_text(encoding="utf-8") == "# title\n"


def test_new_output_dir_is_timestamped_and_unique(tmp_path):
    first = harness.new_output_dir(tmp_path, "gpt-4o/arm")
    assert first.exists() and "gpt-4o-arm" in first.name


def test_prepare_sidecar_config_applies_policy_overrides(tmp_path):
    overrides = {
        "consequential_tools": ["send_money"],
        "sensitive_params": {"send_money": ["recipient"]},
    }
    skip = {"tool_param_scan_skip": {"send_money": {"subject": ["shell_metacharacter"]}}}
    config = harness.prepare_sidecar_config(tmp_path / "run", ("send_money",), overrides, skip)
    config_text = config.read_text(encoding="utf-8")
    assert 'tool_param_scan_skip: {"send_money": {"subject": ["shell_metacharacter"]}}' in config_text
    assert "calculator:" not in config_text and "memory_key_allowlist:" in config_text
    text = (tmp_path / "run" / "policies" / "v1" / "data" / "policy_config.yaml").read_text(
        encoding="utf-8"
    )
    assert 'consequential_tools: ["send_money"]' in text
    assert 'sensitive_params: {"send_money": ["recipient"]}' in text
    # The shipped list items went with the key, and the keys around it survive.
    assert "transfer_funds" not in text
    assert "signal_weights:" in text and "trusted_tools:" in text


def test_replace_top_level_yaml_value_requires_the_key():
    with pytest.raises(RuntimeError):
        harness.replace_top_level_yaml_value("a: 1\n", "missing", [])


def test_taint_is_off_in_every_shared_arm():
    assert not any(arm.taint for arm in harness.ARMS.values())


def test_sidecar_socket_path_is_short_and_distinct():
    first, second = harness.sidecar_socket_path("agentdojo", 0), harness.sidecar_socket_path("agentdojo", 1)
    assert first != second
    # sockaddr_un holds about 100 characters; a pipe name has no such limit.
    assert harness.IS_WINDOWS or len(first) < 100


def test_sidecar_pool_makes_its_paths_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pool = harness.SidecarPool(Path("bin") / "sidecar", Path("work"), harness.FirewallFactory())
    assert pool.binary.is_absolute() and pool.work_dir == tmp_path.resolve() / "work"
