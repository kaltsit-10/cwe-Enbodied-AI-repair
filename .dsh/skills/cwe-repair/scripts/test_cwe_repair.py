#!/usr/bin/env python3
"""Minimal regression tests for cwe-repair without project toolchains."""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

repair = load("cwe_repair")
contract_module = load("repair_contract")
detect = load("cwe_detect")
verify = load("cwe_verify")
symmetry = load("symmetry_check")
leaderboard = load("cwe_leaderboard")
evidence = load("repair_evidence")
schema = load("dataset_schema_check")
benchmark_v2 = load("benchmark_v2")
verdict = load("repair_verdict")
matrix_module = load("contract_matrix")
pr_registry = load("pr_case_registry")
pr_readiness = load("pr_case_readiness")
pr_plan = load("pr_materialization_plan")
lattice = load("evidence_lattice")
paired_build = load("paired_build_evidence")
gtest_runtime = load("gtest_runtime")
paired_runtime_evidence = load("paired_runtime_evidence")
checked_addition_contract = load("checked_addition_contract")
added_test_target_build = load("added_test_target_build_evidence")
asset_semantic = load("asset_semantic_contract")
release_audit = load("release_audit")
profile_validator = load("embodied_profile_validate")
evaluation_summary = load("evaluation_summary")
callback_review = load("embodied_callback_review")
fake_sink = load("joint_command_fake_sink")
source_slice_validator = load("source_slice_plan_validate")


def main():
    raw = [
        {"file": "x.cc", "line": 10, "cwe": 125, "pattern": "nested_index", "evidence": "a[i]", "context": "ctx", "desc": "d"},
        {"file": "x.cc", "line": 10, "cwe": 125, "pattern": "index_write_raw", "evidence": "a[i] =", "context": "ctx2", "desc": "d"},
        {"file": "x.cc", "line": 11, "cwe": 369, "pattern": "divide_by_input", "evidence": "x / d", "context": "ctx3", "desc": "d"},
    ]
    merged = detect.merge_findings(raw)
    assert len(merged) == 2
    assert set(merged[0]["patterns"]) == {"nested_index", "index_write_raw"}
    assert len(merged[0]["evidence_items"]) == 2
    assert merged[0]["finding_key"].startswith("cr-")
    safe = {"file": "x.cc", "line": 1, "cwe": 125, "pattern": "nested_index", "evidence": "if (message == nullptr)", "context": "", "desc": ""}
    assert detect.filter_false_positive(safe, [safe["evidence"]], 1)
    assert detect.filter_false_positive({"pattern": "divide_by_input"}, ["x / 4;"], 1)
    assert detect.filter_false_positive({"pattern": "mod_by_input"}, ["x % mjNFRAME;"], 1)
    assert not detect.filter_false_positive({"pattern": "divide_by_input"}, ["x / freq_;"], 1)
    assert not detect.filter_false_positive({"pattern": "divide_by_input"}, ["x / state_bytes;"], 1)
    assert detect.filter_false_positive({"pattern": "divide_by_input"}, ["if (interval > 0) { x / interval;"], 1)
    ext = {"pattern": "nested_index", "evidence": "json[root][i]", "context": "request payload"}
    ext["evidence_source"] = detect.classify_evidence(ext)
    ext["confidence"] = detect.confidence_for(ext)
    assert ext["evidence_source"] == "external-like"
    assert ext["confidence"] == "high"
    internal = {"pattern": "nested_index", "evidence": "sim->qpos_[i]", "context": "internal state"}
    assert detect.classify_evidence(internal) != "external-like"
    agibot = {"pattern": "nested_index", "evidence": "joint_state_data.position[index]", "context": "sensor_msgs JointState callback"}
    agibot["evidence_source"] = detect.classify_evidence(agibot, "agibot")
    agibot["confidence"] = detect.confidence_for(agibot)
    assert agibot["evidence_source"] == "external-like"
    assert agibot["confidence"] == "high"
    req = detect.repair_requirements({"pattern": "nested_index", "evidence": "cmd.position[index]", "context": "joint_state_index_map_[name]"})
    assert any("key existence" in item for item in req)
    assert any("derived index" in item for item in req)
    assert detect.repair_requirements({"pattern": "parallel_array_loop"}) == ["validate all parallel array lengths before the loop"]
    offset = {"pattern": "config_pointer_offset", "evidence": "send + ACTUATOR_FRAME_SIZE * (id_ - 1)", "context": "can_id config"}
    assert detect.classify_evidence(offset, "agibot") == "external-like"
    assert len(detect.repair_requirements(offset)) == 2
    it = {"pattern": "iterator_end_deref", "evidence": "iter->second", "context": "config.begin()"}
    assert len(detect.repair_requirements(it)) == 2
    loader = {"pattern": "loader_result_deref", "evidence": "mj_loadXML(...); m_->njnt", "context": "model load failure"}
    assert len(detect.repair_requirements(loader)) == 2
    contract = {"pattern": "declared_length_contract", "evidence": "observations_size resize and CreateTensor", "context": "onnx input shape"}
    assert len(detect.repair_requirements(contract)) == 2
    memcpy = {"pattern": "memcpy_source_contract", "evidence": "memcpy(position.data(), d_->qpos+7, joint_names_.size() * sizeof(double))", "context": "JointState"}
    assert len(detect.repair_requirements(memcpy)) == 2
    config_index = {"pattern": "config_index_access", "evidence": "joy_data.buttons[button]", "context": "buttons from YAML config"}
    assert len(detect.repair_requirements(config_index)) == 2
    output_contract = {"pattern": "model_output_contract", "evidence": "output_values[0].GetTensorMutableData<float>() + i", "context": "actions_size"}
    assert len(detect.repair_requirements(output_contract)) == 2
    assert len(detect.repair_requirements({"pattern": "partial_param_id_guard"})) == 2
    assert len(detect.repair_requirements({"pattern": "unchecked_blob_index"})) == 2
    assert len(detect.repair_requirements({"pattern": "unchecked_parser_count"})) == 2
    assert len(detect.repair_requirements({"pattern": "array_length_contract"})) == 2
    header = {"pattern": "text_layer_header_contract", "evidence": "SCAN_VALUE(\\\"%255s\\\", layer_type)", "context": "layer header"}
    assert len(detect.repair_requirements(header)) == 2
    assert detect.confidence_for({"pattern": "text_layer_header_contract"}) == "high"
    assert detect.confidence_for({"pattern": "parser_error_continue"}) == "high"
    assert len(detect.repair_requirements({"pattern": "parser_error_continue"})) == 2
    command = {"pattern": "command_from_config", "evidence": "system(cmd.data())", "context": "service_name interface_type config"}
    assert len(detect.repair_requirements(command)) == 2
    assert symmetry.check_symmetry
    finding = {"file": "rl_controller.cc", "line": 231, "evidence_lines": [231]}
    assert leaderboard.location_match(finding, "rl_controller.cc:196-232")
    assert not leaderboard.location_match(finding, "rl_controller.cc:100-120")
    assert leaderboard.location_match({"file": "rl_controller.cc", "line": 156}, "rl_controller.cc:96-120/156-160/210-217")
    assert leaderboard.nearby_finding({"file": "net.cpp", "line": 1810}, "src/net.cpp:1809/1822")
    assert not leaderboard.nearby_finding({"file": "net.cpp", "line": 500}, "src/net.cpp:1809/1822")
    guard_lines = [""] * 1809 + ["if (bottom_blob_index < 0 || bottom_blob_index >= blob_count)"]
    assert leaderboard.has_nearby_guard(guard_lines, "src/net.cpp:1809/1822", [__import__('re').compile(r"bottom_blob_index\s*<\s*0")])
    count_lines = [""] * 1714 + ["if (layer_count <= 0 || blob_count > MAX_BLOB_COUNT)"]
    assert leaderboard.has_nearby_guard(count_lines, "src/net.cpp:1699-1709", [__import__('re').compile(r"layer_count\s*[<>]=?\s*(?:MAX_|0)")])
    with tempfile.TemporaryDirectory() as guarded_src:
        Path(guarded_src, "net.cpp").write_text("\n" * 1698 + "if (layer_count <= 0 || blob_count > MAX_BLOB_COUNT) {}\n", encoding="utf-8")
        assert leaderboard.guarded_status("Tencent ncnn", 400, guarded_src, ["src/net.cpp:1699-1709"])[0]
    checked_addition_base = (
        "void MemcpyToBuf(size_t size_expression) {\n"
        "  if (g_hash_offset + size_expression >= g_hash_buf_size) return;\n"
        "  g_hash_offset += size_expression;\n"
        "}\n"
    )
    checked_addition_head = (
        "void MemcpyToBuf(size_t size_expression) {\n"
        "  if (MS_UNLIKELY(static_cast<uint64_t>(g_hash_offset) > SIZE_MAX - size_expression)) {\n"
        "    return;\n"
        "  }\n"
        "  if (g_hash_offset + size_expression >= g_hash_buf_size) return;\n"
        "  g_hash_offset += size_expression;\n"
        "}\n"
    )
    checked_addition = checked_addition_contract.validate_pair(
        checked_addition_base, checked_addition_head, "g_hash_offset", "size_expression"
    )
    assert checked_addition["verdict"] == "STATIC_CONTRACT_DELTA_VERIFIED"
    assert checked_addition["checks"]["head_guard_returns_before_operation"] is True
    missing_checked_addition = checked_addition_contract.validate_pair(
        checked_addition_base, checked_addition_base, "g_hash_offset", "size_expression"
    )
    assert "head-representability-guard-missing" in missing_checked_addition["errors"]

    with tempfile.TemporaryDirectory() as dettd:
        dettd = Path(dettd)
        before = dettd / "before.cpp"
        after = dettd / "after.cpp"
        before.write_text(
            "int f(int id, int len, int bottom_blob_index, int blob_count, int layer_count) {\n"
            "    if (id >= NCNN_MAX_PARAM_COUNT) return -1;\n"
            "    d->params[id].v.create(len);\n"
            "    d->blobs[bottom_blob_index].consumer = 0;\n"
            "    d->layers.resize(layer_count);\n"
            "    return 0;\n}\n", encoding="utf-8")
        after.write_text(
            "int f(int id, int len, int bottom_blob_index, int blob_count, int layer_count) {\n"
            "    if (id < 0 || id >= NCNN_MAX_PARAM_COUNT) return -1;\n"
            "    if (len <= 0) return -1;\n"
            "    d->params[id].v.create(len);\n"
            "    if (d->params[id].v.empty()) return -1;\n"
            "    if (bottom_blob_index < 0 || bottom_blob_index >= blob_count) return -1;\n"
            "    d->blobs[bottom_blob_index].consumer = 0;\n"
            "    if (layer_count <= 0 || layer_count > MAX_LAYER_COUNT) return -1;\n"
            "    d->layers.resize(layer_count);\n"
            "    return 0;\n}\n", encoding="utf-8")
        before_findings = detect.detect_in_file(str(before), {190, 476, 787}, component="ncnn")
        after_findings = detect.detect_in_file(str(after), {190, 476, 787}, component="ncnn")
        before_patterns = {item["pattern"] for item in before_findings}
        after_patterns = {item["pattern"] for item in after_findings}
        assert {"array_length_contract", "unchecked_blob_index", "unchecked_parser_count"} <= before_patterns
        assert not ({"array_length_contract", "unchecked_blob_index", "unchecked_parser_count"} & after_patterns)

    fixture_dir = ROOT.parent / "examples"
    text_header = detect.detect_in_file(str(fixture_dir / "ncnn_text_layer_header_before.cpp"), {787}, component="ncnn")
    assert any(item["pattern"] == "text_layer_header_contract" for item in text_header)
    text_count_before = detect.detect_in_file(str(fixture_dir / "ncnn_text_layer_header_before.cpp"), {190, 787}, component="ncnn")
    text_count_after = detect.detect_in_file(str(fixture_dir / "ncnn_text_layer_header_counts_after.cpp"), {190, 787}, component="ncnn")
    assert any(item["pattern"] == "unchecked_parser_count" for item in text_count_before)
    assert not any(item["pattern"] == "unchecked_parser_count" for item in text_count_after)
    assert any(item["pattern"] == "text_layer_header_contract" for item in text_count_after)
    with tempfile.TemporaryDirectory() as text_idx_td:
        text_idx_td = Path(text_idx_td)
        text_idx_before = text_idx_td / "before.cpp"
        text_idx_after = text_idx_td / "after.cpp"
        text_idx_before.write_text(
            "void f(int blob_index, int blob_count) {\n"
            "    Blob& blob = d->blobs[blob_index];\n"
            "    use(blob);\n}\n", encoding="utf-8")
        text_idx_after.write_text(
            "void f(int blob_index, int blob_count) {\n"
            "    if (blob_index < 0 || blob_index >= blob_count) return;\n"
            "    Blob& blob = d->blobs[blob_index];\n"
            "    use(blob);\n}\n", encoding="utf-8")
        text_idx_before_findings = detect.detect_in_file(str(text_idx_before), {787}, component="ncnn")
        text_idx_after_findings = detect.detect_in_file(str(text_idx_after), {787}, component="ncnn")
        assert any(item["pattern"] == "text_blob_index_access" for item in text_idx_before_findings)
        assert not any(item["pattern"] == "text_blob_index_access" for item in text_idx_after_findings)

    text_idx_before_fixture = detect.detect_in_file(str(fixture_dir / "ncnn_text_blob_index_before.cpp"), {787}, component="ncnn")
    text_idx_after_fixture = detect.detect_in_file(str(fixture_dir / "ncnn_text_blob_index_after.cpp"), {787}, component="ncnn")
    assert any(item["pattern"] == "text_blob_index_access" for item in text_idx_before_fixture)
    assert not any(item["pattern"] == "text_blob_index_access" for item in text_idx_after_fixture)
    yolo_evidence = evidence.compare_guard(
        str(fixture_dir / "ncnn_yolo_softmax_before.cpp"),
        str(fixture_dir / "ncnn_yolo_softmax_after.cpp"),
        r"\bsoftmax\s*=\s*0\b",
    )
    assert not yolo_evidence["before"] and len(yolo_evidence["after"]) == 1
    assert evidence.build_evidence_summary(yolo_evidence)["runtime_verdict"] == "REVIEW"

    len_before = detect.detect_in_file(str(fixture_dir / "ncnn_paramdict_len_before.cpp"), {476}, component="ncnn")
    len_after = detect.detect_in_file(str(fixture_dir / "ncnn_paramdict_len_after.cpp"), {476}, component="ncnn")
    assert any(item["pattern"] == "array_length_contract" for item in len_before)
    assert not any(item["pattern"] == "array_length_contract" for item in len_after)
    len_evidence = evidence.compare_guard(
        str(fixture_dir / "ncnn_paramdict_len_before.cpp"),
        str(fixture_dir / "ncnn_paramdict_len_after.cpp"),
        r"d->params\s*\[\s*id\s*\]\.v\.create\(\s*len\s*\)",
    )
    assert evidence.build_evidence_summary(len_evidence)["runtime_verdict"] == "REVIEW"

    with tempfile.TemporaryDirectory() as evtd:
        before = Path(evtd) / "before.cpp"
        after = Path(evtd) / "after.cpp"
        before.write_text("if (id >= MAX_COUNT) return -1;\n", encoding="utf-8")
        after.write_text("if (id < 0 || id >= MAX_COUNT) return -1;\n", encoding="utf-8")
        ev = evidence.compare_guard(str(before), str(after), r"id\s*<\s*0|id\s*>=\s*MAX_COUNT")
        assert ev["changed"] and len(ev["before"]) == 1 and len(ev["after"]) == 1
        summary = evidence.build_evidence_summary(ev, {"summary": {"verdict": "PASS"}})
        assert summary["complete"] and summary["runtime_verdict"] == "PASS"
        review = evidence.build_evidence_summary(ev)
        assert not review["complete"] and review["runtime_verdict"] == "REVIEW"

    workspace = ROOT.parent.parent.parent.parent
    symmetry_cli = subprocess.run(
        [sys.executable, str(ROOT / "symmetry_check.py"), str(workspace / "TOOLTEST_NCNN"),
         "--file", "net.cpp", "--json"],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert symmetry_cli.returncode == 0, symmetry_cli.stderr
    symmetry_result = json.loads(symmetry_cli.stdout)
    assert symmetry_result["files_scanned"] == 1 and symmetry_result["symmetric"]
    patch_summary = evidence.summarize_patch(
        str(workspace / "NCNN" / "上报材料" / "PR-6922合并修复.patch"),
        [r"MAX_(?:LAYER|BLOB)_COUNT", r"bottom_blob_index\s*<\s*0", r"top_count\s*>\s*0"],
    )
    assert "src/net.cpp" in patch_summary["files"]
    assert len(patch_summary["added_guard_lines"]) >= 4
    assert patch_summary["source_proof"] is False
    assert "GUARDED" in {"HIT", "GUARDED", "MISS"}
    yolo_patch_summary = evidence.summarize_patch(
        str(workspace / "NCNN" / "上报材料" / "PR-YoloDetectionOutput-softmax初始化修复.patch"),
        [r"\bsoftmax\s*=\s*0\b"],
    )
    assert yolo_patch_summary["files"] == ["src/layer/yolodetectionoutput.cpp"]
    assert len(yolo_patch_summary["added_lines"]) == 1
    assert len(yolo_patch_summary["added_guard_lines"]) == 1
    assert yolo_patch_summary["source_proof"] is False
    blob_fragment_relation = evidence.check_patch_addition_subset(
        str(workspace / "NCNN" / "上报材料" / "PR-6922合并修复.patch"),
        str(workspace / "NCNN" / "上报材料" / "PR-blob索引修复.patch"),
    )
    assert blob_fragment_relation["addition_subset"]
    assert blob_fragment_relation["contained_added_lines"] == blob_fragment_relation["fragment_added_lines"]
    with tempfile.TemporaryDirectory() as blob_td:
        blob_root = Path(blob_td)
        blob_source = blob_root / "src" / "net.cpp"
        blob_source.parent.mkdir()
        blob_source.write_text((workspace / "TOOLTEST_NCNN" / "net.cpp").read_text(encoding="utf-8"), encoding="utf-8")
        blob_post = detect.detect_in_file(str(blob_source), {787}, component="ncnn")
        reversed_patch = subprocess.run(
            ["git", "-C", str(blob_root), "apply", "--reverse",
             str(workspace / "NCNN" / "上报材料" / "PR-blob索引修复.patch")],
            capture_output=True, text=True,
        )
        assert reversed_patch.returncode == 0, reversed_patch.stderr
        blob_pre = detect.detect_in_file(str(blob_source), {787}, component="ncnn")
        post_bin_candidates = sum(
            item["pattern"] == "unchecked_blob_index" and item["line"] > 1700 for item in blob_post
        )
        pre_bin_candidates = sum(
            item["pattern"] == "unchecked_blob_index" and item["line"] > 1700 for item in blob_pre
        )
        assert (post_bin_candidates, pre_bin_candidates) == (0, 2)
    paramdict_application = evidence.check_patch_application(
        str(workspace / "NCNN" / "复现工具" / "paramdict_vuln.cpp"),
        str(workspace / "NCNN" / "上报材料" / "PR-paramdict数组len校验修复.patch"),
        "src/paramdict.cpp",
    )
    assert paramdict_application["forward_applicable"]
    assert not paramdict_application["reverse_applicable"]
    with tempfile.TemporaryDirectory() as direct_td:
        direct_root = Path(direct_td)
        (direct_root / "paramdict_vuln.cpp").write_text(
            (workspace / "NCNN" / "复现工具" / "paramdict_vuln.cpp").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(direct_root), "init", "-q"], check=True)
        direct_check = subprocess.run(
            ["git", "-C", str(direct_root), "apply", "--check",
             str(workspace / "NCNN" / "上报材料" / "PR-paramdict数组len校验修复.patch")],
            capture_output=True, text=True,
        )
        assert direct_check.returncode != 0
    patch_cli = subprocess.run(
        [sys.executable, str(ROOT / "repair_evidence.py"),
         "--source", str(workspace / "NCNN" / "复现工具" / "paramdict_vuln.cpp"),
         "--patch", str(workspace / "NCNN" / "上报材料" / "PR-paramdict数组len校验修复.patch"),
         "--target-path", "src/paramdict.cpp", "--json"],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert patch_cli.returncode == 0, patch_cli.stderr
    assert json.loads(patch_cli.stdout)["forward_applicable"]
    relation_cli = subprocess.run(
        [sys.executable, str(ROOT / "repair_evidence.py"),
         "--container-patch", str(workspace / "NCNN" / "上报材料" / "PR-6922合并修复.patch"),
         "--fragment-patch", str(workspace / "NCNN" / "上报材料" / "PR-blob索引修复.patch"),
         "--json"],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert relation_cli.returncode == 0, relation_cli.stderr
    assert json.loads(relation_cli.stdout)["addition_subset"]
    net_application = evidence.check_patch_application(
        str(workspace / "TOOLTEST_NCNN" / "net.cpp"),
        str(workspace / "NCNN" / "上报材料" / "PR-6922合并修复.patch"),
        "src/net.cpp",
    )
    assert not net_application["forward_applicable"]
    assert net_application["reverse_applicable"]
    text_count_application = evidence.check_patch_application(
        str(workspace / "TOOLTEST_NCNN" / "net.cpp"),
        str(workspace / "NCNN" / "上报材料" / "PR-text层头校验修复.patch"),
        "src/net.cpp",
    )
    assert not text_count_application["forward_applicable"]
    assert text_count_application["reverse_applicable"]
    net_text_candidates = detect.detect_in_file(str(workspace / "TOOLTEST_NCNN" / "net.cpp"), {787}, component="ncnn")
    assert any(item["pattern"] == "text_layer_header_contract" for item in net_text_candidates)
    with tempfile.TemporaryDirectory() as patch_td:
        patch_root = Path(patch_td)
        patched_source = patch_root / "src" / "paramdict.cpp"
        patched_source.parent.mkdir()
        patched_source.write_text(
            (workspace / "NCNN" / "复现工具" / "paramdict_vuln.cpp").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        before_patch_findings = detect.detect_in_file(str(patched_source), {476}, component="ncnn")
        applied = subprocess.run(
            ["git", "-C", str(patch_root), "apply", str(workspace / "NCNN" / "上报材料" / "PR-paramdict数组len校验修复.patch")],
            capture_output=True, text=True,
        )
        assert applied.returncode == 0, applied.stderr
        after_patch_findings = detect.detect_in_file(str(patched_source), {476}, component="ncnn")
        before_patch_lines = [item["line"] for item in before_patch_findings if item["pattern"] == "array_length_contract"]
        after_patch_lines = [item["line"] for item in after_patch_findings if item["pattern"] == "array_length_contract"]
        assert (before_patch_lines, after_patch_lines) == ([297, 591], [297])
        bin_block = patched_source.read_text(encoding="utf-8").split("int ParamDict::load_param_bin", 1)[1]
        array_block = bin_block.rsplit("else if (is_array)", 1)[1]
        assert array_block.index("if (len <= 0)") < array_block.index("d->params[id].v.create(len)")
        assert array_block.index("d->params[id].v.create(len)") < array_block.index("if (d->params[id].v.empty())")
        assert array_block.index("if (d->params[id].v.empty())") < array_block.index("nread = dr.read(ptr,")
    paramdict_id_fix = detect.detect_in_file(
        str(workspace / "NCNN" / "复现工具" / "paramdict_fix.cpp"), {476}, component="ncnn"
    )
    assert [item["line"] for item in paramdict_id_fix if item["pattern"] == "array_length_contract"] == [297, 591]

    runtime_evidence_path = ROOT.parent / "examples" / "ncnn_pr6922_runtime_evidence.json"
    runtime_evidence = json.loads(runtime_evidence_path.read_text(encoding="utf-8"))
    assert runtime_evidence["scoped_summary"]["bin_malicious_rejected"] == "2/2"
    assert runtime_evidence["scoped_summary"]["bin_benign_passed"] == "1/1"
    assert runtime_evidence["scoped_summary"]["text_count_malicious_rejected"] == "1/1"
    assert runtime_evidence["scoped_summary"]["text_blob_index_residual"] is True
    assert runtime_evidence["scoped_summary"]["runtime_infrastructure_failures"] == 0

    v2_path = ROOT.parent / "examples" / "ncnn_history_benchmark_v2.json"
    v2_data = benchmark_v2.read_json(v2_path)
    assert not benchmark_v2.validate_data(v2_data)
    v2_detector = benchmark_v2.load_detector()
    v2_results = [benchmark_v2.evaluate_case(case, v2_detector) for case in v2_data["cases"]]
    v2_summary = benchmark_v2.summarize(v2_results)
    assert v2_summary["cases"] == 8
    assert v2_summary["preimage_detection"]["HIT"] == 8
    assert v2_summary["postimage_guard"]["GUARDED"] == 6
    assert v2_summary["postimage_guard"]["GUARDED_SCOPED"] == 1
    assert v2_summary["postimage_guard"]["MISS"] == 1
    assert v2_summary["provenance_complete"] == 8
    assert v2_summary["strict_eligible_cases"] == 3
    assert v2_summary["legacy_benchmark_untouched"]
    assert any(item["id"] == "NCNN-PR-6922-BIN-INDEX-GUARD"
               and item["postimage_guard"]["status"] == "GUARDED_SCOPED"
               for item in v2_results)
    assert any(item["id"] == "NCNN-PR-6922-TEXT-BLOB-RESIDUAL"
               and item["postimage_guard"]["status"] == "MISS"
               for item in v2_results)
    assert any(item["id"] == "NCNN-LOCAL-PR6922-TEXT-BLOB-FIX"
               and item["postimage_guard"]["status"] == "GUARDED"
               and item["strict_eligible"] is False
               for item in v2_results)
    fixture_dir = ROOT.parent / "examples"
    registry_path = fixture_dir / "embodied_ai_pr_case_registry.json"
    registry_data = json.loads(registry_path.read_text(encoding="utf-8"))
    registry_errors = pr_registry.validate(registry_data)
    assert not registry_errors
    registry_summary = pr_registry.summarize(registry_data)
    assert registry_summary["cases"] == 12
    assert registry_summary["by_materialization"].get("external-reference", 0) == 0
    assert registry_summary["accepted_with_local_provenance"] == 5
    assert registry_summary["legacy_dataset_impact"] == "none"
    ms87710_screening = json.loads((fixture_dir / "ms_pr87710_screening.json").read_text(encoding="utf-8"))
    assert ms87710_screening["screening"]["title_diff_contract_match"] is True
    assert ms87710_screening["screening"]["decision"] == "OFFICIAL_LOCAL_SOURCE_SCOPE_AND_STATIC_CONTRACT_VERIFIED_REVIEW"
    assert ms87710_screening["source_materialization"]["static_contract_verdict"] == "STATIC_CONTRACT_DELTA_VERIFIED"
    assert ms87710_screening["changed_scope"]["files_changed"] == 1
    assert ms87710_screening["status"] == "REVIEW"
    ms87710_static = json.loads((fixture_dir / "ms_pr87710_static_contract_evidence.json").read_text(encoding="utf-8"))
    assert ms87710_static["static_validator"]["verdict"] == "STATIC_CONTRACT_DELTA_VERIFIED"
    assert ms87710_static["contract"]["head"]["guard_returns_before_operation"] is True
    assert ms87710_static["runtime"]["status"] == "NOT_RUN"
    assert any(item.get("pr_number") == 87710 and item.get("status") == "screened-local-source-static-contract-review" for item in registry_data["candidate_sources"])
    ort_build = json.loads((fixture_dir / "ort_pr28003_full_build_evidence.json").read_text(encoding="utf-8"))
    assert ort_build["head_sha"] == "795675a77ebb898302c5798bd6247658db165d14"
    assert ort_build["configure"]["status"] == "PASS"
    assert ort_build["build"]["target"] == "onnxruntime_provider_test"
    assert ort_build["build"]["target_includes_rnn_op_test"] is True
    assert ort_build["build"]["status"] in {"RUNNING", "PASS", "REVIEW"}
    assert ort_build["base_build"]["status"] == "PASS"
    assert ort_build["base_build"]["target_includes_rnn_op_test"] is True
    assert ort_build["base_build"]["binary_sha256"] == "6d3dc79a07cc129deef5da44a6158412f2e7df82a3ec91a14a38fd7d2ffc8c24"
    assert ort_build["source_probe"]["source_scope_integrity"] == "ort_pr28003_source_scope_integrity.json"
    assert ort_build["source_probe"]["target_binding_limit"].startswith("onnxruntime_provider_test manifest")
    ort_source_scope = json.loads((fixture_dir / "ort_pr28003_source_scope_integrity.json").read_text(encoding="utf-8"))
    assert ort_source_scope["status"] == "PAIRED_SOURCE_SCOPE_VERIFIED"
    assert ort_source_scope["build_and_runtime_binding"]["safeint_test_target_or_runtime"] == "PAIRED_BUILD_VERIFIED_NOT_RUN"
    assert len(ort_source_scope["changed_scope"]["files"]) == 4
    safeint_test_scope = next(item for item in ort_source_scope["changed_scope"]["files"] if item["path"].endswith("safeint_test.cc"))
    assert safeint_test_scope["status"] == "added"
    assert safeint_test_scope["base_git_blob"] is None
    safeint_build_plan = json.loads((fixture_dir / "ort_pr28003_safeint_build_plan.json").read_text(encoding="utf-8"))
    assert safeint_build_plan["execution"]["mode"] == "build-only"
    assert safeint_build_plan["execution"]["test_binary_execution"] is False
    assert safeint_build_plan["base"]["manifest_test_source_count"] == 108
    assert safeint_build_plan["head"]["manifest_test_source_count"] == 109
    assert safeint_build_plan["head"]["safeint_test_manifest_entry"] is True
    assert ort_build["runtime"]["status"] == "HEAD_DIRECT_RUNTIME_PASS_WITH_BASE_SHARED_CONTROL_PASS"
    paired_evidence = json.loads((fixture_dir / "ort_pr28003_paired_build_evidence.json").read_text(encoding="utf-8"))
    assert paired_build.validate_evidence(paired_evidence)["verdict"] == "PAIRED_BUILD_VERIFIED"
    paired_fixture = {
        "case_id": "ORT-PR-28003",
        "target": "onnxruntime_provider_test",
        "base": {
            "sha": "0fedb26c93e6c29882185715d5c2bb583a6d92b5",
            "configure": {"status": "PASS"},
            "build": {
                "status": "PASS",
                "target": "onnxruntime_provider_test",
                "target_includes_contract_test": True,
                "target_source_manifest": "DependInfo.cmake:183",
                "contract_test_source": "onnxruntime/test/providers/cpu/rnn/rnn_op_test.cc",
                "binary_sha256": "0" * 64,
            },
        },
        "head": {
            "sha": ort_build["head_sha"],
            "configure": {"status": "PASS"},
            "build": {
                "status": ort_build["build"]["status"],
                "target": ort_build["build"]["target"],
                "target_includes_contract_test": ort_build["build"]["target_includes_rnn_op_test"],
                "target_source_manifest": ort_build["build"]["target_source_manifest"],
                "contract_test_source": ort_build["source_probe"]["rnn_test_source"],
                "binary_sha256": ort_build["build"]["binary_sha256"],
            },
        },
        "toolchain": {"cmake": "3.31.10", "compiler": "c++", "generator": "Unix Makefiles"},
        "runtime": {"base": "NOT_RUN", "head": "NOT_RUN"},
    }
    paired_result = paired_build.validate_evidence(paired_fixture)
    assert paired_result["valid"] is (ort_build["build"]["status"] == "PASS")
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        target_name = "onnxruntime_test_all"
        shared_source = "onnxruntime/test/common/common_test.cc"
        added_source = "onnxruntime/test/common/safeint_test.cc"
        base_root = temp_root / "base-source"
        head_root = temp_root / "head-source"
        for source_root in (base_root, head_root):
            (source_root / Path(shared_source).parent).mkdir(parents=True)
            (source_root / shared_source).write_text("// shared\n", encoding="utf-8")
        (head_root / added_source).write_text("// added\n", encoding="utf-8")
        base_build_dir = temp_root / "base-build"
        head_build_dir = temp_root / "head-build"
        base_build_dir.mkdir()
        head_build_dir.mkdir()
        base_manifest = base_build_dir / "CMakeFiles" / f"{target_name}.dir" / "DependInfo.cmake"
        head_manifest = head_build_dir / "CMakeFiles" / f"{target_name}.dir" / "DependInfo.cmake"
        def manifest_entry(source_root, build_dir, relative):
            source_path = (source_root / relative).as_posix()
            object_relative = Path("CMakeFiles") / f"{target_name}.dir" / f"{relative}.o"
            object_path = build_dir / object_relative
            object_path.parent.mkdir(parents=True, exist_ok=True)
            object_path.write_bytes(f"object for {relative}".encode())
            object_path_d = f"{object_relative.as_posix()}.d"
            return f'  "{source_path}" "{object_relative.as_posix()}" "gcc" "{object_path_d}"\n'
        base_manifest.parent.mkdir(parents=True)
        head_manifest.parent.mkdir(parents=True)
        base_manifest.write_text("set(CMAKE_DEPENDS_DEPENDENCY_FILES\n" + manifest_entry(base_root, base_build_dir, shared_source) + ")\n", encoding="utf-8")
        head_manifest.write_text("set(CMAKE_DEPENDS_DEPENDENCY_FILES\n" + manifest_entry(head_root, head_build_dir, shared_source) + manifest_entry(head_root, head_build_dir, added_source) + ")\n", encoding="utf-8")
        cache_text = "CMAKE_BUILD_TYPE:STRING=Debug\nCMAKE_CXX_COMPILER:FILEPATH=/usr/bin/c++\nCMAKE_GENERATOR:INTERNAL=Unix Makefiles\nCMAKE_CXX_FLAGS:STRING=\nCMAKE_CXX_FLAGS_DEBUG:STRING=-g\nCMAKE_CXX_STANDARD:STRING=17\n"
        base_cache = base_build_dir / "CMakeCache.txt"
        head_cache = head_build_dir / "CMakeCache.txt"
        base_cache.write_text(cache_text, encoding="utf-8")
        head_cache.write_text(cache_text, encoding="utf-8")
        base_binary = base_build_dir / target_name
        head_binary = head_build_dir / target_name
        base_binary.write_bytes(b"base test target")
        head_binary.write_bytes(b"head test target")
        added_test_fixture = {
            "case_id": "ORT-PR-28003",
            "target": target_name,
            "added_contract_test_source": added_source,
            "head_added_test_source_sha256": hashlib.sha256((head_root / added_source).read_bytes()).hexdigest(),
            "configuration": {"CMAKE_BUILD_TYPE": "Debug", "CMAKE_CXX_COMPILER": "/usr/bin/c++", "CMAKE_GENERATOR": "Unix Makefiles", "CMAKE_CXX_FLAGS": "", "CMAKE_CXX_FLAGS_DEBUG": "-g", "CMAKE_CXX_STANDARD": "17"},
            "base": {
                "sha": "a" * 40,
                "source_root": str(base_root),
                "configure": {"status": "PASS", "cmake_cache": str(base_cache)},
                "build": {"status": "PASS", "exit_code": 0, "build_dir": str(base_build_dir), "target": target_name, "target_source_manifest": str(base_manifest), "manifest_test_source_count": 1, "binary": str(base_binary), "binary_size": base_binary.stat().st_size, "binary_sha256": hashlib.sha256(base_binary.read_bytes()).hexdigest()}, 
            },
            "head": {
                "sha": "b" * 40,
                "source_root": str(head_root),
                "configure": {"status": "PASS", "cmake_cache": str(head_cache)},
                "build": {"status": "PASS", "exit_code": 0, "build_dir": str(head_build_dir), "target": target_name, "target_source_manifest": str(head_manifest), "manifest_test_source_count": 2, "binary": str(head_binary), "binary_size": head_binary.stat().st_size, "binary_sha256": hashlib.sha256(head_binary.read_bytes()).hexdigest(), "added_test_object": str(head_build_dir / Path("CMakeFiles") / f"{target_name}.dir" / f"{added_source}.o"), "added_test_object_size": (head_build_dir / Path("CMakeFiles") / f"{target_name}.dir" / f"{added_source}.o").stat().st_size, "added_test_object_sha256": hashlib.sha256((head_build_dir / Path("CMakeFiles") / f"{target_name}.dir" / f"{added_source}.o").read_bytes()).hexdigest()}, 
            },
            "toolchain": {"cmake": "3.31.10", "compiler": "/usr/bin/c++", "generator": "Unix Makefiles"},
            "execution": {"mode": "build-only", "test_binary_execution": False},
            "runtime": {"base": "NOT_RUN", "head": "NOT_RUN"},
        }
        added_test_result = added_test_target_build.validate_evidence(added_test_fixture)
        assert added_test_result["valid"] is True
        assert added_test_result["verdict"] == "REVIEW"
        assert added_test_result["build_only_status"] == "BUILD_ONLY_NOT_RUN"
        build_only_case = {"evidence": {"runtime": added_test_result["build_only_status"]}}
        assert lattice.classify_case(build_only_case)["gate_status"]["runtime"] == "missing"
        assert pr_readiness.meaningful(added_test_result["build_only_status"], "runtime") is False
        bad_added_test_fixture = json.loads(json.dumps(added_test_fixture))
        bad_added_test_fixture["head"]["build"]["manifest_test_source_count"] = True
        assert "head-manifest-count-invalid" in added_test_target_build.validate_evidence(bad_added_test_fixture)["errors"]
        head_manifest.write_text("set(CMAKE_DEPENDS_DEPENDENCY_FILES\n" + manifest_entry(head_root, head_build_dir, shared_source) + ")\n", encoding="utf-8")
        assert "head-manifest-excludes-added-test" in added_test_target_build.validate_evidence(added_test_fixture)["errors"]
        head_manifest.write_text("set(CMAKE_DEPENDS_DEPENDENCY_FILES\n" + manifest_entry(head_root, head_build_dir, shared_source) + manifest_entry(head_root, head_build_dir, added_source) + ")\n", encoding="utf-8")
        contradictory_runtime_fixture = json.loads(json.dumps(added_test_fixture))
        contradictory_runtime_fixture["runtime"]["status"] = "PASS"
        assert "runtime-must-be-exactly-not-run" in added_test_target_build.validate_evidence(contradictory_runtime_fixture)["errors"]
        mismatched_toolchain_fixture = json.loads(json.dumps(added_test_fixture))
        mismatched_toolchain_fixture["toolchain"]["compiler"] = "c++"
        assert "toolchain-compiler-does-not-match-configuration" in added_test_target_build.validate_evidence(mismatched_toolchain_fixture)["errors"]
        missing_binary_fixture = json.loads(json.dumps(added_test_fixture))
        missing_binary_fixture["head"]["build"]["binary"] = str(temp_root / "missing" / target_name)
        assert "head-binary-not-target-output" in added_test_target_build.validate_evidence(missing_binary_fixture)["errors"]
        assert "record-root-not-object" in added_test_target_build.validate_evidence(None)["errors"]
    gtest_plan = {
        "case_id": "ORT-PR-28003",
        "execution_scope": "local-pinned-binary-only",
        "binary": "/nonexistent/onnxruntime_provider_test",
        "timeout_seconds": 120,
        "cases": [
            {"id": "seq-zero", "filter": "RNNTest.RNN_seq_length_zero", "expected_test_count": 1},
            {"id": "lens-zero", "filter": "RNNTest.RNN_forward_sequence_lens_with_zero", "expected_test_count": 1},
        ],
        "safety": {
            "no_external_inputs": True,
            "no_network_target_execution": True,
            "no_oom_or_huge_allocation": True,
            "no_exploit_chain": True,
        },
    }
    gtest_result = gtest_runtime.execute_plan(gtest_plan)
    assert gtest_result["status"] == "REVIEW"
    assert "binary-missing" in gtest_result["errors"]
    gtest_summary = gtest_runtime.parse_gtest_summary("[==========] Running 1 test from 1 test suite.\n[  PASSED  ] 1 test.\n")
    assert gtest_summary == {"tests_run": 1, "tests_passed": 1, "tests_failed": 0, "tests_skipped": 0}
    invalid_gtest_plan = json.loads(json.dumps(gtest_plan))
    invalid_gtest_plan["cases"][0]["filter"] = "*"
    assert "case-0-filter-not-allowlisted" in gtest_runtime.validate_plan(invalid_gtest_plan)
    head_gtest_plan = json.loads((fixture_dir / "ort_pr28003_head_gtest_runtime_plan.json").read_text(encoding="utf-8"))
    assert gtest_runtime.validate_plan(head_gtest_plan) == []
    assert {item["filter"] for item in head_gtest_plan["cases"]} == {
        "RNNTest.RNN_seq_length_zero",
        "RNNTest.RNN_forward_sequence_lens_with_zero",
        "RNNTest.RNN_bidirectional_with_sequence_lens",
        "RNNTest.RNN_invalid_sequence_lens",
    }
    base_gtest_plan = json.loads((fixture_dir / "ort_pr28003_base_gtest_runtime_plan.json").read_text(encoding="utf-8"))
    assert gtest_runtime.validate_plan(base_gtest_plan) == []
    assert {item["filter"] for item in base_gtest_plan["cases"]} == {
        "RNNTest.RNN_bidirectional_with_sequence_lens",
        "RNNTest.RNN_invalid_sequence_lens",
    }
    base_full_rnn_plan = json.loads((fixture_dir / "ort_pr28003_base_full_rnn_suite_plan.json").read_text(encoding="utf-8"))
    head_full_rnn_plan = json.loads((fixture_dir / "ort_pr28003_head_full_rnn_suite_plan.json").read_text(encoding="utf-8"))
    assert gtest_runtime.validate_plan(base_full_rnn_plan) == []
    assert gtest_runtime.validate_plan(head_full_rnn_plan) == []
    assert base_full_rnn_plan["cases"][0]["expected_test_count"] == 10
    assert head_full_rnn_plan["cases"][0]["expected_test_count"] == 12
    base_gtest_evidence = json.loads((fixture_dir / "ort_pr28003_base_gtest_runtime_evidence.json").read_text(encoding="utf-8"))
    head_gtest_evidence = json.loads((fixture_dir / "ort_pr28003_head_gtest_runtime_evidence.json").read_text(encoding="utf-8"))
    assert base_gtest_evidence["source_revision"] == ort_build["base_sha"]
    assert base_gtest_evidence["binary_sha256"] == ort_build["base_build"]["binary_sha256"]
    assert base_gtest_evidence["summary"] == {"passed": "2/2", "verdict": "PASS"}
    assert head_gtest_evidence["source_revision"] == ort_build["head_sha"]
    assert head_gtest_evidence["binary_sha256"] == ort_build["build"]["binary_sha256"]
    assert head_gtest_evidence["summary"] == {"passed": "4/4", "verdict": "PASS"}
    base_full_rnn_evidence = json.loads((fixture_dir / "ort_pr28003_base_full_rnn_suite_evidence.json").read_text(encoding="utf-8"))
    head_full_rnn_evidence = json.loads((fixture_dir / "ort_pr28003_head_full_rnn_suite_evidence.json").read_text(encoding="utf-8"))
    assert base_full_rnn_evidence["cases"][0]["tests_run"] == 10
    assert base_full_rnn_evidence["cases"][0]["tests_passed"] == 10
    assert head_full_rnn_evidence["cases"][0]["tests_run"] == 12
    assert head_full_rnn_evidence["cases"][0]["tests_passed"] == 12
    paired_runtime = json.loads((fixture_dir / "ort_pr28003_paired_runtime_evidence.json").read_text(encoding="utf-8"))
    assert paired_runtime["status"] == "PAIRED_ACTIVE_RNN_SUITE_PASS_WITH_HEAD_DIRECT_REGRESSIONS"
    assert paired_runtime_evidence.validate_evidence(paired_runtime, fixture_dir)["verdict"] == "PAIRED_RUNTIME_EVIDENCE_VERIFIED"
    broken_paired_runtime = json.loads(json.dumps(paired_runtime))
    broken_paired_runtime["head"]["binary_sha256"] = "0" * 64
    assert "head-focused-binary-mismatch" in paired_runtime_evidence.validate_evidence(broken_paired_runtime, fixture_dir)["errors"]
    assert paired_runtime["comparison"]["shared_control_symmetry"] == "PASS"
    assert "sequence_lens={1,2,2}" in paired_runtime["shared_controls"][0]["coverage"]
    assert "not sequence_lens=0-alone rejection" in paired_runtime["shared_controls"][1]["coverage"]
    assert paired_runtime["comparison"]["full_active_rnn_suite"] == {"base": "10/10 PASS", "head": "12/12 PASS", "disabled_tests": "1 per revision; not executed"}
    runtime_audit = json.loads((fixture_dir / "ort_pr28003_runtime_contract_audit.json").read_text(encoding="utf-8"))
    assert runtime_audit["implementation_allows"] == ["len == 0", "len == seq_length"]
    assert runtime_audit["diagnostic_matches_predicate"] is False
    assert runtime_audit["runtime_test_coverage"]["RNNTest.RNN_seq_length_zero"]["source"].endswith("rnn_op_test.cc:889")
    assert "proof that sequence_lens=0 alone is rejected" in runtime_audit["runtime_test_coverage"]["RNNTest.RNN_invalid_sequence_lens"]["does_not_support"]
    assert "SafeMul/narrow overflow hardening" in runtime_audit["runtime_test_coverage"]["RNNTest.RNN_bidirectional_with_sequence_lens"]["does_not_support"]
    ort_feasibility = json.loads((fixture_dir / "ort_pr28003_build_feasibility.json").read_text(encoding="utf-8"))
    assert ort_feasibility["checks"]["configure_probe"] == "PASS"
    assert ort_feasibility["checks"]["full_source_probe_materialized"] is True
    path_inventory = json.loads((fixture_dir / "ort_pr28003_path_inventory.json").read_text(encoding="utf-8"))
    assert len(path_inventory["declared_paths"]) == 2
    assert path_inventory["verdict"] == "REVIEW"
    assert all(item["full_runtime"] == "DIRECT_CPU_RUNTIME_PASS_PARTIAL_CONTRACT" for item in path_inventory["declared_paths"])
    assert path_inventory["runtime_execution_plans"]["status"] == "PASS_WITH_PARTIAL_CONTRACT_COVERAGE"
    assert "formal all-path proof" in path_inventory["unverified_dimensions"]
    readiness = pr_readiness.build_queue(registry_data)
    readiness_snapshot = json.loads((fixture_dir / "embodied_ai_pr_readiness_queue.json").read_text(encoding="utf-8"))
    assert pr_readiness.validate_queue_snapshot(registry_data, readiness_snapshot)["valid"]
    stale_snapshot = json.loads(json.dumps(readiness_snapshot))
    stale_snapshot["case_count"] = 0
    stale_result = pr_readiness.validate_queue_snapshot(registry_data, stale_snapshot)
    assert not stale_result["valid"]
    assert "queue-drift-case_count" in stale_result["errors"]
    assert readiness["case_count"] == 12
    lattice_queue = lattice.classify_registry(registry_data)
    assert lattice_queue["evidence_level_counts"] == {
        "FULL_GATED_LOCAL": 4,
        "SCOPED_RUNTIME": 6,
        "LOCAL_STATIC": 2,
    }
    assert lattice_queue["anomalies"] == []
    assert readiness["priority_counts"].get("materialize-external-reference", 0) == 0
    assert readiness["priority_counts"]["complete-missing-gates"] == 8
    assert readiness["evidence_level_counts"] == {
        "FULL_GATED_LOCAL": 4,
        "SCOPED_RUNTIME": 6,
        "LOCAL_STATIC": 2,
    }
    local_case = next(item for item in readiness["assessments"] if item["id"] == "NCNN-LOCAL-PR6922-TEXT-BLOB-FIX")
    assert local_case["readiness_score"] == "8/8"
    assert local_case["priority"] == "ready-for-semantic-verification"
    assert local_case["evidence_level"] == "FULL_GATED_LOCAL"
    assert local_case["full_gate_ready"] is True
    open_case = next(item for item in readiness["assessments"] if item["id"] == "NCNN-PR-6922")
    assert open_case["priority"] == "complete-missing-gates"
    assert set(open_case["gaps"]) == {"symmetry", "runtime"}
    external_case = next(item for item in readiness["assessments"] if item["id"] == "ORT-PR-28003")
    assert external_case["readiness_score"] == "6/8"
    assert external_case["priority"] == "complete-missing-gates"
    assert external_case["evidence_level"] == "SCOPED_RUNTIME"
    assert external_case["gate_status"]["runtime"] == "missing"
    assert external_case["full_gate_ready"] is False
    qnn_case = next(item for item in readiness["assessments"] if item["id"] == "ORT-PR-23435")
    assert qnn_case["readiness_score"] == "7/8"
    assert qnn_case["priority"] == "complete-missing-gates"
    assert qnn_case["gaps"] == ["runtime"]
    assert qnn_case["evidence_level"] == "LOCAL_STATIC"
    assert qnn_case["gate_status"]["runtime"] == "missing"
    ms_case = next(item for item in readiness["assessments"] if item["id"] == "MS-PR-70694")
    assert ms_case["readiness_score"] == "4/8"
    assert ms_case["priority"] == "complete-missing-gates"
    assert set(ms_case["gaps"]) == {"detect", "repair_plan", "symmetry", "runtime"}
    assert ms_case["evidence_level"] == "LOCAL_STATIC"
    assert ms_case["gate_status"]["runtime"] == "missing"
    ort_narrow_case = next(item for item in readiness["assessments"] if item["id"] == "ORT-PR-28112")
    assert ort_narrow_case["readiness_score"] == "6/8"
    assert ort_narrow_case["priority"] == "complete-missing-gates"
    assert set(ort_narrow_case["gaps"]) == {"symmetry", "runtime"}
    assert ort_narrow_case["evidence_level"] == "SCOPED_RUNTIME"
    assert ort_narrow_case["gate_status"]["runtime"] == "scoped"
    ms_overflow_case = next(item for item in readiness["assessments"] if item["id"] == "MS-PR-89363")
    assert ms_overflow_case["readiness_score"] == "6/8"
    assert ms_overflow_case["priority"] == "complete-missing-gates"
    assert set(ms_overflow_case["gaps"]) == {"symmetry", "runtime"}
    assert ms_overflow_case["evidence_level"] == "SCOPED_RUNTIME"
    assert ms_overflow_case["gate_status"]["runtime"] == "scoped"
    ort_narrow_evidence = json.loads((fixture_dir / "ort_pr28112_provenance.json").read_text(encoding="utf-8"))
    assert ort_narrow_evidence["static"]["target_pattern"] == "static_cast_narrow_truncation"
    ort_narrow_runtime = json.loads((fixture_dir / "ort_pr28112_bounded_runtime_evidence.json").read_text(encoding="utf-8"))
    assert ort_narrow_runtime["reduced_runtime"]["summary"]["verdict"] == "PASS"
    assert ort_narrow_runtime["full_case_status"] == "REVIEW"
    ort_narrow_matrix = matrix_module.evaluate_matrix(json.loads((fixture_dir / "ort_pr28112_contract_matrix.json").read_text(encoding="utf-8")))
    assert ort_narrow_matrix["status"] == "REVIEW"
    assert ort_narrow_matrix["paths"][0]["residual_count"] == 0
    assert ort_narrow_matrix["paths"][0]["runtime_scope"] == "scoped"
    assert ort_narrow_matrix["paths"][0]["scoped_runtime_verdict"] == "PASS"
    ort_rnn_matrix = matrix_module.evaluate_matrix(json.loads((fixture_dir / "ort_pr28003_contract_matrix.json").read_text(encoding="utf-8")))
    assert ort_rnn_matrix["status"] == "REVIEW"
    assert all(path["runtime_scope"] == "scoped" for path in ort_rnn_matrix["paths"])
    assert all(path["scoped_runtime_verdict"] == "PASS" for path in ort_rnn_matrix["paths"])
    assert all(path["operator_runtime_scope"] == "local pinned full provider target; all active default-CPU RNNTest cases" for path in ort_rnn_matrix["paths"])
    assert all(path["operator_runtime_verdict"] == "PASS" for path in ort_rnn_matrix["paths"])
    assert all(path["status"] == "REVIEW" for path in ort_rnn_matrix["paths"])
    assert matrix_module.operator_runtime_summary({"verdict": "PASS", "scope": "local target"}) == {"scope": "local target", "verdict": "PASS"}
    assert matrix_module.operator_runtime_summary({"verdict": "REVIEW"}) == {"scope": "none", "verdict": None}
    ms_overflow_evidence = json.loads((fixture_dir / "ms_pr89363_provenance.json").read_text(encoding="utf-8"))
    assert ms_overflow_evidence["verification"]["verdict"] == "REVIEW"
    ms_overflow_runtime = json.loads((fixture_dir / "ms_pr89363_bounded_runtime_evidence.json").read_text(encoding="utf-8"))
    assert ms_overflow_runtime["reduced_runtime"]["summary"]["verdict"] == "PASS"
    assert ms_overflow_runtime["full_case_status"] == "REVIEW"
    ms_overflow_matrix = matrix_module.evaluate_matrix(json.loads((fixture_dir / "ms_pr89363_contract_matrix.json").read_text(encoding="utf-8")))
    assert ms_overflow_matrix["status"] == "REVIEW"
    assert ms_overflow_matrix["paths"][0]["residual_count"] == 0
    assert ms_overflow_matrix["paths"][0]["runtime_scope"] == "scoped"
    assert ms_overflow_matrix["paths"][0]["scoped_runtime_verdict"] == "PASS"
    axis_case = next(item for item in readiness["assessments"] if item["id"] == "MS-PR-90617")
    assert axis_case["readiness_score"] == "6/8"
    assert axis_case["priority"] == "complete-missing-gates"
    assert set(axis_case["gaps"]) == {"symmetry", "runtime"}
    assert axis_case["evidence_level"] == "SCOPED_RUNTIME"
    assert axis_case["gate_status"]["runtime"] == "scoped"
    axis_evidence = json.loads((fixture_dir / "ms_pr90617_provenance.json").read_text(encoding="utf-8"))
    assert axis_evidence["static"]["target_pattern"] == "shape_axis_index"
    axis_runtime = json.loads((fixture_dir / "ms_pr90617_bounded_runtime_evidence.json").read_text(encoding="utf-8"))
    assert axis_runtime["reduced_runtime"]["summary"]["verdict"] == "PASS"
    assert axis_runtime["full_case_status"] == "REVIEW"
    axis_matrix = matrix_module.evaluate_matrix(json.loads((fixture_dir / "ms_pr90617_contract_matrix.json").read_text(encoding="utf-8")))
    assert axis_matrix["status"] == "REVIEW"
    assert axis_matrix["paths"][0]["residual_count"] == 0
    assert axis_matrix["paths"][0]["runtime_scope"] == "scoped"
    assert axis_matrix["paths"][0]["scoped_runtime_verdict"] == "PASS"
    shape_case = next(item for item in readiness["assessments"] if item["id"] == "MS-PR-91146")
    assert shape_case["readiness_score"] == "7/8"
    assert shape_case["priority"] == "complete-missing-gates"
    assert shape_case["gaps"] == ["runtime"]
    assert shape_case["evidence_level"] == "SCOPED_RUNTIME"
    assert shape_case["gate_status"]["runtime"] == "scoped"
    shape_evidence = json.loads((fixture_dir / "ms_pr91146_provenance.json").read_text(encoding="utf-8"))
    assert shape_evidence["contract"] == "nonnegative-shape-dimension-validation"
    shape_runtime = json.loads((fixture_dir / "ms_pr91146_bounded_runtime_evidence.json").read_text(encoding="utf-8"))
    assert shape_runtime["reduced_runtime"]["summary"]["verdict"] == "PASS"
    assert shape_runtime["full_case_status"] == "REVIEW"
    shape_matrix = matrix_module.evaluate_matrix(json.loads((fixture_dir / "ms_pr91146_contract_matrix.json").read_text(encoding="utf-8")))
    assert shape_matrix["status"] == "REVIEW"
    assert all(path["residual_count"] == 0 for path in shape_matrix["paths"])
    assert all(path["runtime_scope"] == "scoped" for path in shape_matrix["paths"])
    assert all(path["scoped_runtime_verdict"] == "PASS" for path in shape_matrix["paths"])
    assert matrix_module.scoped_runtime_summary(
        {"verdict": "REVIEW"},
        {"malicious_rejected": "2/2", "benign_passed": "1/1", "infrastructure_failures": 0, "verdict": "PASS"},
    ) == {"scope": "scoped", "verdict": "PASS"}
    assert matrix_module.scoped_runtime_summary(
        {"verdict": "REVIEW"},
        {"malicious_rejected": "0/0", "benign_passed": "0/0", "infrastructure_failures": 0, "verdict": "PASS"},
    ) == {"scope": "none", "verdict": None}
    assert matrix_module.scoped_runtime_summary(
        {"malicious_rejected": "2/2", "benign_passed": "1/1", "infrastructure_failures": 0, "verdict": "PASS", "note": "reduced harness only"},
    ) == {"scope": "scoped", "verdict": "PASS"}
    plan_path = fixture_dir / "embodied_ai_pr_materialization_plan.json"
    plan_data = json.loads(plan_path.read_text(encoding="utf-8"))
    assert not pr_plan.validate(plan_data, registry_data)
    assert {item["id"] for item in plan_data["cases"]} == {"ORT-PR-28003", "MS-PR-70694"}

    matrix_path = fixture_dir / "ncnn_pr6922_local_text_bin_contract_matrix.json"
    matrix_data = json.loads(matrix_path.read_text(encoding="utf-8"))
    matrix_result = matrix_module.evaluate_matrix(matrix_data)
    assert matrix_result["status"] == "MATRIX_VERIFIED"
    assert matrix_result["path_count"] == 2
    assert all(item["status"] == "PASS" for item in matrix_result["paths"])
    incomplete_matrix = dict(matrix_data)
    incomplete_matrix["paths"] = [matrix_data["paths"][0]]
    incomplete_result = matrix_module.evaluate_matrix(incomplete_matrix)
    assert incomplete_result["status"] == "REVIEW"
    assert any(error.startswith("required-path-missing:") for error in incomplete_result["errors"])

    verdict_pass = verdict.evaluate(
        fixture_dir / "ncnn_text_blob_index_before.cpp",
        fixture_dir / "ncnn_text_blob_index_after.cpp",
        787,
        "text_blob_index_access",
        {"summary": {"malicious_rejected": "1/1", "benign_passed": "1/1", "infrastructure_failures": 0, "verdict": "PASS"}},
        {"base_sha": "base", "head_sha": "head"},
        {"symmetric": True, "findings": []},
    )
    assert verdict_pass["status"] == "SEMANTIC_VERIFIED"
    assert verdict_pass["formal_proof"] is False
    verdict_review = verdict.evaluate(
        fixture_dir / "ncnn_text_blob_index_before.cpp",
        fixture_dir / "ncnn_text_blob_index_before.cpp",
        787,
        "text_blob_index_access",
        {"summary": {"malicious_rejected": "0/1", "benign_passed": "1/1", "infrastructure_failures": 0, "verdict": "REVIEW"}},
        {"base_sha": "base", "head_sha": "head"},
        {"symmetric": True, "findings": []},
    )
    assert verdict_review["status"] == "REVIEW"
    runtime_artifact = json.loads((fixture_dir / "ncnn_official_pr_runtime_evidence.json").read_text(encoding="utf-8"))
    assert any(item["id"] == "NCNN-PR-6383-LAYER-PARAM-FAILURE"
               and item["head_result"]["verdict"] == "PASS"
               for item in runtime_artifact["cases"])
    assert any(item["id"] == "NCNN-PR-6922-TEXT-BLOB-RESIDUAL"
               and item["head_result"]["verdict"] == "REVIEW"
               for item in runtime_artifact["cases"])
    arithmetic_before = detect.detect_in_file(str(fixture_dir / "shape_arithmetic_before.cpp"), {190}, component="ncnn")
    arithmetic_after = detect.detect_in_file(str(fixture_dir / "shape_arithmetic_after.cpp"), {190}, component="ncnn")
    static_cast_before = detect.detect_in_file(str(fixture_dir / "static_cast_narrow_before.cpp"), {190}, component="ncnn")
    static_cast_after = detect.detect_in_file(str(fixture_dir / "static_cast_narrow_after.cpp"), {190}, component="ncnn")
    assert any(item["pattern"] == "static_cast_narrow_truncation" for item in static_cast_before)
    assert not any(item["pattern"] == "static_cast_narrow_truncation" for item in static_cast_after)
    assert any(item["pattern"] == "unchecked_shape_product_narrow" for item in arithmetic_before)
    assert any(item["pattern"] == "zero_extent_offset" for item in arithmetic_before)
    assert not any(item["pattern"] in {"unchecked_shape_product_narrow", "zero_extent_offset"}
                   for item in arithmetic_after)
    lifecycle_before = detect.detect_in_file(str(fixture_dir / "partial_init_before.cpp"), {703}, component="ncnn")
    lifecycle_after = detect.detect_in_file(str(fixture_dir / "partial_init_after.cpp"), {703}, component="ncnn")
    assert any(item["pattern"] == "partial_init_cleanup" for item in lifecycle_before)
    assert not any(item["pattern"] == "partial_init_cleanup" for item in lifecycle_after)
    assert len(detect.repair_requirements({"pattern": "partial_init_cleanup"})) == 2

    dataset_result = schema.validate_dataset(str(ROOT.parent.parent.parent.parent / "研究文档" / "embodied-ai-cwe-dataset.json"))
    assert dataset_result["valid"] and dataset_result["findings"] == 34 and dataset_result["repair_pairs"] >= 2
    with tempfile.TemporaryDirectory() as schema_td:
        invalid_dataset = Path(schema_td) / "invalid.json"
        invalid_dataset.write_text(json.dumps({
            "components": [],
            "repair_pairs": [{
                "id": "bad-patch-evidence", "component": "test", "sample_role": "test",
                "before": "external-reference", "after": "external-reference", "contract_type": "test",
                "evidence_status": "external-reference", "repair_status": "review",
                "verification_status": "review", "runtime_verdict": "REVIEW",
                "patch_application_evidence": {
                    "source": "external-reference", "patch": "external-reference", "target_path": "src/test.cpp",
                    "forward_applicable": True, "reverse_applicable": False,
                    "direct_artifact_path_applicable": "false",
                    "bin_blob_fragment": "not-an-object",
                },
                "local_patch_evidence": {
                    "patch": "external-reference", "source_proof": "false", "added_lines": -1,
                },
                "runtime_preflight_evidence": {
                    "launcher_preflight_attempted": "true", "actual_harness_executed": False,
                    "verdict": "PASS", "infrastructure_failures": -1,
                    "infrastructure_reasons": {"wsl-unavailable": "2"},
                },
                "runtime_verification_evidence": {
                    "artifact": "external-reference", "source_commit": "", "actual_harness_executed": False,
                    "infrastructure_failures": -1, "scope_verdict": "PASS",
                    "bin_scope": {"verdict": "BAD"},
                },
            }],
        }), encoding="utf-8")
        invalid_result = schema.validate_dataset(str(invalid_dataset))
        assert not invalid_result["valid"]
        assert any(error.get("patch_application_not_bool") == "direct_artifact_path_applicable"
                   for error in invalid_result["errors"])
        assert any(error.get("patch_fragment_not_object") == "bin_blob_fragment"
                   for error in invalid_result["errors"])
        assert any(error.get("local_patch_source_proof_not_bool") for error in invalid_result["errors"])
        assert any(error.get("local_patch_added_lines_invalid") for error in invalid_result["errors"])
        assert any(error.get("runtime_preflight_not_bool") == "launcher_preflight_attempted"
                   for error in invalid_result["errors"])
        assert any("runtime_preflight_invalid_failures" in error for error in invalid_result["errors"])
        assert any(error.get("runtime_preflight_invalid_reasons") for error in invalid_result["errors"])
        assert any(error.get("runtime_preflight_unexecuted_pass") for error in invalid_result["errors"])
        assert any(error.get("runtime_verification_invalid_artifact") for error in invalid_result["errors"])
        assert any(error.get("runtime_verification_invalid_commit") for error in invalid_result["errors"])
        assert any(error.get("runtime_verification_invalid_failures") is not None
                   for error in invalid_result["errors"])
        assert any(error.get("runtime_verification_invalid_scope") == "bin_scope"
                   for error in invalid_result["errors"])
        assert any(error.get("runtime_verification_unexecuted_pass") for error in invalid_result["errors"])

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        source = td / "fixture.cpp"
        source.write_text("int f(int idx, int size) {\n    return data[idx];\n}\n", encoding="utf-8")
        unsupported, ok = repair.generate_patch(str(source), 2, 129, {})
        assert not ok and "不支持" in unsupported
        patch, ok = repair.generate_patch(str(source), 2, 787, {
            "cwe": 787, "idx": "idx", "size": "size", "log": "generic", "fail_ret": "-1"
        })
        assert ok
        assert patch.index("if (idx < 0") < patch.index("return data[idx]")
        patch_path = td / "fixture.patch"
        patch_path.write_text(patch, encoding="utf-8")
        check = subprocess.run(["git", "apply", "--check", "--unsafe-paths", str(patch_path)],
                               capture_output=True, text=True)
        assert check.returncode == 0, check.stderr
        assert repair.patch_path(r"\\wsl.localhost\Ubuntu-22.04\repo\src\net.cpp") == "src/net.cpp"

        candidate = contract_module.analyze_contract(str(source), 2, 787, {
            "idx": "idx", "size": "size", "cleanup": "",
        })
        assert candidate["status"] == "AUTO_CANDIDATE"
        assert candidate["formal_proof"] is False
        assert any(item["status"] == "to-add" for item in candidate["obligations"])

        parser_like = td / "parser_like.cpp"
        parser_like.write_text(
            "int load(int idx, int size) {\n"
            "    Layer* layer = nullptr;\n"
            "    d->layers[0] = layer;\n"
            "    Blob& blob = d->blobs[idx];\n"
            "    return -1;\n"
            "}\n", encoding="utf-8")
        review = contract_module.analyze_contract(str(parser_like), 4, 787, {
            "idx": "idx", "size": "size", "cleanup": "",
        })
        assert review["status"] == "REVIEW"
        assert any(item["name"] == "partial-state-cleanup" and item["status"] == "missing"
                   for item in review["obligations"])

        guarded = td / "guarded.cpp"
        guarded.write_text(
            "int load(int idx, int size) {\n"
            "    if (idx < 0 || idx >= size) return -1;\n"
            "    return data[idx];\n"
            "}\n", encoding="utf-8")
        no_change = contract_module.analyze_contract(str(guarded), 3, 787, {
            "idx": "idx", "size": "size", "cleanup": "",
        })
        assert no_change["status"] == "NO_CHANGE"

        cleanup_patch, cleanup_ok = repair.generate_patch(str(parser_like), 4, 787, {
            "cwe": 787, "idx": "idx", "size": "size", "log": "generic",
            "fail_ret": "-1", "cleanup": "d->layers[0] = nullptr;",
        })
        assert cleanup_ok and "d->layers[0] = nullptr;" in cleanup_patch

        malicious = td / "malicious"
        benign = td / "benign"
        malicious.write_text("x", encoding="utf-8")
        benign.write_text("x", encoding="utf-8")
        runner = td / "runner.py"
        runner.write_text(
            "import sys\n"
            "if sys.argv[1].endswith('malicious'):\n"
            " print('ret=-1', file=sys.stderr)\n"
            " raise SystemExit(0)\n"
            "print('ret=0', file=sys.stderr)\n",
            encoding="utf-8",
        )
        result = verify.verify_binary(
            f"{sys.executable} {runner}", [str(malicious)], [str(benign)]
        )
        assert result["summary"]["verdict"] == "PASS", json.dumps(result)

        missing = verify.verify_binary(
            str(td / "missing-binary"), [str(malicious)], [str(benign)]
        )
        assert missing["summary"]["verdict"] == "REVIEW", json.dumps(missing)
        assert missing["summary"]["infrastructure_failures"] == 2

        wsl_failure_runner = td / "wsl_failure_runner.py"
        wsl_failure_runner.write_text(
            "import sys\n"
            "print('HCS_E_HYPERV_NOT_INSTALLED', file=sys.stderr)\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        wsl_failure = verify.verify_binary(
            f"{sys.executable} {wsl_failure_runner}", [str(malicious)], [str(benign)]
        )
        assert wsl_failure["summary"]["verdict"] == "REVIEW", json.dumps(wsl_failure)
        assert wsl_failure["summary"]["infrastructure_failures"] == 2
        assert wsl_failure["summary"]["infrastructure_reasons"] == {"wsl-unavailable": 2}
        assert not wsl_failure["malicious"][0]["rejected"]
        assert wsl_failure["malicious"][0]["infra_reason"] == "wsl-unavailable"

        invalid_utf8_runner = td / "invalid_utf8_runner.py"
        invalid_utf8_runner.write_text(
            "import sys\n"
            "sys.stderr.buffer.write(b'\\xffH\\x00C\\x00S\\x00_\\x00E\\x00_\\x00H\\x00Y\\x00P\\x00E\\x00R\\x00V\\x00_\\x00N\\x00O\\x00T\\x00_\\x00I\\x00N\\x00S\\x00T\\x00A\\x00L\\x00L\\x00E\\x00D\\x00\\n')\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        json_cli = subprocess.run(
            [sys.executable, str(ROOT / "cwe_verify.py"),
             "--binary", f"{sys.executable} {invalid_utf8_runner}",
             "--malicious", str(malicious), "--benign", str(benign), "--json"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        assert json_cli.returncode == 0, json_cli.stderr
        json_result = json.loads(json_cli.stdout)
        assert json_result["summary"]["verdict"] == "REVIEW"
        assert json_result["summary"]["infrastructure_reasons"] == {"wsl-unavailable": 2}

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        artifact = td / "evidence.json"
        artifact.write_text(json.dumps({
            "case_id": "ASSET-CASE-1",
            "status": "PASS",
            "formal_proof": False,
        }, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

        def ref(assertions):
            return {"path": artifact.name, "sha256": digest, "assertions": assertions}

        evidence_ref = ref([{"path": "case_id", "equals": "ASSET-CASE-1"}, {"path": "status", "equals": "PASS"}])

        def gate(status="PASS", metrics=None):
            value = {"status": status, "evidence": [evidence_ref]}
            if metrics is not None:
                value["metrics"] = metrics
            return value

        complete = {
            "schema_version": 1,
            "asset_id": "fixture/asset",
            "case_id": "ASSET-CASE-1",
            "asset_kind": "ai-runtime",
            "scope_type": "single-asset-declared-contract",
            "official_source": "https://example.invalid/asset",
            "universal_claim": False,
            "formal_proof": False,
            "revisions": {"base": "a" * 40, "head": "b" * 40},
            "declared_scope": {
                "providers": ["cpu"],
                "targets": ["fixture-test"],
                "configurations": ["debug"],
                "input_domains": ["bounded-contract-fixtures"],
            },
            "contract": {
                "required_asset_gates": list(asset_semantic.DEFAULT_ASSET_GATES),
                "required_path_gates": list(asset_semantic.DEFAULT_PATH_GATES),
                "required_dimensions": ["bounded_input_contract"],
            },
            "safety": {key: True for key in asset_semantic.SAFETY_KEYS},
            "inventory": {
                "enumeration_method": "fixture manifest plus explicit boundary review",
                "source_basis": "fixture source and target manifest",
                "external_boundaries": ["fixture input API"],
                "reachable_sinks": ["fixture output API"],
                "declared_path_ids": ["path-a"],
                "unverified": [],
            },
            "asset_coverage": {name: gate() for name in asset_semantic.DEFAULT_ASSET_GATES},
            "paths": [{
                "id": "path-a",
                "source": "src/asset.cc",
                "entrypoint": "asset::Run",
                "call_path": ["asset::Run", "asset::Validate"],
                "required_dimensions": ["bounded_input_contract"],
            }],
            "path_coverage": {"path-a": {
                name: gate(
                    metrics={"malicious_rejected": "1/1", "infrastructure_failures": 0}
                    if name == "negative_rejection" else
                    {"benign_passed": "1/1", "infrastructure_failures": 0}
                    if name == "benign_preservation" else
                    {"unsafe_behavior_observed": True, "malicious_rejected": "0/1", "infrastructure_failures": 0}
                    if name == "preimage_witness" else None
                )
                for name in asset_semantic.DEFAULT_PATH_GATES
            }},
            "path_dimension_coverage": {"path-a": {"bounded_input_contract": gate()}},
            "exclusions": [{"dimension": "non_cpu_provider", "reason": "outside this declared asset scope"}],
        }
        complete["path_coverage"]["path-a"]["detect"]["evidence_role"] = "detector"
        complete["path_coverage"]["path-a"]["repair_plan"]["evidence_role"] = "repair_plan"

        complete_result = asset_semantic.validate_asset_record(complete, base_dir=td)
        assert complete_result["valid"]
        assert complete_result["artifact_integrity"]
        assert complete_result["scope_complete"]
        assert complete_result["verdict"] == "ASSET_SCOPE_COMPLETE"

        repair_scope = json.loads(json.dumps(complete))
        repair_scope["contract"]["required_path_gates"] = [
            "static_contract", "symmetry", "paired_build", "preimage_witness",
            "runtime_head", "negative_rejection", "benign_preservation", "detect", "repair_plan",
        ]
        repair_scope["path_coverage"]["path-a"]["preimage_witness"] = gate(
            metrics={
                "unsafe_behavior_observed": True,
                "malicious_rejected": "0/1",
                "infrastructure_failures": 0,
            }
        )
        repair_scope_result = asset_semantic.validate_asset_record(repair_scope, base_dir=td)
        assert repair_scope_result["valid"]
        assert repair_scope_result["scope_complete"]
        assert repair_scope_result["verdict"] == "ASSET_SCOPE_COMPLETE"

        bad_preimage = json.loads(json.dumps(repair_scope))
        bad_preimage["path_coverage"]["path-a"]["preimage_witness"]["metrics"]["unsafe_behavior_observed"] = False
        bad_preimage_result = asset_semantic.validate_asset_record(bad_preimage, base_dir=td)
        assert not bad_preimage_result["valid"]
        assert "path.path-a.preimage_witness-unsafe-behavior-not-observed" in bad_preimage_result["errors"]

        incomplete = json.loads(json.dumps(complete))
        incomplete["path_coverage"]["path-a"]["runtime_head"]["status"] = "REVIEW"
        incomplete_result = asset_semantic.validate_asset_record(incomplete, base_dir=td)
        assert incomplete_result["valid"]
        assert not incomplete_result["scope_complete"]
        assert "path.path-a.runtime_head" in incomplete_result["missing_gates"]
        assert incomplete_result["verdict"] == "REVIEW"

        inventory_missing = json.loads(json.dumps(complete))
        del inventory_missing["inventory"]
        inventory_result = asset_semantic.validate_asset_record(inventory_missing, base_dir=td)
        assert not inventory_result["valid"]
        assert "inventory-missing" in inventory_result["errors"]
        assert "asset.inventory_completeness" in inventory_result["missing_gates"]

        inventory_unverified = json.loads(json.dumps(complete))
        inventory_unverified["inventory"]["unverified"] = ["unmapped sink"]
        inventory_unverified["asset_coverage"]["inventory_completeness"]["status"] = "PASS"
        inventory_unverified_result = asset_semantic.validate_asset_record(inventory_unverified, base_dir=td)
        assert not inventory_unverified_result["valid"]
        assert "inventory-pass-with-unverified-items" in inventory_unverified_result["errors"]

        invalid_scope = json.loads(json.dumps(complete))
        invalid_scope["universal_claim"] = True
        invalid_result = asset_semantic.validate_asset_record(invalid_scope, base_dir=td)
        assert not invalid_result["valid"]
        assert "universal-claim-must-be-false" in invalid_result["errors"]

        artifact.write_text(artifact.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        tampered_result = asset_semantic.validate_asset_record(complete, base_dir=td)
        assert not tampered_result["valid"]
        assert any("sha256-mismatch" in error for error in tampered_result["errors"])

    ncnn_contract = ROOT.parent / "examples" / "ncnn_pr6383_asset_semantic_contract.json"
    ncnn_result = asset_semantic.validate_asset_record(
        json.loads(ncnn_contract.read_text(encoding="utf-8")),
        base_dir=ncnn_contract.parent,
    )
    assert ncnn_result["valid"]
    assert ncnn_result["artifact_integrity"]
    assert ncnn_result["scope_complete"]
    assert ncnn_result["verdict"] == "ASSET_SCOPE_COMPLETE"

    ncnn_two_path_contract = ROOT.parent / "examples" / "ncnn_pr6383_two_text_failure_asset_contract.json"
    ncnn_two_path_result = asset_semantic.validate_asset_record(
        json.loads(ncnn_two_path_contract.read_text(encoding="utf-8")),
        base_dir=ncnn_two_path_contract.parent,
    )
    assert ncnn_two_path_result["valid"]
    assert ncnn_two_path_result["artifact_integrity"]
    assert ncnn_two_path_result["scope_complete"]
    assert ncnn_two_path_result["verdict"] == "ASSET_SCOPE_COMPLETE"

    four_path_contract = ROOT.parent / "examples" / "ncnn_pr6383_four_parser_paths_asset_contract.json"
    four_path_result = asset_semantic.validate_asset_record(
        json.loads(four_path_contract.read_text(encoding="utf-8")),
        base_dir=four_path_contract.parent,
    )
    assert four_path_result["valid"]
    assert four_path_result["artifact_integrity"]
    assert four_path_result["scope_complete"]
    assert four_path_result["verdict"] == "ASSET_SCOPE_COMPLETE"

    ort_scoped_contract = ROOT.parent / "examples" / "ort_pr28003_rnn_narrowing_scoped_contract.json"
    ort_scoped_result = asset_semantic.validate_asset_record(
        json.loads(ort_scoped_contract.read_text(encoding="utf-8")),
        base_dir=ort_scoped_contract.parent,
    )
    assert ort_scoped_result["valid"]
    assert ort_scoped_result["artifact_integrity"]
    assert not ort_scoped_result["scope_complete"]
    assert ort_scoped_result["verdict"] == "REVIEW"
    assert "path.rnn-narrowing-contract.negative_rejection" in ort_scoped_result["missing_gates"]

    ort_safeint_contract = ROOT.parent / "examples" / "ort_pr28003_safeint_helper_asset_contract.json"
    ort_safeint_result = asset_semantic.validate_asset_record(
        json.loads(ort_safeint_contract.read_text(encoding="utf-8")),
        base_dir=ort_safeint_contract.parent,
    )
    assert ort_safeint_result["valid"]
    assert ort_safeint_result["artifact_integrity"]
    assert ort_safeint_result["scope_complete"]
    assert ort_safeint_result["verdict"] == "ASSET_SCOPE_COMPLETE"

    release_result = release_audit.audit(release_audit.DEFAULT_BASELINE)
    assert release_result["verdict"] == "PASS"
    assert release_result["protected_artifacts"]["status"] == "PASS"
    assert release_result["embodied_profile"]["status"] == "PASS"
    assert release_result["formal_contract_inventory"]["status"] == "PASS"
    original_contracts = release_audit.CONTRACTS
    release_audit.CONTRACTS = release_audit.CONTRACTS[:-1]
    inventory_drift_result = release_audit.audit(release_audit.DEFAULT_BASELINE)
    assert inventory_drift_result["verdict"] == "REVIEW"
    assert "formal-contract-inventory-mismatch" in inventory_drift_result["errors"]
    release_audit.CONTRACTS = original_contracts
    original_profile = release_audit.PROFILE
    release_audit.PROFILE = fixture_dir / "missing_embodied_ai_profile.json"
    missing_profile_result = release_audit.audit(release_audit.DEFAULT_BASELINE)
    assert missing_profile_result["verdict"] == "REVIEW"
    assert "embodied-profile-missing" in missing_profile_result["errors"]
    release_audit.PROFILE = original_profile

    profile_data = json.loads((fixture_dir / "embodied_ai_profile.json").read_text(encoding="utf-8"))
    assert profile_validator.validate_profile(profile_data, release_audit.CONTRACTS)["valid"]
    invalid_profile = json.loads(json.dumps(profile_data))
    invalid_profile["contracts"]["ort_pr28003_asset_semantic_contract.json"]["real_robot_execution"] = True
    assert not profile_validator.validate_profile(invalid_profile, release_audit.CONTRACTS)["valid"]

    evaluation_manifest = json.loads((fixture_dir / "evaluation_manifest.json").read_text(encoding="utf-8"))
    evaluation_result = evaluation_summary.validate(evaluation_manifest, fixture_dir)
    assert evaluation_result["valid"]
    assert evaluation_summary.summarize(evaluation_manifest)["comparative_claim"] == "NOT_AVAILABLE until external baselines use normalized commands and mappings"

    callback_source = ROOT.parents[3] / "AGIBOT" / "repos" / "agibot_x1_infer_src" / "src" / "module" / "dcu_driver_module" / "src" / "dcu_driver_module.cc"
    if callback_source.is_file():
        callback_result = callback_review.review(callback_source)
        assert not callback_result["errors"]
    else:
        # Public clones do not redistribute the third-party AGIBOT source tree.
        callback_result = json.loads((fixture_dir / "agibot_jointcmd_callback_static_review.json").read_text(encoding="utf-8"))
        assert callback_result["valid"]
    assert callback_result["static_finding"]["verdict"] == "REVIEW"
    assert callback_result["static_finding"]["missing_length_guards"] == ["effort", "velocity", "position", "stiffness", "damping"]
    assert callback_result["real_robot_execution"] is False

    malformed_command = json.loads((fixture_dir / "agibot_jointcmd_malformed_fixture.json").read_text(encoding="utf-8"))
    benign_command = json.loads((fixture_dir / "agibot_jointcmd_benign_fixture.json").read_text(encoding="utf-8"))
    malformed_result = fake_sink.run(malformed_command)
    benign_result = fake_sink.run(benign_command)
    assert malformed_result == {"ret": -1, "reason": "parallel-array-length-mismatch:position", "state_mutated": False, "transform_count": 0, "fake_publish_count": 0}
    assert benign_result["ret"] == 0 and benign_result["fake_publish_count"] == 2 and benign_result["transform_count"] == 1

    source_slice_plan = json.loads((fixture_dir / "agibot_jointcmd_source_slice_plan.json").read_text(encoding="utf-8"))
    source_workspace = ROOT.parents[3]
    source_available = (source_workspace / source_slice_plan["source_root"]).is_dir()
    source_slice_result = source_slice_validator.validate(source_slice_plan, source_workspace, allow_unavailable_source=not source_available)
    assert source_slice_result == {"valid": True, "errors": [], "status": "REVIEW", "source_anchors": "VERIFIED" if source_available else "UNAVAILABLE"}
    portable_slice_result = source_slice_validator.validate(source_slice_plan, ROOT / "missing-workspace", allow_unavailable_source=True)
    assert portable_slice_result == {"valid": True, "errors": [], "status": "REVIEW", "source_anchors": "UNAVAILABLE"}
    if source_available:
        broken_slice_plan = json.loads(json.dumps(source_slice_plan))
        broken_slice_plan["source_anchors"][0]["sha256"] = "0" * 64
        assert not source_slice_validator.validate(broken_slice_plan, source_workspace)["valid"]

    paired_benign = json.loads((fixture_dir / "ort_pr28003_paired_benign_control_evidence.json").read_text(encoding="utf-8"))
    assert paired_benign["status"] == "PAIRED_FINITE_RNN_BENIGN_CONTROL_PASS"
    assert paired_benign["base"]["revision"] == "0fedb26c93e6c29882185715d5c2bb583a6d92b5"
    assert paired_benign["head"]["revision"] == "795675a77ebb898302c5798bd6247658db165d14"
    assert paired_benign["base"]["passed"] == paired_benign["head"]["passed"] == "1/1"
    assert paired_benign["universal_claim"] is False and paired_benign["formal_proof"] is False

    print("cwe-repair regression: PASS")


if __name__ == "__main__":
    main()
