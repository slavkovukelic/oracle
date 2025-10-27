import json
import pathlib
import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import oracle_setup
import oracle_setup_py26 as legacy


def fake_resources(mem_gb, cpus=8, swap_gb=2, hugepage_kb=2048):
    modern = oracle_setup.ResourceSummary(
        mem_total_kb=mem_gb * 1024 * 1024,
        swap_total_kb=swap_gb * 1024 * 1024,
        cpu_count=cpus,
        hugepage_size_kb=hugepage_kb,
    )
    compat = legacy.ResourceSummary(
        mem_total_kb=modern.mem_total_kb,
        swap_total_kb=modern.swap_total_kb,
        cpu_count=modern.cpu_count,
        hugepage_size_kb=modern.hugepage_size_kb,
    )
    return modern, compat


def test_hugepage_calculation_matches_modern():
    modern, compat = fake_resources(16)
    assert oracle_setup._calculate_hugepages(modern) == legacy._calculate_hugepages(compat)


def test_kernel_parameters_match_modern():
    modern, compat = fake_resources(32)
    modern_params = oracle_setup.OracleKernelParameters.from_resources(modern).as_sysctl_dict()
    compat_params = legacy.OracleKernelParameters.from_resources(compat).as_sysctl_dict()
    assert modern_params == compat_params


def test_limits_match_modern():
    modern, compat = fake_resources(12, cpus=12)
    modern_limits = oracle_setup.OracleLimits.from_resources(modern)
    compat_limits = legacy.OracleLimits.from_resources(compat)
    assert modern_limits.soft_nproc == compat_limits.soft_nproc
    assert modern_limits.memlock_kb == compat_limits.memlock_kb


def test_plan_serialization_matches(tmp_path):
    modern, compat = fake_resources(24)
    config_path = pathlib.Path(__file__).resolve().parents[1] / "oracle_setup.toml"
    modern_config = oracle_setup.load_setup_config(config_path)
    compat_config = legacy.load_setup_config(config_path)

    modern_plan = oracle_setup.build_plan(modern, oracle_setup.DEFAULT_ORACLE_USER, fmw_user="fmw", config=modern_config)
    compat_plan = legacy.build_plan(compat, legacy.DEFAULT_ORACLE_USER, fmw_user="fmw", config=compat_config)

    assert modern_plan.to_dict() == compat_plan.to_dict()

    modern_output = tmp_path / "modern.json"
    compat_output = tmp_path / "compat.json"
    modern_output.write_text(modern_plan.describe(), encoding="utf-8")
    compat_output.write_text(compat_plan.describe(), encoding="utf-8")

    assert json.loads(modern_output.read_text(encoding="utf-8")) == json.loads(
        compat_output.read_text(encoding="utf-8")
    )
