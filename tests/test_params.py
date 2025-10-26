import pathlib
import sys
from unittest import mock

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import oracle_setup


def fake_resources(mem_gb: int, cpus: int = 4, hugepage_kb: int = 2048, swap_gb: int = 2):
    return oracle_setup.ResourceSummary(
        mem_total_kb=mem_gb * 1024 * 1024,
        swap_total_kb=swap_gb * 1024 * 1024,
        cpu_count=cpus,
        hugepage_size_kb=hugepage_kb,
    )


def test_kernel_parameters_scale_with_memory():
    res_small = fake_resources(8)
    res_large = fake_resources(64)

    kernel_small = oracle_setup.OracleKernelParameters.from_resources(res_small)
    kernel_large = oracle_setup.OracleKernelParameters.from_resources(res_large)

    assert kernel_large.kernel_shmmax > kernel_small.kernel_shmmax
    assert kernel_large.vm_nr_hugepages > kernel_small.vm_nr_hugepages


def test_limits_include_memlock_for_hugepages():
    res = fake_resources(16, cpus=8)
    limits = oracle_setup.OracleLimits.from_resources(res)
    expected_memlock = res.hugepage_size_kb * oracle_setup._calculate_hugepages(res)
    assert limits.memlock_kb == expected_memlock


def test_plan_serialization(tmp_path):
    res = fake_resources(16)
    kernel = oracle_setup.OracleKernelParameters.from_resources(res)
    limits = oracle_setup.OracleLimits.from_resources(res)
    plan = oracle_setup.ConfigurationPlan(res, kernel, limits, oracle_setup.DEFAULT_ORACLE_USER)

    data = plan.to_dict()
    assert data["resources"]["mem_total_kb"] == res.mem_total_kb
    assert "kernel.shmmax" in data["kernel"]

    out_file = tmp_path / "plan.json"
    out_file.write_text(plan.describe(), encoding="utf-8")
    assert out_file.exists()


def test_legacy_runner_invokes_shell(tmp_path):
    legacy_script = tmp_path / "oracle.sh"
    legacy_script.write_text("#!/bin/bash\necho legacy\n", encoding="utf-8")
    runner = oracle_setup.LegacyRunner(legacy_script)

    with mock.patch.object(oracle_setup, "ensure_root") as ensure_root_mock, mock.patch.object(
        oracle_setup.subprocess, "run"
    ) as run_mock:
        ensure_root_mock.return_value = None
        run_mock.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
        runner.execute(apply_changes=True, dry_run=False)

    run_mock.assert_called_once()
