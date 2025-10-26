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
    plan = oracle_setup.build_plan(res, oracle_setup.DEFAULT_ORACLE_USER, fmw_user=None)

    data = plan.to_dict()
    assert data["resources"]["mem_total_kb"] == res.mem_total_kb
    assert "kernel.shmmax" in data["kernel"]
    assert "net.core.somaxconn" in data["kernel"]
    assert "vm.dirty_bytes" in data["kernel"]
    assert any(user["name"] == oracle_setup.DEFAULT_ORACLE_USER for user in data["users"])

    out_file = tmp_path / "plan.json"
    out_file.write_text(plan.describe(), encoding="utf-8")
    assert out_file.exists()


def test_plan_includes_directories_and_files():
    res = fake_resources(32)
    plan = oracle_setup.build_plan(res, "oracle", fmw_user="fmw")

    directory_paths = {str(spec.path) for spec in plan.directories}
    file_paths = {str(spec.path) for spec in plan.files}

    assert "/oradata" in directory_paths
    assert "/etc/oraInst.loc" in file_paths
    assert any(user.name == "fmw" for user in plan.users)


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


def test_package_installation_invoked(monkeypatch):
    res = fake_resources(8)
    plan = oracle_setup.build_plan(res, "oracle", fmw_user=None)
    plan.packages = ["pkg-one", "pkg-two"]
    writer = oracle_setup.PlanWriter(dry_run=False)
    provisioner = oracle_setup.Provisioner(plan, writer, dry_run=False)

    monkeypatch.setattr(oracle_setup.shutil, "which", lambda name: "/usr/bin/dnf" if name == "dnf" else None)
    run_calls = []

    def fake_run(cmd, capture_output=True, text=True, check=False):
        run_calls.append(cmd)
        return mock.Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(oracle_setup.subprocess, "run", fake_run)

    provisioner.install_packages()

    assert run_calls
    assert run_calls[0][:3] == ["/usr/bin/dnf", "-y", "install"]
