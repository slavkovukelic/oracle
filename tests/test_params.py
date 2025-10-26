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


def test_custom_config_overrides_paths(tmp_path):
    config_path = tmp_path / "custom.toml"
    config_path.write_text(
        """
[packages]
install = ["pkg-a"]

[[groups]]
name = "dbgrp"

[[users]]
name = "oracle"
primary_group = "dbgrp"
home = "/opt/oracle"

[paths]
data_root = "/mnt/oradata"
profile_dir = "/opt/profiles"
ora_inventory = "/etc/custom_oraInst.loc"
oratab = "/etc/custom_oratab"
""",
        encoding="utf-8",
    )

    config = oracle_setup.load_setup_config(config_path)
    res = fake_resources(16)
    plan = oracle_setup.build_plan(res, "oracle", fmw_user=None, config=config)

    directory_paths = {spec.path for spec in plan.directories}
    file_paths = {spec.path for spec in plan.files}

    assert pathlib.Path("/mnt/oradata") in directory_paths
    assert pathlib.Path("/etc/custom_oraInst.loc") in file_paths
    assert plan.packages == ["pkg-a"]


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

    original_which = oracle_setup.shutil.which

    def fake_which(name):
        if name == "dnf":
            return "/usr/bin/dnf"
        if name == "yum":
            return None
        if name == "rpm":
            return "/usr/bin/rpm"
        return original_which(name)

    monkeypatch.setattr(oracle_setup.shutil, "which", fake_which)
    run_calls = []

    def fake_run(cmd, capture_output=True, text=True, check=False):
        run_calls.append(cmd)
        if cmd[0].endswith("rpm"):
            return mock.Mock(returncode=1, stdout="", stderr="")
        return mock.Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(oracle_setup.subprocess, "run", fake_run)

    provisioner.install_packages()

    assert any(cmd[0].endswith("dnf") for cmd in run_calls)
    install_cmd = next(cmd for cmd in run_calls if cmd[0].endswith("dnf"))
    assert install_cmd[:3] == ["/usr/bin/dnf", "-y", "install"]


def test_package_installation_skips_preinstalled(monkeypatch, caplog):
    res = fake_resources(8)
    plan = oracle_setup.build_plan(res, "oracle", fmw_user=None)
    plan.packages = ["pkg-preinstalled"]
    writer = oracle_setup.PlanWriter(dry_run=False)
    provisioner = oracle_setup.Provisioner(plan, writer, dry_run=False)

    def fake_which(name):
        if name == "dnf":
            return "/usr/bin/dnf"
        if name == "rpm":
            return "/usr/bin/rpm"
        return None

    monkeypatch.setattr(oracle_setup.shutil, "which", fake_which)

    run_calls = []

    def fake_run(cmd, capture_output=True, text=True, check=False):
        run_calls.append(cmd)
        if cmd[0].endswith("rpm"):
            return mock.Mock(returncode=0, stdout="", stderr="")
        raise AssertionError("Installation should not be invoked for preinstalled packages")

    monkeypatch.setattr(oracle_setup.subprocess, "run", fake_run)

    caplog.set_level("INFO")
    provisioner.install_packages()

    assert any(cmd[0].endswith("rpm") for cmd in run_calls)
    assert not any(cmd[0].endswith("dnf") for cmd in run_calls)
    assert any("already installed" in record.message for record in caplog.records)


def test_parse_args_supports_inspection():
    args = oracle_setup.parse_args(["--inspect"])
    assert args.inspect is True


def test_inspection_reports_differences():
    res = fake_resources(8)
    plan = oracle_setup.build_plan(res, "oracle", fmw_user=None)
    kernel = plan.kernel.as_sysctl_dict()

    def fake_reader(key: str):
        if key == "kernel.shmmax":
            return kernel[key]
        if key == "kernel.shmall":
            return str(int(kernel[key]) // 2)
        return None

    report = oracle_setup.inspect_current_system(plan, sysctl_reader=fake_reader)

    assert report["sysctl"]["kernel.shmmax"]["status"] == "ok"
    assert report["sysctl"]["kernel.shmall"]["status"] == "needs_update"
    assert "kernel.shmall" in report["recommendations"]


def test_inspection_reports_missing_packages():
    res = fake_resources(8)
    plan = oracle_setup.build_plan(res, "oracle", fmw_user=None)
    plan.packages = ["pkg-one", "pkg-two"]

    def fake_checker(packages):
        return {"pkg-one": True, "pkg-two": False}

    report = oracle_setup.inspect_current_system(plan, package_checker=fake_checker)

    assert report["packages"]["status"] == "missing"
    assert report["packages"]["missing"] == ["pkg-two"]
    assert report["packages"]["details"]["pkg-one"] == "installed"
    assert any(item == "package:pkg-two" for item in report["recommendations"])
