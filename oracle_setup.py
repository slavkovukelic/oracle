#!/usr/bin/env python3
"""Oracle Linux tuning utility for Oracle Database workloads.

This module offers two execution modes:

``adaptive``
    Generates Oracle best-practice kernel and resource limit settings based on
    the current host resources.  This is the modernised workflow that replaces
    the brittle imperative logic from the legacy shell implementation.

``legacy``
    Delegates the work to the original :mod:`oracle.sh` script so that
    administrators can obtain byte-for-byte identical results compared to the
    historically deployed automation.  This mode is useful when validating the
    Python refactor or when a perfect reproduction of the legacy behaviour is
    required.

The script supports a dry-run mode (default) that only prints the calculated
configuration.  Use the ``--apply`` flag to persist the configuration.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import grp
import json
import logging
import os
import pathlib
import pwd
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Tuple

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - fallback for older runtimes
    import tomli as tomllib  # type: ignore[assignment]

LOG = logging.getLogger(__name__)

# Oracle recommends a dedicated user.  ``oracle`` is the conventional default,
# but it can be overridden on the CLI.
DEFAULT_ORACLE_USER = "oracle"
LEGACY_SCRIPT_NAME = "oracle.sh"


class LegacyRunner:
    """Thin wrapper that executes the historical ``oracle.sh`` script.

    Keeping the original shell implementation in-repo allows teams to validate
    functional parity.  ``LegacyRunner`` automates its execution by piping the
    required confirmation response so that it can be run unattended.
    """

    def __init__(self, script_path: Optional[pathlib.Path] = None) -> None:
        if script_path is None:
            script_path = pathlib.Path(__file__).with_name(LEGACY_SCRIPT_NAME)
        self.script_path = script_path

    def execute(self, apply_changes: bool, dry_run: bool) -> None:
        LOG.debug("LegacyRunner invoked (apply=%s, dry_run=%s)", apply_changes, dry_run)
        if dry_run:
            if not self.script_path.exists():
                LOG.warning("Legacy script %s is missing", self.script_path)
            else:
                LOG.info("[dry-run] Would execute legacy script %s", self.script_path)
            return

        ensure_root()
        if not self.script_path.exists():
            raise FileNotFoundError(f"Legacy script not found: {self.script_path}")

        LOG.info("Executing legacy provisioning script %s", self.script_path)
        result = subprocess.run(
            ["/bin/bash", str(self.script_path)],
            input="y\n",
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            LOG.error("Legacy script failed: %s", result.stderr.strip())
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
        if result.stdout:
            LOG.debug("legacy stdout: %s", result.stdout.strip())
        LOG.info("Legacy provisioning completed successfully")


@dataclasses.dataclass(frozen=True)
class ResourceSummary:
    """Hardware resources discovered on the host."""

    mem_total_kb: int
    swap_total_kb: int
    cpu_count: int
    hugepage_size_kb: int

    @property
    def mem_total_bytes(self) -> int:
        return self.mem_total_kb * 1024

    @property
    def mem_total_gb(self) -> float:
        return self.mem_total_kb / (1024 ** 2)

    @property
    def swap_total_gb(self) -> float:
        return self.swap_total_kb / (1024 ** 2)


class SystemInspector:
    """Collects system information without requiring third-party packages."""

    MEMINFO_PATH = pathlib.Path("/proc/meminfo")
    HUGE_PAGE_SIZE_KEY = "Hugepagesize"

    def collect(self) -> ResourceSummary:
        meminfo = self._read_meminfo()
        mem_total_kb = int(meminfo.get("MemTotal", 0))
        swap_total_kb = int(meminfo.get("SwapTotal", 0))
        hugepage_size_kb = int(meminfo.get(self.HUGE_PAGE_SIZE_KEY, 2048))
        cpu_count = os.cpu_count() or 1
        LOG.debug(
            "System resources - RAM: %s KB, swap: %s KB, CPUs: %s, huge page: %s KB",
            mem_total_kb,
            swap_total_kb,
            cpu_count,
            hugepage_size_kb,
        )
        return ResourceSummary(
            mem_total_kb=mem_total_kb,
            swap_total_kb=swap_total_kb,
            cpu_count=cpu_count,
            hugepage_size_kb=hugepage_size_kb,
        )

    def _read_meminfo(self) -> Dict[str, int]:
        data: Dict[str, int] = {}
        try:
            with self.MEMINFO_PATH.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if ":" not in line:
                        continue
                    key, value = line.split(":", 1)
                    fields = value.strip().split()
                    if not fields:
                        continue
                    data[key] = int(fields[0])
        except FileNotFoundError as exc:  # pragma: no cover - platforms without procfs
            raise RuntimeError("/proc/meminfo is not available on this platform") from exc
        return data


@dataclasses.dataclass(frozen=True)
class OracleKernelParameters:
    """Kernel parameters tuned for Oracle Database workloads."""

    kernel_shmmax: int
    kernel_shmall: int
    kernel_shmmni: int
    kernel_sem: Tuple[int, int, int, int]
    fs_aio_max_nr: int
    fs_file_max: int
    kernel_msgmnb: int
    kernel_msgmni: int
    kernel_msgmax: int
    net_core_rmem_default: int
    net_core_rmem_max: int
    net_core_wmem_default: int
    net_core_wmem_max: int
    net_core_netdev_max_backlog: int
    net_core_somaxconn: int
    net_ipv4_ip_local_port_range: Tuple[int, int]
    net_ipv4_tcp_fin_timeout: int
    net_ipv4_tcp_keepalive_intvl: int
    net_ipv4_tcp_keepalive_probes: int
    net_ipv4_tcp_keepalive_time: int
    net_ipv4_tcp_rmem: Tuple[int, int, int]
    net_ipv4_tcp_wmem: Tuple[int, int, int]
    vm_dirty_background_bytes: int
    vm_dirty_bytes: int
    vm_min_free_kbytes: int
    vm_dirty_background_ratio: int
    vm_dirty_ratio: int
    vm_swappiness: int
    vm_nr_hugepages: int

    @classmethod
    def from_resources(cls, res: ResourceSummary) -> "OracleKernelParameters":
        page_size = os.sysconf("SC_PAGE_SIZE")
        shmmax = int(res.mem_total_bytes * 0.9)
        shmall = shmmax // page_size
        shmmni = max(4096, res.cpu_count * 1024)

        semmsl = 250
        semmns = max(32000, res.cpu_count * 6400)
        semopm = 100
        semmni = max(128, res.cpu_count * 16)

        aio_max_nr = max(1_048_576, res.cpu_count * 262_144)
        file_max = max(6_815_744, res.cpu_count * 65_536)

        msgmnb = 65_536
        msgmni = max(32_000, res.cpu_count * 2_048)
        msgmax = 65_536

        rmem_default = 262_144
        rmem_max = max(6_291_456, res.cpu_count * 512 * 1024)
        wmem_default = 262_144
        wmem_max = max(6_291_456, res.cpu_count * 512 * 1024)

        port_range = (9000, 65500)
        tcp_fin_timeout = 30
        tcp_keepalive_time = 600
        tcp_keepalive_intvl = 30
        tcp_keepalive_probes = 5
        tcp_rmem = (4096, 87380, rmem_max)
        tcp_wmem = (4096, 65536, wmem_max)

        backlog = max(32768, res.cpu_count * 4096)
        somaxconn = max(4096, res.cpu_count * 512)

        dirty_background_bytes = _clamp_dirty_bytes(res.mem_total_bytes, low=134_217_728, pct=0.01)
        dirty_bytes = max(
            dirty_background_bytes * 2,
            _clamp_dirty_bytes(res.mem_total_bytes, low=536_870_912, pct=0.04),
        )
        min_free_kbytes = max(67_584, res.mem_total_kb // 64)

        dirty_background_ratio = 5
        dirty_ratio = 20
        swappiness = 10 if res.swap_total_gb > 0 else 1
        hugepages = _calculate_hugepages(res)

        LOG.debug(
            "Calculated kernel params: shmmax=%s shmall=%s sem=%s hugepages=%s",
            shmmax,
            shmall,
            (semmsl, semmns, semopm, semmni),
            hugepages,
        )

        return cls(
            kernel_shmmax=shmmax,
            kernel_shmall=shmall,
            kernel_shmmni=shmmni,
            kernel_sem=(semmsl, semmns, semopm, semmni),
            fs_aio_max_nr=aio_max_nr,
            fs_file_max=file_max,
            kernel_msgmnb=msgmnb,
            kernel_msgmni=msgmni,
            kernel_msgmax=msgmax,
            net_core_rmem_default=rmem_default,
            net_core_rmem_max=rmem_max,
            net_core_wmem_default=wmem_default,
            net_core_wmem_max=wmem_max,
            net_core_netdev_max_backlog=backlog,
            net_core_somaxconn=somaxconn,
            net_ipv4_ip_local_port_range=port_range,
            net_ipv4_tcp_fin_timeout=tcp_fin_timeout,
            net_ipv4_tcp_keepalive_intvl=tcp_keepalive_intvl,
            net_ipv4_tcp_keepalive_probes=tcp_keepalive_probes,
            net_ipv4_tcp_keepalive_time=tcp_keepalive_time,
            net_ipv4_tcp_rmem=tcp_rmem,
            net_ipv4_tcp_wmem=tcp_wmem,
            vm_dirty_background_bytes=dirty_background_bytes,
            vm_dirty_bytes=dirty_bytes,
            vm_min_free_kbytes=min_free_kbytes,
            vm_dirty_background_ratio=dirty_background_ratio,
            vm_dirty_ratio=dirty_ratio,
            vm_swappiness=swappiness,
            vm_nr_hugepages=hugepages,
        )

    def as_sysctl_dict(self) -> Dict[str, str]:
        sem = " ".join(str(x) for x in self.kernel_sem)
        tcp_rmem = " ".join(str(x) for x in self.net_ipv4_tcp_rmem)
        tcp_wmem = " ".join(str(x) for x in self.net_ipv4_tcp_wmem)
        port_range = " ".join(str(x) for x in self.net_ipv4_ip_local_port_range)
        return {
            "kernel.shmmax": str(self.kernel_shmmax),
            "kernel.shmall": str(self.kernel_shmall),
            "kernel.shmmni": str(self.kernel_shmmni),
            "kernel.sem": sem,
            "kernel.msgmnb": str(self.kernel_msgmnb),
            "kernel.msgmni": str(self.kernel_msgmni),
            "kernel.msgmax": str(self.kernel_msgmax),
            "fs.aio-max-nr": str(self.fs_aio_max_nr),
            "fs.file-max": str(self.fs_file_max),
            "net.core.rmem_default": str(self.net_core_rmem_default),
            "net.core.rmem_max": str(self.net_core_rmem_max),
            "net.core.wmem_default": str(self.net_core_wmem_default),
            "net.core.wmem_max": str(self.net_core_wmem_max),
            "net.core.netdev_max_backlog": str(self.net_core_netdev_max_backlog),
            "net.core.somaxconn": str(self.net_core_somaxconn),
            "net.ipv4.ip_local_port_range": port_range,
            "net.ipv4.tcp_fin_timeout": str(self.net_ipv4_tcp_fin_timeout),
            "net.ipv4.tcp_keepalive_intvl": str(self.net_ipv4_tcp_keepalive_intvl),
            "net.ipv4.tcp_keepalive_probes": str(self.net_ipv4_tcp_keepalive_probes),
            "net.ipv4.tcp_keepalive_time": str(self.net_ipv4_tcp_keepalive_time),
            "net.ipv4.tcp_rmem": tcp_rmem,
            "net.ipv4.tcp_wmem": tcp_wmem,
            "vm.dirty_background_bytes": str(self.vm_dirty_background_bytes),
            "vm.dirty_bytes": str(self.vm_dirty_bytes),
            "vm.min_free_kbytes": str(self.vm_min_free_kbytes),
            "vm.dirty_background_ratio": str(self.vm_dirty_background_ratio),
            "vm.dirty_ratio": str(self.vm_dirty_ratio),
            "vm.swappiness": str(self.vm_swappiness),
            "vm.nr_hugepages": str(self.vm_nr_hugepages),
        }


@dataclasses.dataclass(frozen=True)
class OracleLimits:
    """Process limits recommended for Oracle users."""

    soft_nproc: int
    hard_nproc: int
    soft_nofile: int
    hard_nofile: int
    soft_stack: int
    hard_stack: int
    memlock_kb: int

    @classmethod
    def from_resources(cls, res: ResourceSummary) -> "OracleLimits":
        concurrency = max(4096, res.cpu_count * 2048)
        nofile = max(65536, res.cpu_count * 32768)
        stack_kb = 10240
        memlock_kb = res.hugepage_size_kb * _calculate_hugepages(res)
        return cls(
            soft_nproc=concurrency,
            hard_nproc=concurrency,
            soft_nofile=nofile,
            hard_nofile=nofile,
            soft_stack=stack_kb,
            hard_stack=stack_kb,
            memlock_kb=memlock_kb,
        )

    def render(self, user: str) -> str:
        lines = [
            f"{user} soft nofile {self.soft_nofile}",
            f"{user} hard nofile {self.hard_nofile}",
            f"{user} soft nproc {self.soft_nproc}",
            f"{user} hard nproc {self.hard_nproc}",
            f"{user} soft stack {self.soft_stack}",
            f"{user} hard stack {self.hard_stack}",
            f"{user} soft memlock {self.memlock_kb}",
            f"{user} hard memlock {self.memlock_kb}",
        ]
        return "\n".join(lines) + "\n"


class PlanWriter:
    """Writes configuration files safely and idempotently."""

    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run

    def write_file(self, path: pathlib.Path, content: str, mode: Optional[int] = None) -> None:
        timestamp = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
        if self.dry_run:
            LOG.info("[dry-run] Would write %s", path)
            LOG.debug("Content for %s:\n%s", path, content)
            if mode is not None:
                LOG.debug("[dry-run] Desired mode for %s: %s", path, oct(mode))
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            backup = path.with_suffix(path.suffix + f".bak-{timestamp}")
            shutil.copy2(path, backup)
            LOG.info("Created backup %s", backup)
        with path.open("w", encoding="utf-8") as fh:
            fh.write(content)
        if mode is not None:
            os.chmod(path, mode)
        LOG.info("Wrote %s", path)

    def apply_sysctl(self, params: Dict[str, str], sysctl_path: pathlib.Path) -> None:
        header = "# Generated by oracle_setup.py on %s\n" % _dt.datetime.now().isoformat()
        body = "\n".join(f"{k} = {v}" for k, v in sorted(params.items()))
        self.write_file(sysctl_path, header + body + "\n", mode=0o644)
        if not self.dry_run:
            run_command(["sysctl", "--system"], check=False)

    def apply_limits(self, content: str, limits_path: pathlib.Path) -> None:
        header = "# Oracle limits generated on %s\n" % _dt.datetime.now().isoformat()
        self.write_file(limits_path, header + content, mode=0o644)


def ensure_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("oracle_setup.py requires root privileges to apply changes")


def run_command(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    LOG.debug("Executing command: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    if result.stdout:
        LOG.debug("stdout: %s", result.stdout.strip())
    if result.stderr:
        LOG.debug("stderr: %s", result.stderr.strip())
    return result



@dataclasses.dataclass(frozen=True)
class PathSettings:
    """Paths to key directories and files used by the provisioner."""

    data_root: pathlib.Path
    profile_dir: pathlib.Path
    ora_inventory: pathlib.Path
    oratab: pathlib.Path


@dataclasses.dataclass(frozen=True)
class SetupConfig:
    """Configuration loaded from a TOML manifest."""

    packages: Tuple[str, ...]
    groups: Tuple[GroupSpec, ...]
    users: Dict[str, UserSpec]
    paths: PathSettings

    def get_user(self, name: str) -> UserSpec:
        try:
            return self.users[name]
        except KeyError as exc:  # pragma: no cover - defensive guard
            raise KeyError(f"User '{name}' is not defined in the configuration") from exc

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "SetupConfig":
        packages_section = data.get("packages", {})
        if not isinstance(packages_section, Mapping):
            raise TypeError("[packages] section must be a table in the configuration")
        package_list = packages_section.get("install", [])
        if isinstance(package_list, (str, bytes)):
            raise TypeError("packages.install must be a list of package names")
        if not isinstance(package_list, Iterable):
            raise TypeError("packages.install must be a list of package names")
        packages = tuple(sorted({str(item) for item in package_list}))

        groups_section = data.get("groups", [])
        if not isinstance(groups_section, Iterable):
            raise TypeError("[[groups]] section must be a list of tables")
        groups: List[GroupSpec] = []
        for entry in groups_section:
            if not isinstance(entry, Mapping):
                raise TypeError("Each group entry must be a table")
            name = entry.get("name")
            if not isinstance(name, str):
                raise TypeError("Group name must be a string")
            gid = entry.get("gid")
            if gid is not None and not isinstance(gid, int):
                raise TypeError("Group gid must be an integer if provided")
            groups.append(GroupSpec(name=name, gid=gid))

        users_section = data.get("users", [])
        if not isinstance(users_section, Iterable):
            raise TypeError("[[users]] section must be a list of tables")
        users: Dict[str, UserSpec] = {}
        for entry in users_section:
            if not isinstance(entry, Mapping):
                raise TypeError("Each user entry must be a table")
            name = entry.get("name")
            if not isinstance(name, str):
                raise TypeError("User name must be a string")
            primary_group = entry.get("primary_group")
            if not isinstance(primary_group, str):
                raise TypeError(f"User {name!r} requires a primary_group string")
            supplementary = entry.get("supplementary_groups", [])
            if supplementary is None:
                supplementary_groups: Tuple[str, ...] = tuple()
            elif isinstance(supplementary, Iterable) and not isinstance(supplementary, (str, bytes)):
                supplementary_groups = tuple(str(item) for item in supplementary)
            else:
                raise TypeError(f"User {name!r} supplementary_groups must be a list of strings")
            home_raw = entry.get("home")
            if not isinstance(home_raw, str):
                raise TypeError(f"User {name!r} requires a home path string")
            shell = entry.get("shell", "/bin/bash")
            if not isinstance(shell, str):
                raise TypeError(f"User {name!r} shell must be a string")
            uid = entry.get("uid")
            if uid is not None and not isinstance(uid, int):
                raise TypeError(f"User {name!r} uid must be an integer")
            create_home = bool(entry.get("create_home", False))
            spec = UserSpec(
                name=name,
                primary_group=primary_group,
                supplementary_groups=supplementary_groups,
                home=pathlib.Path(home_raw),
                shell=shell,
                uid=uid,
                create_home=create_home,
            )
            users[name] = spec

        paths_section = data.get("paths")
        if not isinstance(paths_section, Mapping):
            raise TypeError("[paths] section must be defined in the configuration")

        def _as_path(value: object, key: str) -> pathlib.Path:
            if not isinstance(value, str):
                raise TypeError(f"paths.{key} must be a string")
            return pathlib.Path(value)

        try:
            paths = PathSettings(
                data_root=_as_path(paths_section["data_root"], "data_root"),
                profile_dir=_as_path(paths_section["profile_dir"], "profile_dir"),
                ora_inventory=_as_path(paths_section["ora_inventory"], "ora_inventory"),
                oratab=_as_path(paths_section["oratab"], "oratab"),
            )
        except KeyError as exc:
            raise KeyError(f"Missing required path setting: {exc.args[0]}") from exc

        return cls(packages=packages, groups=tuple(groups), users=users, paths=paths)


DEFAULT_CONFIG_PATH = pathlib.Path(__file__).with_name("oracle_setup.toml")


def load_setup_config(path: Optional[pathlib.Path] = None) -> SetupConfig:
    """Load a :class:`SetupConfig` from the provided TOML file."""

    config_path = path or DEFAULT_CONFIG_PATH
    with config_path.open("rb") as fh:
        data = tomllib.load(fh)
    if not isinstance(data, Mapping):
        raise TypeError("Configuration root must be a table")
    return SetupConfig.from_mapping(data)


@dataclasses.dataclass(frozen=True)
class GroupSpec:
    """Definition of a system group that should exist."""

    name: str
    gid: Optional[int] = None


@dataclasses.dataclass(frozen=True)
class UserSpec:
    """Definition of a managed system user."""

    name: str
    primary_group: str
    supplementary_groups: Tuple[str, ...]
    home: pathlib.Path
    shell: str = "/bin/bash"
    uid: Optional[int] = None
    create_home: bool = False


@dataclasses.dataclass(frozen=True)
class DirectorySpec:
    """Directory that must exist with ownership and permissions."""

    path: pathlib.Path
    owner: str
    group: str
    mode: int = 0o775


@dataclasses.dataclass(frozen=True)
class FileSpec:
    """File that should be rendered with specific ownership and mode."""

    path: pathlib.Path
    content: str
    owner: str = "root"
    group: str = "root"
    mode: int = 0o644


def _calculate_hugepages(res: ResourceSummary) -> int:
    """Estimate HugePages count based on RAM.

    Oracle typically recommends reserving around 70% of physical memory for
    database SGA.  We subtract 2 GiB for the OS and divide by the huge page size.
    """

    mem_for_sga_kb = max(0, int(res.mem_total_kb * 0.70) - 2 * 1024 * 1024)
    if mem_for_sga_kb <= 0:
        return 0
    return mem_for_sga_kb // res.hugepage_size_kb


def _clamp_dirty_bytes(total_bytes: int, low: int, pct: float) -> int:
    """Clamp dirty memory thresholds for modern kernels.

    ``pct`` controls the default ratio relative to RAM while ``low`` provides a
    floor recommended by current Oracle Linux guidance for database hosts.
    Values are rounded to the nearest multiple of 4 KiB so they align with
    kernel expectations.
    """

    computed = int(total_bytes * pct)
    value = max(low, computed)
    # Align to 4 KiB pages to avoid sysctl warnings.
    page = 4096
    remainder = value % page
    if remainder:
        value += page - remainder
    return value


def _normalize_whitespace(value: str) -> str:
    return " ".join(value.split())


def read_sysctl_value(key: str) -> Optional[str]:
    """Read the current sysctl value for ``key`` from ``/proc/sys``.

    Returns ``None`` when the kernel parameter is not present on the host.
    """

    path = pathlib.Path("/proc/sys") / key.replace(".", "/")
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    return _normalize_whitespace(raw)


def check_installed_packages(packages: Iterable[str]) -> Dict[str, Optional[bool]]:
    """Determine whether each package in ``packages`` is installed.

    Returns a mapping of package name to ``True`` (installed), ``False``
    (missing) or ``None`` when the status could not be determined.  The
    function prefers the system ``rpm`` binary because it is available on
    Oracle Linux by default.  When package metadata cannot be queried the
    caller receives an ``unknown`` status instead of an exception so that the
    inspection report can still be generated.
    """

    package_list = list(packages)
    if not package_list:
        return {}

    rpm = shutil.which("rpm")
    dpkg_query = shutil.which("dpkg-query")
    if not rpm and not dpkg_query:
        LOG.warning("Package inspection skipped because neither 'rpm' nor 'dpkg-query' is available")
        return {pkg: None for pkg in package_list}

    results: Dict[str, Optional[bool]] = {}
    for pkg in package_list:
        if rpm:
            try:
                proc = subprocess.run(
                    [rpm, "-q", pkg],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except OSError as exc:
                LOG.warning("Failed to inspect package %s: %s", pkg, exc)
                results[pkg] = None
                continue

            if proc.returncode == 0:
                results[pkg] = True
            elif proc.returncode == 1:
                # ``rpm -q`` returns 1 when the package is not installed.
                results[pkg] = False
            else:
                LOG.warning(
                    "Unexpected return code %s while inspecting package %s", proc.returncode, pkg
                )
                results[pkg] = None
            continue

        # Debian/Ubuntu fallback using dpkg-query
        try:
            proc = subprocess.run(
                [dpkg_query, "-W", "-f=${Status}", pkg],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            LOG.warning("Failed to inspect package %s: %s", pkg, exc)
            results[pkg] = None
            continue

        if proc.returncode != 0:
            results[pkg] = False
        elif "install ok installed" in (proc.stdout or ""):
            results[pkg] = True
        else:
            results[pkg] = None
    return results


def inspect_current_system(
    plan: "ConfigurationPlan",
    sysctl_reader: Optional[Callable[[str], Optional[str]]] = None,
    package_checker: Optional[Callable[[Iterable[str]], Dict[str, Optional[bool]]]] = None,
) -> Dict[str, object]:
    """Compare the live system state with the recommended configuration plan.

    ``sysctl_reader`` exists primarily for unit testing and allows callers to
    override how kernel parameters are retrieved. ``package_checker`` fulfils a
    similar role for unit tests by allowing them to inject a deterministic view
    of installed packages.
    """

    reader = sysctl_reader or read_sysctl_value
    kernel_report: Dict[str, Dict[str, str]] = {}

    for key, recommended in plan.kernel.as_sysctl_dict().items():
        current = reader(key)
        normalized_recommended = _normalize_whitespace(recommended)
        if current is None:
            status = "missing"
        elif current == normalized_recommended:
            status = "ok"
        else:
            status = "needs_update"
        kernel_report[key] = {
            "current": current,
            "recommended": normalized_recommended,
            "status": status,
        }

    recommendations = [key for key, data in kernel_report.items() if data["status"] != "ok"]

    package_results = (
        package_checker(plan.packages) if package_checker else check_installed_packages(plan.packages)
    )
    package_details: Dict[str, str] = {}
    missing_packages: List[str] = []
    installed_packages: List[str] = []
    unknown_packages: List[str] = []

    for pkg in plan.packages:
        status = package_results.get(pkg)
        if status is True:
            package_details[pkg] = "installed"
            installed_packages.append(pkg)
        elif status is False:
            package_details[pkg] = "missing"
            missing_packages.append(pkg)
            recommendations.append(f"package:{pkg}")
        else:
            package_details[pkg] = "unknown"
            unknown_packages.append(pkg)

    if missing_packages:
        package_status = "missing"
    elif unknown_packages:
        package_status = "unknown"
    else:
        package_status = "ok"

    return {
        "sysctl": kernel_report,
        "recommendations": recommendations,
        "packages": {
            "status": package_status,
            "installed": installed_packages,
            "missing": missing_packages,
            "unknown": unknown_packages,
            "details": package_details,
        },
    }


@dataclasses.dataclass
class ConfigurationPlan:
    resources: ResourceSummary
    kernel: OracleKernelParameters
    limits: OracleLimits
    oracle_user: str
    groups: List[GroupSpec]
    users: List[UserSpec]
    directories: List[DirectorySpec]
    files: List[FileSpec]
    packages: List[str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "resources": dataclasses.asdict(self.resources),
            "kernel": self.kernel.as_sysctl_dict(),
            "limits": dataclasses.asdict(self.limits),
            "oracle_user": self.oracle_user,
            "groups": [dataclasses.asdict(group) for group in self.groups],
            "users": [
                {
                    **dataclasses.asdict(user),
                    "home": str(user.home),
                    "supplementary_groups": list(user.supplementary_groups),
                }
                for user in self.users
            ],
            "directories": [
                {
                    **dataclasses.asdict(directory),
                    "path": str(directory.path),
                }
                for directory in self.directories
            ],
            "files": [
                {**dataclasses.asdict(file_spec), "path": str(file_spec.path)} for file_spec in self.files
            ],
            "packages": list(self.packages),
        }

    def describe(self) -> str:
        data = self.to_dict()
        return json.dumps(data, indent=2)

    def persist(self, writer: PlanWriter) -> None:
        sysctl_path = pathlib.Path("/etc/sysctl.d/99-oracle.conf")
        limits_path = pathlib.Path("/etc/security/limits.d/oracle.conf")
        writer.apply_sysctl(self.kernel.as_sysctl_dict(), sysctl_path)
        writer.apply_limits(self.limits.render(self.oracle_user), limits_path)


def _render_oracle_profile(user: UserSpec, data_dir: pathlib.Path) -> str:
    oracle_base = user.home / "base"
    oracle_home = oracle_base / "dbhome"
    tns_admin = oracle_home / "network" / "admin"
    return (
        f"# Oracle environment for {user.name}\n"
        f"export ORACLE_BASE={oracle_base}\n"
        f"export ORACLE_HOME={oracle_home}\n"
        "export ORACLE_SID=ORCLCDB\n"
        "export ORACLE_TERM=xterm\n"
        "export NLS_DATE_FORMAT='YYYY-MM-DD:HH24:MI:SS'\n"
        f"export TNS_ADMIN={tns_admin}\n"
        f"export ORACLE_PATH={data_dir}\n"
        "export LD_LIBRARY_PATH=$ORACLE_HOME/lib\n"
        "export PATH=$ORACLE_HOME/bin:$PATH\n"
        "export ORAENV_ASK=NO\n"
    )


def _render_fmw_profile(user: UserSpec) -> str:
    mw_home = user.home / "mwhome"
    node_manager = user.home / "mwlog" / "nodemanager"
    return (
        f"# Fusion Middleware environment for {user.name}\n"
        f"export MW_HOME={mw_home}\n"
        f"export NODEMGR_HOME={node_manager}\n"
        "export PATH=$MW_HOME/bin:$PATH\n"
    )


def _render_bash_profile_include(script_name: pathlib.Path) -> str:
    return (
        "# ~/.bash_profile generated by oracle_setup.py\n"
        "umask 027\n"
        "if [ -f ~/.bashrc ]; then\n"
        "  . ~/.bashrc\n"
        "fi\n"
        f"if [ -f {script_name} ]; then\n"
        f"  . {script_name}\n"
        "fi\n"
    )


def _oracle_directories(user: UserSpec) -> List[DirectorySpec]:
    inventory_group = "oinstall" if "oinstall" in user.supplementary_groups else user.primary_group
    base = user.home
    directories = [
        DirectorySpec(base, owner=user.name, group=user.primary_group, mode=0o750),
        DirectorySpec(base / "base", owner=user.name, group=user.primary_group, mode=0o750),
        DirectorySpec(base / "base" / "dbhome", owner=user.name, group=user.primary_group, mode=0o750),
        DirectorySpec(base / "INSTALL", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "oraInventory", owner=user.name, group=inventory_group, mode=0o770),
        DirectorySpec(base / "ubin", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "utils", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "sys_sql", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "tmp", owner=user.name, group=user.primary_group, mode=0o770),
    ]
    return directories


def _fmw_directories(user: UserSpec) -> List[DirectorySpec]:
    base = user.home
    inventory_group = "oinstall" if "oinstall" in user.supplementary_groups else user.primary_group
    return [
        DirectorySpec(base, owner=user.name, group=user.primary_group, mode=0o750),
        DirectorySpec(base / "INSTALL", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "mwlog", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "ubin", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "utils", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "mwhome", owner=user.name, group=user.primary_group, mode=0o750),
        DirectorySpec(base / "tmp", owner=user.name, group=user.primary_group, mode=0o770),
        DirectorySpec(base / "oraInventory", owner=user.name, group=inventory_group, mode=0o770),
    ]


def _oracle_files(user: UserSpec, data_dir: pathlib.Path, profile_dir: pathlib.Path) -> List[FileSpec]:
    profile_path = profile_dir / f"{user.name}_oracle.sh"
    bash_profile_path = user.home / ".bash_profile"
    files = [
        FileSpec(
            path=profile_path,
            content=_render_oracle_profile(user, data_dir),
            owner="root",
            group="root",
            mode=0o644,
        ),
        FileSpec(
            path=bash_profile_path,
            content=_render_bash_profile_include(profile_path),
            owner=user.name,
            group=user.primary_group,
            mode=0o640,
        ),
    ]
    return files


def _fmw_files(user: UserSpec, profile_dir: pathlib.Path) -> List[FileSpec]:
    profile_path = profile_dir / f"{user.name}_fmw.sh"
    bash_profile_path = user.home / ".bash_profile"
    files = [
        FileSpec(
            path=profile_path,
            content=_render_fmw_profile(user),
            owner="root",
            group="root",
            mode=0o644,
        ),
        FileSpec(
            path=bash_profile_path,
            content=_render_bash_profile_include(profile_path),
            owner=user.name,
            group=user.primary_group,
            mode=0o640,
        ),
    ]
    return files


def _ora_inventory_file(user: UserSpec, path: pathlib.Path) -> FileSpec:
    content = (
        f"inventory_loc={user.home / 'oraInventory'}\n"
        f"inst_group={user.primary_group}\n"
    )
    inventory_group = "oinstall" if "oinstall" in user.supplementary_groups else user.primary_group
    return FileSpec(path=path, content=content, owner="root", group=inventory_group, mode=0o664)


def _oratab_file(path: pathlib.Path) -> FileSpec:
    content = (
        "# /etc/oratab generated by oracle_setup.py\n"
        "# Populate this file after creating Oracle databases.\n"
    )
    return FileSpec(path=path, content=content, owner="root", group="root", mode=0o664)


def build_plan(
    resources: ResourceSummary,
    oracle_user: str,
    fmw_user: Optional[str] = "fmw",
    *,
    config: Optional[SetupConfig] = None,
) -> ConfigurationPlan:
    kernel = OracleKernelParameters.from_resources(resources)
    limits = OracleLimits.from_resources(resources)

    config = config or load_setup_config()

    groups = list(config.groups)
    users: List[UserSpec] = []
    directories: List[DirectorySpec] = []
    files: List[FileSpec] = []

    oracle_spec = config.get_user(oracle_user)
    users.append(oracle_spec)

    data_dir = config.paths.data_root
    directories.extend(_oracle_directories(oracle_spec))
    directories.append(DirectorySpec(data_dir, owner=oracle_spec.name, group=oracle_spec.primary_group, mode=0o770))
    files.extend(_oracle_files(oracle_spec, data_dir, config.paths.profile_dir))
    files.append(_ora_inventory_file(oracle_spec, config.paths.ora_inventory))
    files.append(_oratab_file(config.paths.oratab))

    if fmw_user:
        fmw_spec = config.get_user(fmw_user)
        users.append(fmw_spec)
        directories.extend(_fmw_directories(fmw_spec))
        files.extend(_fmw_files(fmw_spec, config.paths.profile_dir))

    packages = list(config.packages)

    return ConfigurationPlan(
        resources=resources,
        kernel=kernel,
        limits=limits,
        oracle_user=oracle_user,
        groups=groups,
        users=users,
        directories=directories,
        files=files,
        packages=packages,
    )


class PackageManager(ABC):
    """Simple wrapper around the system package manager."""

    def __init__(self, dry_run: bool) -> None:
        self.dry_run = dry_run

    @classmethod
    def for_system(cls, dry_run: bool) -> "PackageManager":
        for manager_cls in (DnfManager, AptManager):
            manager = manager_cls.try_create(dry_run)
            if manager is not None:
                return manager
        raise FileNotFoundError("No supported package manager (dnf/yum or apt) is available on this system")

    @classmethod
    @abstractmethod
    def try_create(cls, dry_run: bool) -> Optional["PackageManager"]:
        """Return an initialised manager when the backend is available."""

    @abstractmethod
    def is_installed(self, package: str) -> bool:
        """Return ``True`` when ``package`` is already present on the host."""

    @abstractmethod
    def install_missing(self, packages: List[str]) -> None:
        """Install the provided packages without performing any additional checks."""

    def install(self, packages: List[str]) -> None:
        if not packages:
            return

        unique_packages = sorted(set(packages))
        missing: List[str] = []
        for pkg in unique_packages:
            try:
                installed = self.is_installed(pkg)
            except OSError as exc:
                LOG.warning("Failed to determine installation status for %s: %s", pkg, exc)
                missing.append(pkg)
                continue

            if installed:
                LOG.info("Package '%s' is already installed; skipping.", pkg)
            else:
                missing.append(pkg)

        if not missing:
            return

        if self.dry_run:
            LOG.info("[dry-run] Would install packages: %s", ", ".join(missing))
            return

        self.install_missing(missing)


class DnfManager(PackageManager):
    """Package manager implementation for dnf/yum based systems."""

    def __init__(self, executable: str, dry_run: bool) -> None:
        super().__init__(dry_run)
        self.executable = executable
        self.query_tool = shutil.which("rpm") or "rpm"

    @classmethod
    def try_create(cls, dry_run: bool) -> Optional["PackageManager"]:
        executable = shutil.which("dnf") or shutil.which("yum")
        if not executable:
            return None
        return cls(executable, dry_run)

    def is_installed(self, package: str) -> bool:
        result = subprocess.run(
            [self.query_tool, "-q", package], capture_output=True, text=True, check=False
        )
        return result.returncode == 0

    def install_missing(self, packages: List[str]) -> None:
        cmd = [self.executable, "-y", "install", *packages]
        run_command(cmd)


class AptManager(PackageManager):
    """Package manager implementation for Debian/Ubuntu based systems."""

    def __init__(self, executable: str, dry_run: bool) -> None:
        super().__init__(dry_run)
        self.executable = executable
        self.query_tool = shutil.which("dpkg-query") or "dpkg-query"

    @classmethod
    def try_create(cls, dry_run: bool) -> Optional["PackageManager"]:
        executable = shutil.which("apt-get") or shutil.which("apt")
        if not executable:
            return None
        return cls(executable, dry_run)

    def is_installed(self, package: str) -> bool:
        result = subprocess.run(
            [self.query_tool, "-W", "-f=${Status}", package],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return False
        return "install ok installed" in (result.stdout or "")

    def install_missing(self, packages: List[str]) -> None:
        cmd = [self.executable, "install", "-y", *packages]
        run_command(cmd)


class Provisioner:
    """Apply the configuration plan to the host system."""

    def __init__(self, plan: ConfigurationPlan, writer: PlanWriter, dry_run: bool) -> None:
        self.plan = plan
        self.writer = writer
        self.dry_run = dry_run

    def apply(self) -> None:
        self.ensure_groups()
        self.ensure_users()
        self.ensure_directories()
        self.write_files()
        self.install_packages()

    def ensure_groups(self) -> None:
        for spec in self.plan.groups:
            try:
                existing = grp.getgrnam(spec.name)
            except KeyError:
                if self.dry_run:
                    LOG.info("[dry-run] Would create group %s", spec.name)
                    continue
                cmd = ["groupadd"]
                if spec.gid is not None:
                    cmd.extend(["-g", str(spec.gid)])
                cmd.append(spec.name)
                run_command(cmd)
                LOG.info("Created group %s", spec.name)
            else:
                if spec.gid is not None and existing.gr_gid != spec.gid:
                    LOG.warning(
                        "Group %s already exists with gid %s (expected %s)",
                        spec.name,
                        existing.gr_gid,
                        spec.gid,
                    )

    def ensure_users(self) -> None:
        for spec in self.plan.users:
            try:
                pwd.getpwnam(spec.name)
            except KeyError:
                if self.dry_run:
                    LOG.info("[dry-run] Would create user %s", spec.name)
                    continue
                cmd = ["useradd", "-g", spec.primary_group]
                if spec.uid is not None:
                    cmd.extend(["-u", str(spec.uid)])
                if spec.supplementary_groups:
                    cmd.extend(["-G", ",".join(spec.supplementary_groups)])
                cmd.extend(["-d", str(spec.home), "-s", spec.shell])
                if spec.create_home:
                    cmd.append("-m")
                else:
                    cmd.append("-M")
                cmd.append(spec.name)
                run_command(cmd)
                LOG.info("Created user %s", spec.name)
            else:
                LOG.info("User %s already exists; skipping creation", spec.name)

    def ensure_directories(self) -> None:
        for spec in self.plan.directories:
            if self.dry_run:
                LOG.info(
                    "[dry-run] Would ensure directory %s owned by %s:%s", spec.path, spec.owner, spec.group
                )
                continue
            spec.path.mkdir(parents=True, exist_ok=True)
            uid = pwd.getpwnam(spec.owner).pw_uid
            gid = grp.getgrnam(spec.group).gr_gid
            os.chown(spec.path, uid, gid)
            os.chmod(spec.path, spec.mode)
            LOG.info("Ensured directory %s", spec.path)

    def write_files(self) -> None:
        for spec in self.plan.files:
            self.writer.write_file(spec.path, spec.content, mode=spec.mode)
            if self.dry_run:
                LOG.info(
                    "[dry-run] Would set ownership of %s to %s:%s", spec.path, spec.owner, spec.group
                )
                continue
            uid = pwd.getpwnam(spec.owner).pw_uid
            gid = grp.getgrnam(spec.group).gr_gid
            os.chown(spec.path, uid, gid)
            os.chmod(spec.path, spec.mode)
            LOG.info("Configured %s", spec.path)

    def install_packages(self) -> None:
        if not self.plan.packages:
            return

        try:
            manager = PackageManager.for_system(self.dry_run)
        except FileNotFoundError:
            if self.dry_run:
                LOG.warning(
                    "Package manager not available; would install: %s",
                    ", ".join(sorted(set(self.plan.packages))),
                )
                return
            raise

        manager.install(self.plan.packages)


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--oracle-user",
        default=DEFAULT_ORACLE_USER,
        help="Database owner that should receive resource limits (default: oracle)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Persist the generated configuration (requires root).",
    )
    parser.add_argument(
        "--fmw-user",
        default="fmw",
        help="Optional Fusion Middleware user to manage (use --no-fmw to disable).",
    )
    parser.add_argument(
        "--no-fmw",
        action="store_true",
        help="Skip creating the Fusion Middleware account and directories.",
    )
    parser.add_argument(
        "--mode",
        choices=("adaptive", "legacy"),
        default="adaptive",
        help="Execution strategy: adaptive Python workflow or legacy shell script.",
    )
    parser.add_argument(
        "--inspect",
        action="store_true",
        help=(
            "Inspect the current system configuration and highlight differences from the"
            " recommended plan."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="count",
        default=0,
        help="Increase logging verbosity (use -vv for debug).",
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        help="Optional path to write the computed plan as JSON (dry-run safe).",
    )
    parser.add_argument(
        "--legacy-script",
        type=pathlib.Path,
        help="Override path to oracle.sh when using legacy mode.",
    )
    parser.add_argument(
        "--config",
        type=pathlib.Path,
        help="Path to a TOML configuration file describing packages, users, and directories.",
    )
    return parser.parse_args(argv)


def configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)

    if args.mode == "legacy":
        runner = LegacyRunner(args.legacy_script)
        runner.execute(apply_changes=args.apply, dry_run=not args.apply)
        if not args.apply:
            LOG.info("Legacy dry-run completed. No changes were made.")
        return 0

    config = load_setup_config(args.config)

    inspector = SystemInspector()
    resources = inspector.collect()
    fmw_user = None if args.no_fmw else (args.fmw_user or None)
    plan = build_plan(resources, args.oracle_user, fmw_user, config=config)

    plan_summary = plan.describe()
    LOG.info("Calculated configuration summary:\n%s", plan_summary)

    if args.output:
        args.output.write_text(plan_summary, encoding="utf-8")
        LOG.info("Wrote plan JSON to %s", args.output)

    if args.inspect:
        inspection = inspect_current_system(plan)
        LOG.info("Inspection report:\n%s", json.dumps(inspection, indent=2))

    writer = PlanWriter(dry_run=not args.apply)
    provisioner = Provisioner(plan, writer, dry_run=not args.apply)

    if args.apply:
        ensure_root()

    provisioner.apply()
    plan.persist(writer)

    if args.apply:
        LOG.info("Configuration applied successfully")
    else:
        LOG.info("Dry-run mode. No changes were made.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
