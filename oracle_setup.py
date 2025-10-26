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
from typing import Dict, Iterable, List, Optional, Tuple

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
    net_core_rmem_default: int
    net_core_rmem_max: int
    net_core_wmem_default: int
    net_core_wmem_max: int
    net_ipv4_ip_local_port_range: Tuple[int, int]
    net_ipv4_tcp_rmem: Tuple[int, int, int]
    net_ipv4_tcp_wmem: Tuple[int, int, int]
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

        aio_max_nr = max(1048576, res.cpu_count * 262144)
        file_max = max(6815744, res.cpu_count * 65536)

        rmem_default = 262144
        rmem_max = max(4194304, res.cpu_count * 1024 * 256)
        wmem_default = 262144
        wmem_max = max(4194304, res.cpu_count * 1024 * 256)

        port_range = (9000, 65500)
        tcp_rmem = (4096, 87380, rmem_max)
        tcp_wmem = (4096, 65536, wmem_max)

        swappiness = 10 if res.swap_total_gb > 0 else 1
        dirty_background_ratio = 5
        dirty_ratio = 20
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
            net_core_rmem_default=rmem_default,
            net_core_rmem_max=rmem_max,
            net_core_wmem_default=wmem_default,
            net_core_wmem_max=wmem_max,
            net_ipv4_ip_local_port_range=port_range,
            net_ipv4_tcp_rmem=tcp_rmem,
            net_ipv4_tcp_wmem=tcp_wmem,
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
            "fs.aio-max-nr": str(self.fs_aio_max_nr),
            "fs.file-max": str(self.fs_file_max),
            "net.core.rmem_default": str(self.net_core_rmem_default),
            "net.core.rmem_max": str(self.net_core_rmem_max),
            "net.core.wmem_default": str(self.net_core_wmem_default),
            "net.core.wmem_max": str(self.net_core_wmem_max),
            "net.ipv4.ip_local_port_range": port_range,
            "net.ipv4.tcp_rmem": tcp_rmem,
            "net.ipv4.tcp_wmem": tcp_wmem,
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


RECOMMENDED_PACKAGES = {
    "bc",
    "binutils",
    "compat-libcap1",
    "elfutils-libelf-devel",
    "gcc",
    "glibc",
    "ksh",
    "libaio",
    "libstdc++",
    "make",
    "net-tools",
    "nfs-utils",
    "smartmontools",
    "sysstat",
}


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
    return [
        DirectorySpec(base, owner=user.name, group=user.primary_group, mode=0o750),
        DirectorySpec(base / "INSTALL", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "mwlog", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "ubin", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "utils", owner=user.name, group=user.primary_group),
        DirectorySpec(base / "mwhome", owner=user.name, group=user.primary_group, mode=0o750),
        DirectorySpec(base / "tmp", owner=user.name, group=user.primary_group, mode=0o770),
        DirectorySpec(base / "oraInventory", owner=user.name, group="oinstall", mode=0o770),
    ]


def _oracle_files(user: UserSpec, data_dir: pathlib.Path) -> List[FileSpec]:
    profile_path = pathlib.Path("/etc/profile.d") / f"{user.name}_oracle.sh"
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


def _fmw_files(user: UserSpec) -> List[FileSpec]:
    profile_path = pathlib.Path("/etc/profile.d") / f"{user.name}_fmw.sh"
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


def _ora_inventory_file(user: UserSpec) -> FileSpec:
    content = (
        f"inventory_loc={user.home / 'oraInventory'}\n"
        f"inst_group={user.primary_group}\n"
    )
    return FileSpec(path=pathlib.Path("/etc/oraInst.loc"), content=content, owner="root", group="oinstall", mode=0o664)


def _oratab_file() -> FileSpec:
    content = (
        "# /etc/oratab generated by oracle_setup.py\n"
        "# Populate this file after creating Oracle databases.\n"
    )
    return FileSpec(path=pathlib.Path("/etc/oratab"), content=content, owner="root", group="root", mode=0o664)


def build_plan(resources: ResourceSummary, oracle_user: str, fmw_user: Optional[str] = "fmw") -> ConfigurationPlan:
    kernel = OracleKernelParameters.from_resources(resources)
    limits = OracleLimits.from_resources(resources)

    groups = [GroupSpec("oinstall"), GroupSpec("dba")]
    users: List[UserSpec] = [
        UserSpec(
            name=oracle_user,
            primary_group="dba",
            supplementary_groups=("oinstall",),
            home=pathlib.Path(f"/{oracle_user}"),
        )
    ]

    directories: List[DirectorySpec] = []
    files: List[FileSpec] = []

    data_dir = pathlib.Path("/oradata")
    directories.extend(_oracle_directories(users[0]))
    directories.append(DirectorySpec(data_dir, owner=oracle_user, group="dba", mode=0o770))
    files.extend(_oracle_files(users[0], data_dir))
    files.append(_ora_inventory_file(users[0]))
    files.append(_oratab_file())

    if fmw_user:
        fmw_spec = UserSpec(
            name=fmw_user,
            primary_group="dba",
            supplementary_groups=("oinstall",),
            home=pathlib.Path(f"/{fmw_user}"),
        )
        users.append(fmw_spec)
        directories.extend(_fmw_directories(fmw_spec))
        files.extend(_fmw_files(fmw_spec))

    packages = sorted(RECOMMENDED_PACKAGES)

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


class PackageManager:
    """Simple wrapper around the system package manager."""

    def __init__(self, dry_run: bool) -> None:
        self.dry_run = dry_run
        self.executable = shutil.which("dnf") or shutil.which("yum")

    def install(self, packages: List[str]) -> None:
        if not packages:
            return
        unique_packages = sorted(set(packages))
        if not self.executable:
            if self.dry_run:
                LOG.warning(
                    "Package manager (dnf/yum) not available; would install: %s",
                    ", ".join(unique_packages),
                )
                return
            raise FileNotFoundError("Neither dnf nor yum package manager is available on this system")

        cmd = [self.executable, "-y", "install", *unique_packages]
        if self.dry_run:
            LOG.info("[dry-run] Would install packages: %s", ", ".join(unique_packages))
            return
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
        manager = PackageManager(self.dry_run)
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

    inspector = SystemInspector()
    resources = inspector.collect()
    fmw_user = None if args.no_fmw else (args.fmw_user or None)
    plan = build_plan(resources, args.oracle_user, fmw_user)

    LOG.info("Calculated configuration summary:\n%s", plan.describe())

    if args.output:
        args.output.write_text(plan.describe(), encoding="utf-8")
        LOG.info("Wrote plan JSON to %s", args.output)

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
