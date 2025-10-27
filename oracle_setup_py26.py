#!/usr/bin/env python
"""Python 2.6 compatible variant of :mod:`oracle_setup`.

The goal of this module is to mirror the behaviour of the modern
``oracle_setup`` utility while staying within the syntax and runtime limits of
legacy Python interpreters such as Python 2.6.  The original refactor relies on
features like dataclasses, ``pathlib`` and f-strings which are unavailable on
such old systems.  This module re-implements the core functionality using
plain classes and ``os.path`` helpers so it can run unmodified on ancient
platforms that only ship Python 2.

Only modules from the Python 2.6 standard library are used.  The public API is
kept intentionally close to the modern version so that unit tests can assert
behavioural parity between the two implementations.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse
import datetime as _dt
import json
import logging
import os
import re
import shutil
import subprocess
import sys

try:
    import grp
except ImportError:  # pragma: no cover - Windows compatibility
    class _UnsupportedGrpModule(object):
        """Fallback shim for platforms without the ``grp`` module."""

        @staticmethod
        def _raise(*_args, **_kwargs):
            raise NotImplementedError("grp module is not available on this platform")

        getgrnam = _raise
        getgrgid = _raise
        getgrall = _raise

    grp = _UnsupportedGrpModule()  # type: ignore

try:
    import pwd
except ImportError:  # pragma: no cover - Windows compatibility
    class _UnsupportedPwdModule(object):
        """Fallback shim for platforms without the ``pwd`` module."""

        @staticmethod
        def _raise(*_args, **_kwargs):
            raise NotImplementedError("pwd module is not available on this platform")

        getpwnam = _raise

    pwd = _UnsupportedPwdModule()  # type: ignore

LOG = logging.getLogger(__name__)

DEFAULT_ORACLE_USER = "oracle"
LEGACY_SCRIPT_NAME = "oracle.sh"

try:
    basestring
except NameError:  # pragma: no cover - Python 3 compatibility
    basestring = str  # type: ignore

try:
    PermissionError
except NameError:  # pragma: no cover - Python 2 compatibility
    class PermissionError(OSError):
        pass


def _which(executable):
    """Compatibility wrapper for :func:`shutil.which`."""

    if hasattr(shutil, "which"):
        return shutil.which(executable)

    path_env = os.environ.get("PATH", "")
    for directory in path_env.split(os.pathsep):
        candidate = os.path.join(directory, executable)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


class PathHelper(object):
    """A very small helper that mimics the handful of ``pathlib`` features"""

    def __init__(self, path):
        if isinstance(path, PathHelper):
            path = path.path
        self.path = os.path.abspath(path)

    def __div__(self, other):  # pragma: no cover - Python 2 operator overload
        return PathHelper(os.path.join(self.path, str(other)))

    def __truediv__(self, other):  # pragma: no cover - Python 3 operator overload
        return PathHelper(os.path.join(self.path, str(other)))

    def __str__(self):
        return self.path

    def __repr__(self):
        return "PathHelper({0!r})".format(self.path)

    @property
    def parent(self):
        return PathHelper(os.path.dirname(self.path))

    def with_name(self, name):
        return PathHelper(os.path.join(os.path.dirname(self.path), name))

    def with_suffix(self, suffix):
        base, _old = os.path.splitext(self.path)
        return PathHelper(base + suffix)

    def exists(self):
        return os.path.exists(self.path)

    def is_dir(self):
        return os.path.isdir(self.path)

    def mkdir(self, parents=False, exist_ok=False):
        if self.exists():
            if not exist_ok:
                raise OSError("Directory already exists: {0}".format(self.path))
            return
        if parents:
            os.makedirs(self.path)
        else:
            os.mkdir(self.path)

    def glob(self, pattern):
        import fnmatch

        for name in os.listdir(self.path):
            if fnmatch.fnmatch(name, pattern):
                yield PathHelper(os.path.join(self.path, name))

    def resolve(self):
        return PathHelper(os.path.realpath(self.path))

    def as_uri(self):
        return "file://" + self.path.replace(os.sep, "/")

    def open(self, mode="r", encoding=None):
        if "b" not in mode and encoding is not None:
            import codecs

            return codecs.open(self.path, mode, encoding=encoding)
        return open(self.path, mode)

    def read_text(self, encoding="utf-8"):
        fh = self.open("r", encoding=encoding)
        try:
            return fh.read()
        finally:
            fh.close()

    def write_text(self, content, encoding="utf-8"):
        fh = self.open("w", encoding=encoding)
        try:
            fh.write(content)
        finally:
            fh.close()

    def iterdir(self):
        for name in os.listdir(self.path):
            yield PathHelper(os.path.join(self.path, name))


class ResourceSummary(object):
    """Hardware resources discovered on the host."""

    def __init__(self, mem_total_kb, swap_total_kb, cpu_count, hugepage_size_kb):
        self.mem_total_kb = int(mem_total_kb)
        self.swap_total_kb = int(swap_total_kb)
        self.cpu_count = int(cpu_count)
        self.hugepage_size_kb = int(hugepage_size_kb)

    @property
    def mem_total_bytes(self):
        return self.mem_total_kb * 1024

    @property
    def mem_total_gb(self):
        return float(self.mem_total_kb) / (1024.0 ** 2)

    @property
    def swap_total_gb(self):
        return float(self.swap_total_kb) / (1024.0 ** 2)


class OracleKernelParameters(object):
    """Kernel parameters tuned for Oracle Database workloads."""

    def __init__(
        self,
        kernel_shmmax,
        kernel_shmall,
        kernel_shmmni,
        kernel_sem,
        fs_aio_max_nr,
        fs_file_max,
        kernel_msgmnb,
        kernel_msgmni,
        kernel_msgmax,
        net_core_rmem_default,
        net_core_rmem_max,
        net_core_wmem_default,
        net_core_wmem_max,
        net_core_netdev_max_backlog,
        net_core_somaxconn,
        net_ipv4_ip_local_port_range,
        net_ipv4_tcp_fin_timeout,
        net_ipv4_tcp_keepalive_intvl,
        net_ipv4_tcp_keepalive_probes,
        net_ipv4_tcp_keepalive_time,
        net_ipv4_tcp_rmem,
        net_ipv4_tcp_wmem,
        vm_dirty_background_bytes,
        vm_dirty_bytes,
        vm_min_free_kbytes,
        vm_dirty_background_ratio,
        vm_dirty_ratio,
        vm_swappiness,
        vm_nr_hugepages,
    ):
        self.kernel_shmmax = int(kernel_shmmax)
        self.kernel_shmall = int(kernel_shmall)
        self.kernel_shmmni = int(kernel_shmmni)
        self.kernel_sem = tuple(kernel_sem)
        self.fs_aio_max_nr = int(fs_aio_max_nr)
        self.fs_file_max = int(fs_file_max)
        self.kernel_msgmnb = int(kernel_msgmnb)
        self.kernel_msgmni = int(kernel_msgmni)
        self.kernel_msgmax = int(kernel_msgmax)
        self.net_core_rmem_default = int(net_core_rmem_default)
        self.net_core_rmem_max = int(net_core_rmem_max)
        self.net_core_wmem_default = int(net_core_wmem_default)
        self.net_core_wmem_max = int(net_core_wmem_max)
        self.net_core_netdev_max_backlog = int(net_core_netdev_max_backlog)
        self.net_core_somaxconn = int(net_core_somaxconn)
        self.net_ipv4_ip_local_port_range = tuple(net_ipv4_ip_local_port_range)
        self.net_ipv4_tcp_fin_timeout = int(net_ipv4_tcp_fin_timeout)
        self.net_ipv4_tcp_keepalive_intvl = int(net_ipv4_tcp_keepalive_intvl)
        self.net_ipv4_tcp_keepalive_probes = int(net_ipv4_tcp_keepalive_probes)
        self.net_ipv4_tcp_keepalive_time = int(net_ipv4_tcp_keepalive_time)
        self.net_ipv4_tcp_rmem = tuple(net_ipv4_tcp_rmem)
        self.net_ipv4_tcp_wmem = tuple(net_ipv4_tcp_wmem)
        self.vm_dirty_background_bytes = int(vm_dirty_background_bytes)
        self.vm_dirty_bytes = int(vm_dirty_bytes)
        self.vm_min_free_kbytes = int(vm_min_free_kbytes)
        self.vm_dirty_background_ratio = int(vm_dirty_background_ratio)
        self.vm_dirty_ratio = int(vm_dirty_ratio)
        self.vm_swappiness = int(vm_swappiness)
        self.vm_nr_hugepages = int(vm_nr_hugepages)

    @classmethod
    def from_resources(cls, res):
        page_size = os.sysconf("SC_PAGE_SIZE")
        shmmax = int(res.mem_total_bytes * 0.9)
        shmall = int(shmmax // page_size)
        shmmni = max(4096, res.cpu_count * 1024)

        semmsl = 250
        semmns = max(32000, res.cpu_count * 6400)
        semopm = 100
        semmni = max(128, res.cpu_count * 16)

        aio_max_nr = max(1048576, res.cpu_count * 262144)
        file_max = max(6815744, res.cpu_count * 65536)

        msgmnb = 65536
        msgmni = max(32000, res.cpu_count * 2048)
        msgmax = 65536

        rmem_default = 262144
        rmem_max = max(6291456, res.cpu_count * 512 * 1024)
        wmem_default = 262144
        wmem_max = max(6291456, res.cpu_count * 512 * 1024)

        port_range = (9000, 65500)
        tcp_fin_timeout = 30
        tcp_keepalive_time = 600
        tcp_keepalive_intvl = 30
        tcp_keepalive_probes = 5
        tcp_rmem = (4096, 87380, rmem_max)
        tcp_wmem = (4096, 65536, wmem_max)

        backlog = max(32768, res.cpu_count * 4096)
        somaxconn = max(4096, res.cpu_count * 512)

        dirty_background_bytes = _clamp_dirty_bytes(res.mem_total_bytes, 134217728, 0.01)
        dirty_bytes = max(
            dirty_background_bytes * 2,
            _clamp_dirty_bytes(res.mem_total_bytes, 536870912, 0.04),
        )
        min_free_kbytes = max(67584, res.mem_total_kb // 64)

        dirty_background_ratio = 5
        dirty_ratio = 20
        swappiness = 10 if res.swap_total_gb > 0 else 1
        hugepages = _calculate_hugepages(res)

        return cls(
            shmmax,
            shmall,
            shmmni,
            (semmsl, semmns, semopm, semmni),
            aio_max_nr,
            file_max,
            msgmnb,
            msgmni,
            msgmax,
            rmem_default,
            rmem_max,
            wmem_default,
            wmem_max,
            backlog,
            somaxconn,
            port_range,
            tcp_fin_timeout,
            tcp_keepalive_intvl,
            tcp_keepalive_probes,
            tcp_keepalive_time,
            tcp_rmem,
            tcp_wmem,
            dirty_background_bytes,
            dirty_bytes,
            min_free_kbytes,
            dirty_background_ratio,
            dirty_ratio,
            swappiness,
            hugepages,
        )

    def as_sysctl_dict(self):
        sem = " ".join([str(x) for x in self.kernel_sem])
        tcp_rmem = " ".join([str(x) for x in self.net_ipv4_tcp_rmem])
        tcp_wmem = " ".join([str(x) for x in self.net_ipv4_tcp_wmem])
        port_range = " ".join([str(x) for x in self.net_ipv4_ip_local_port_range])
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


class OracleLimits(object):
    """Process limits recommended for Oracle users."""

    def __init__(self, soft_nproc, hard_nproc, soft_nofile, hard_nofile, soft_stack, hard_stack, memlock_kb):
        self.soft_nproc = int(soft_nproc)
        self.hard_nproc = int(hard_nproc)
        self.soft_nofile = int(soft_nofile)
        self.hard_nofile = int(hard_nofile)
        self.soft_stack = int(soft_stack)
        self.hard_stack = int(hard_stack)
        self.memlock_kb = int(memlock_kb)

    @classmethod
    def from_resources(cls, res):
        concurrency = max(4096, res.cpu_count * 2048)
        nofile = max(65536, res.cpu_count * 32768)
        stack_kb = 10240
        memlock_kb = res.hugepage_size_kb * _calculate_hugepages(res)
        return cls(
            concurrency,
            concurrency,
            nofile,
            nofile,
            stack_kb,
            stack_kb,
            memlock_kb,
        )

    def render(self, user):
        lines = [
            "{0} soft nofile {1}".format(user, self.soft_nofile),
            "{0} hard nofile {1}".format(user, self.hard_nofile),
            "{0} soft nproc {1}".format(user, self.soft_nproc),
            "{0} hard nproc {1}".format(user, self.hard_nproc),
            "{0} soft stack {1}".format(user, self.soft_stack),
            "{0} hard stack {1}".format(user, self.hard_stack),
            "{0} soft memlock {1}".format(user, self.memlock_kb),
            "{0} hard memlock {1}".format(user, self.memlock_kb),
        ]
        return "\n".join(lines) + "\n"


class GroupSpec(object):
    def __init__(self, name, gid=None):
        self.name = name
        self.gid = gid


class UserSpec(object):
    def __init__(self, name, primary_group, supplementary_groups, home, shell="/bin/bash", uid=None, create_home=False):
        self.name = name
        self.primary_group = primary_group
        self.supplementary_groups = tuple(supplementary_groups or [])
        self.home = PathHelper(home)
        self.shell = shell
        self.uid = uid
        self.create_home = bool(create_home)


class DirectorySpec(object):
    def __init__(self, path, owner, group, mode=0o775):
        self.path = PathHelper(path)
        self.owner = owner
        self.group = group
        self.mode = int(mode)


class FileSpec(object):
    def __init__(self, path, content, owner="root", group="root", mode=0o644):
        self.path = PathHelper(path)
        self.content = content
        self.owner = owner
        self.group = group
        self.mode = int(mode)


class PathSettings(object):
    def __init__(self, data_root, profile_dir, ora_inventory, oratab):
        self.data_root = PathHelper(data_root)
        self.profile_dir = PathHelper(profile_dir)
        self.ora_inventory = PathHelper(ora_inventory)
        self.oratab = PathHelper(oratab)


class DatabaseSettings(object):
    def __init__(self, target_version="19c"):
        self.target_version = target_version

    def major_release(self):
        match = re.match(r"^(\d+)", self.target_version.strip().lower())
        if match:
            return int(match.group(1))
        return None

    def is_legacy_release(self):
        major = self.major_release()
        return major is not None and major <= 12


class SetupConfig(object):
    def __init__(self, packages, groups, users, paths, database=None):
        self.packages = tuple(packages)
        self.groups = tuple(groups)
        self.users = dict(users)
        self.paths = paths
        self.database = database or DatabaseSettings()

    def get_user(self, name):
        if name not in self.users:
            raise KeyError("User '{0}' is not defined in the configuration".format(name))
        return self.users[name]

    @staticmethod
    def from_mapping(data):
        packages_section = data.get("packages", {})
        if not isinstance(packages_section, dict):
            raise TypeError("[packages] section must be a table")
        package_list = packages_section.get("install", [])
        if isinstance(package_list, basestring):
            raise TypeError("packages.install must be a list of package names")
        if package_list and not isinstance(package_list, list):
            raise TypeError("packages.install must be a list of package names")
        packages = sorted({str(item) for item in package_list})

        groups_section = data.get("groups", [])
        if groups_section and not isinstance(groups_section, list):
            raise TypeError("[[groups]] section must be a list of tables")
        groups = []
        for entry in groups_section:
            if not isinstance(entry, dict):
                raise TypeError("Each group entry must be a table")
            name = entry.get("name")
            if not isinstance(name, basestring):
                raise TypeError("Group name must be a string")
            gid = entry.get("gid")
            if gid is not None and not isinstance(gid, int):
                raise TypeError("Group gid must be an integer if provided")
            groups.append(GroupSpec(name=name, gid=gid))

        users_section = data.get("users", [])
        if users_section and not isinstance(users_section, list):
            raise TypeError("[[users]] section must be a list of tables")
        users = {}
        for entry in users_section:
            if not isinstance(entry, dict):
                raise TypeError("Each user entry must be a table")
            name = entry.get("name")
            if not isinstance(name, basestring):
                raise TypeError("User name must be a string")
            primary_group = entry.get("primary_group")
            if not isinstance(primary_group, basestring):
                raise TypeError("User {0!r} requires a primary_group string".format(name))
            supplementary = entry.get("supplementary_groups", [])
            if supplementary is None:
                supplementary_groups = []
            elif isinstance(supplementary, list):
                supplementary_groups = [str(item) for item in supplementary]
            else:
                raise TypeError("User {0!r} supplementary_groups must be a list of strings".format(name))
            home_raw = entry.get("home")
            if not isinstance(home_raw, basestring):
                raise TypeError("User {0!r} requires a home path string".format(name))
            shell = entry.get("shell", "/bin/bash")
            if not isinstance(shell, basestring):
                raise TypeError("User {0!r} shell must be a string".format(name))
            uid = entry.get("uid")
            if uid is not None and not isinstance(uid, int):
                raise TypeError("User {0!r} uid must be an integer".format(name))
            create_home = bool(entry.get("create_home", False))
            spec = UserSpec(name, primary_group, supplementary_groups, home_raw, shell, uid, create_home)
            users[name] = spec

        paths_section = data.get("paths")
        if not isinstance(paths_section, dict):
            raise TypeError("[paths] section must be defined in the configuration")

        def _as_path(value, key):
            if not isinstance(value, basestring):
                raise TypeError("paths.{0} must be a string".format(key))
            return PathHelper(value)

        try:
            paths = PathSettings(
                _as_path(paths_section["data_root"], "data_root"),
                _as_path(paths_section["profile_dir"], "profile_dir"),
                _as_path(paths_section["ora_inventory"], "ora_inventory"),
                _as_path(paths_section["oratab"], "oratab"),
            )
        except KeyError as exc:
            raise KeyError("Missing required path setting: {0}".format(exc.args[0]))

        database_section = data.get("database")
        if database_section is None:
            database = DatabaseSettings()
        elif isinstance(database_section, dict):
            target_version = database_section.get("target_version", "19c")
            if not isinstance(target_version, basestring):
                raise TypeError("database.target_version must be a string")
            database = DatabaseSettings(target_version=target_version)
        else:
            raise TypeError("[database] section must be a table if provided")

        return SetupConfig(packages, groups, users, paths, database)


def _simple_toml_load(fh):
    text = fh.read()
    result = {}
    current_table = result
    current_array = None
    pending_array_key = None
    pending_array_target = None
    array_buffer = []

    lines = re.split(r"\r?\n", text)
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if pending_array_key is not None:
            if line.endswith("]"):
                value_line = line[:-1].strip()
                if value_line:
                    array_buffer.append(value_line)
                parsed_array = _parse_array_buffer(array_buffer)
                pending_array_target[pending_array_key] = parsed_array
                pending_array_key = None
                pending_array_target = None
                array_buffer = []
            else:
                array_buffer.append(line)
            continue

        if line.startswith("[[") and line.endswith("]]"):
            array_name = line[2:-2]
            array = result.setdefault(array_name, [])
            current_array = {}
            array.append(current_array)
            current_table = current_array
            continue
        if line.startswith("[") and line.endswith("]"):
            table_name = line[1:-1]
            table = result.setdefault(table_name, {})
            current_table = table
            current_array = None
            continue
        if "=" not in line:
            raise ValueError("Invalid TOML line: {0}".format(raw_line))
        key, value = [item.strip() for item in line.split("=", 1)]
        if value == "[":
            pending_array_key = key
            pending_array_target = current_array if current_array is not None else current_table
            array_buffer = []
            continue
        parsed = _parse_toml_value(value)
        target = current_array if current_array is not None else current_table
        target[key] = parsed
    return result


def _parse_toml_value(value):
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        parts = [part.strip() for part in inner.split(",")]
        return [_parse_toml_value(part) for part in parts]
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    try:
        return int(value)
    except ValueError:
        return value


def _parse_array_buffer(lines):
    items = []
    for line in lines:
        entry = line.rstrip(",").strip()
        if not entry:
            continue
        items.append(_parse_toml_value(entry))
    return items


DEFAULT_CONFIG_PATH = PathHelper(os.path.join(os.path.dirname(__file__), "oracle_setup.toml"))


def load_setup_config(path=None):
    config_path = PathHelper(path) if path else DEFAULT_CONFIG_PATH
    fh = config_path.open("r")
    try:
        data = _simple_toml_load(fh)
    finally:
        fh.close()
    if not isinstance(data, dict):
        raise TypeError("Configuration root must be a table")
    return SetupConfig.from_mapping(data)


class SystemInspector(object):
    MEMINFO_PATH = PathHelper("/proc/meminfo")
    HUGE_PAGE_SIZE_KEY = "Hugepagesize"

    def collect(self):
        meminfo = self._read_meminfo()
        mem_total_kb = int(meminfo.get("MemTotal", 0))
        swap_total_kb = int(meminfo.get("SwapTotal", 0))
        hugepage_size_kb = int(meminfo.get(self.HUGE_PAGE_SIZE_KEY, 2048))
        try:
            cpu_count = os.sysconf("SC_NPROCESSORS_ONLN")
        except (AttributeError, ValueError):
            cpu_count = 0
        if not cpu_count:
            cpu_count = 1
        LOG.debug(
            "System resources - RAM: %s KB, swap: %s KB, CPUs: %s, huge page: %s KB",
            mem_total_kb,
            swap_total_kb,
            cpu_count,
            hugepage_size_kb,
        )
        return ResourceSummary(mem_total_kb, swap_total_kb, cpu_count, hugepage_size_kb)

    def _read_meminfo(self):
        data = {}
        try:
            fh = self.MEMINFO_PATH.open("r", encoding="utf-8")
        except IOError:
            raise RuntimeError("/proc/meminfo is not available on this platform")
        try:
            for line in fh:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                fields = value.strip().split()
                if not fields:
                    continue
                data[key] = int(fields[0])
        finally:
            fh.close()
        return data


class ConfigurationPlan(object):
    def __init__(self, resources, kernel, limits, oracle_user, groups, users, directories, files, packages):
        self.resources = resources
        self.kernel = kernel
        self.limits = limits
        self.oracle_user = oracle_user
        self.groups = list(groups)
        self.users = list(users)
        self.directories = list(directories)
        self.files = list(files)
        self.packages = list(packages)

    def to_dict(self):
        return {
            "resources": {
                "mem_total_kb": self.resources.mem_total_kb,
                "swap_total_kb": self.resources.swap_total_kb,
                "cpu_count": self.resources.cpu_count,
                "hugepage_size_kb": self.resources.hugepage_size_kb,
            },
            "kernel": self.kernel.as_sysctl_dict(),
            "limits": {
                "soft_nproc": self.limits.soft_nproc,
                "hard_nproc": self.limits.hard_nproc,
                "soft_nofile": self.limits.soft_nofile,
                "hard_nofile": self.limits.hard_nofile,
                "soft_stack": self.limits.soft_stack,
                "hard_stack": self.limits.hard_stack,
                "memlock_kb": self.limits.memlock_kb,
            },
            "oracle_user": self.oracle_user,
            "groups": [
                {"name": group.name, "gid": group.gid}
                for group in self.groups
            ],
            "users": [
                {
                    "name": user.name,
                    "primary_group": user.primary_group,
                    "supplementary_groups": list(user.supplementary_groups),
                    "home": str(user.home),
                    "shell": user.shell,
                    "uid": user.uid,
                    "create_home": user.create_home,
                }
                for user in self.users
            ],
            "directories": [
                {
                    "path": str(directory.path),
                    "owner": directory.owner,
                    "group": directory.group,
                    "mode": directory.mode,
                }
                for directory in self.directories
            ],
            "files": [
                {
                    "path": str(file_spec.path),
                    "owner": file_spec.owner,
                    "group": file_spec.group,
                    "mode": file_spec.mode,
                    "content": file_spec.content,
                }
                for file_spec in self.files
            ],
            "packages": list(self.packages),
        }

    def describe(self):
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def persist(self, writer):
        sysctl_path = PathHelper("/etc/sysctl.d/99-oracle.conf")
        limits_path = PathHelper("/etc/security/limits.d/oracle.conf")
        writer.apply_sysctl(self.kernel.as_sysctl_dict(), sysctl_path)
        writer.apply_limits(self.limits.render(self.oracle_user), limits_path)


def _calculate_hugepages(res):
    mem_for_sga_kb = max(0, int(res.mem_total_kb * 0.70) - 2 * 1024 * 1024)
    if mem_for_sga_kb <= 0:
        return 0
    return mem_for_sga_kb // res.hugepage_size_kb


def _clamp_dirty_bytes(total_bytes, low, pct):
    computed = int(total_bytes * pct)
    value = max(int(low), int(computed))
    page = 4096
    remainder = value % page
    if remainder:
        value += page - remainder
    return value


def _render_bash_profile_include(script_name):
    return (
        "# ~/.bash_profile generated by oracle_setup.py\n"
        "umask 027\n"
        "if [ -f ~/.bashrc ]; then\n"
        "  . ~/.bashrc\n"
        "fi\n"
        "if [ -f {0} ]; then\n"
        "  . {0}\n"
        "fi\n"
    ).format(script_name)


def _render_oracle_profile(user, data_dir):
    oracle_base = user.home / "base"
    oracle_home = oracle_base / "dbhome"
    tns_admin = oracle_home / "network" / "admin"
    return (
        "# Oracle environment for {0}\n"
        "export ORACLE_BASE={1}\n"
        "export ORACLE_HOME={2}\n"
        "export ORACLE_SID=ORCLCDB\n"
        "export ORACLE_TERM=xterm\n"
        "export NLS_DATE_FORMAT='YYYY-MM-DD:HH24:MI:SS'\n"
        "export TNS_ADMIN={3}\n"
        "export ORACLE_PATH={4}\n"
        "export LD_LIBRARY_PATH=$ORACLE_HOME/lib\n"
        "export PATH=$ORACLE_HOME/bin:$PATH\n"
        "export ORAENV_ASK=NO\n"
    ).format(
        user.name,
        oracle_base,
        oracle_home,
        tns_admin,
        data_dir,
    )


def _render_fmw_profile(user):
    mw_home = user.home / "mwhome"
    node_manager = user.home / "mwlog" / "nodemanager"
    return (
        "# Fusion Middleware environment for {0}\n"
        "export MW_HOME={1}\n"
        "export NODEMGR_HOME={2}\n"
        "export PATH=$MW_HOME/bin:$PATH\n"
    ).format(
        user.name,
        mw_home,
        node_manager,
    )


def _oracle_directories(user):
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


def _fmw_directories(user):
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


def _oracle_files(user, data_dir, profile_dir):
    profile_script = profile_dir / (user.name + "_oracle.sh")
    profile_include = user.home / ".bash_profile"
    return [
        FileSpec(profile_script, _render_oracle_profile(user, data_dir), owner="root", group="root", mode=0o644),
        FileSpec(profile_include, _render_bash_profile_include(profile_script), owner=user.name, group=user.primary_group, mode=0o640),
    ]


def _fmw_files(user, profile_dir):
    profile_script = profile_dir / (user.name + "_fmw.sh")
    profile_include = user.home / ".bash_profile"
    return [
        FileSpec(profile_script, _render_fmw_profile(user), owner="root", group="root", mode=0o644),
        FileSpec(profile_include, _render_bash_profile_include(profile_script), owner=user.name, group=user.primary_group, mode=0o640),
    ]


def _ora_inventory_file(user, path):
    content = "inventory_loc={0}\ninst_group={1}\n".format(user.home / "oraInventory", user.primary_group)
    inventory_group = "oinstall" if "oinstall" in user.supplementary_groups else user.primary_group
    return FileSpec(path=path, content=content, owner="root", group=inventory_group, mode=0o664)


def _oratab_file(path):
    content = (
        "# /etc/oratab generated by oracle_setup.py\n"
        "# Populate this file after creating Oracle databases.\n"
    )
    return FileSpec(path=path, content=content, owner="root", group="root", mode=0o664)


def _packages_for_plan(config):
    packages = list(config.packages)
    if not packages:
        return packages

    os_major = detect_oracle_linux_major_version()
    if os_major is None or os_major < 8 or "compat-libcap1" not in packages:
        return packages

    filtered = [pkg for pkg in packages if pkg != "compat-libcap1"]
    if config.database.is_legacy_release():
        LOG.warning(
            "compat-libcap1 is unavailable on Oracle Linux %s. Oracle Database %s deployments that require it must install the package manually.",
            os_major,
            config.database.target_version,
        )
    else:
        LOG.debug(
            "Skipping compat-libcap1 on Oracle Linux %s because it is not provided for modern releases.",
            os_major,
        )
    return filtered


def build_plan(resources, oracle_user, fmw_user="fmw", config=None):
    kernel = OracleKernelParameters.from_resources(resources)
    limits = OracleLimits.from_resources(resources)

    config = config or load_setup_config()

    groups = list(config.groups)
    users = []
    directories = []
    files = []

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

    packages = _packages_for_plan(config)

    return ConfigurationPlan(
        resources,
        kernel,
        limits,
        oracle_user,
        groups,
        users,
        directories,
        files,
        packages,
    )


def ensure_root():
    if os.geteuid() != 0:
        raise PermissionError("oracle_setup_py26 requires root privileges to apply changes")


class LegacyRunner(object):
    def __init__(self, script_path=None):
        if script_path is None:
            script_path = PathHelper(os.path.join(os.path.dirname(__file__), LEGACY_SCRIPT_NAME))
        self.script_path = PathHelper(script_path)

    def execute(self, apply_changes, dry_run):
        LOG.debug("LegacyRunner invoked (apply=%s, dry_run=%s)", apply_changes, dry_run)
        if dry_run:
            if not self.script_path.exists():
                LOG.warning("Legacy script %s is missing", self.script_path)
            else:
                LOG.info("[dry-run] Would execute legacy script %s", self.script_path)
            return

        ensure_root()
        if not self.script_path.exists():
            raise IOError("Legacy script not found: {0}".format(self.script_path))

        LOG.info("Executing legacy provisioning script %s", self.script_path)
        process = subprocess.Popen(
            ["/bin/bash", str(self.script_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate(b"y\n")
        if process.returncode != 0:
            LOG.error("Legacy script failed: %s", stderr.strip())
            error = subprocess.CalledProcessError(process.returncode, ["/bin/bash", str(self.script_path)])
            error.output = stdout
            error.stderr = stderr
            raise error
        if stdout:
            LOG.debug("legacy stdout: %s", stdout.strip())
        LOG.info("Legacy provisioning completed successfully")


def run_command(cmd, check=True):
    LOG.debug("Executing command: %s", " ".join(cmd))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if check and process.returncode != 0:
        error = subprocess.CalledProcessError(process.returncode, cmd)
        error.output = stdout
        error.stderr = stderr
        raise error
    if stdout:
        LOG.debug("stdout: %s", stdout.decode("utf-8", "ignore").strip())
    if stderr:
        LOG.debug("stderr: %s", stderr.decode("utf-8", "ignore").strip())
    return process


class PlanWriter(object):
    def __init__(self, dry_run=True):
        self.dry_run = dry_run

    def write_file(self, path, content, mode=None):
        path = PathHelper(path)
        timestamp = _dt.datetime.now().strftime("%Y%m%d%H%M%S")
        if self.dry_run:
            LOG.info("[dry-run] Would write %s", path)
            LOG.debug("Content for %s:\n%s", path, content)
            if mode is not None:
                LOG.debug("[dry-run] Desired mode for %s: %s", path, oct(mode))
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            backup = PathHelper(path.path + ".bak-{0}".format(timestamp))
            shutil.copy2(path.path, backup.path)
            LOG.info("Created backup %s", backup)
        fh = path.open("w", encoding="utf-8")
        try:
            fh.write(content)
        finally:
            fh.close()
        if mode is not None:
            os.chmod(path.path, mode)
        LOG.info("Wrote %s", path)

    def apply_sysctl(self, params, sysctl_path):
        header = "# Generated by oracle_setup_py26.py on {0}\n".format(_dt.datetime.now().isoformat())
        body = "\n".join(["{0} = {1}".format(k, v) for k, v in sorted(params.items())])
        self.write_file(sysctl_path, header + body + "\n", mode=0o644)
        if not self.dry_run:
            run_command(["sysctl", "--system"], check=False)

    def apply_limits(self, content, limits_path):
        header = "# Oracle limits generated on {0}\n".format(_dt.datetime.now().isoformat())
        self.write_file(limits_path, header + content, mode=0o644)


def detect_oracle_linux_major_version(os_release_path=PathHelper("/etc/os-release")):
    try:
        contents = os_release_path.read_text(encoding="utf-8")
    except IOError:
        return None

    data = {}
    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')

    id_value = data.get("ID", "").lower()
    name_value = data.get("NAME", "").lower()
    id_like = data.get("ID_LIKE", "").lower().split()

    if "oracle" not in name_value and id_value not in ("ol", "oracle") and "ol" not in id_like:
        return None

    version_id = data.get("VERSION_ID", "")
    match = re.match(r"^(\d+)", version_id)
    if not match:
        return None
    return int(match.group(1))


def _normalize_whitespace(value):
    if value is None:
        return None
    return " ".join(value.split())


def read_sysctl_value(key):
    path = PathHelper("/proc/sys") / key.replace(".", "/")
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except IOError:
        return None
    return _normalize_whitespace(raw)


def check_installed_packages(packages):
    packages = list(packages)
    if not packages:
        return {}

    rpm = _which("rpm")
    dpkg_query = _which("dpkg-query")

    results = {}
    for pkg in packages:
        if rpm:
            try:
                process = subprocess.Popen([rpm, "-q", pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
            except OSError as exc:
                LOG.warning("Failed to inspect package %s: %s", pkg, exc)
                results[pkg] = None
                continue

            if process.returncode == 0:
                results[pkg] = True
            elif process.returncode == 1:
                results[pkg] = False
            else:
                LOG.warning("Unexpected return code %s while inspecting package %s", process.returncode, pkg)
                results[pkg] = None
            continue

        if dpkg_query:
            try:
                process = subprocess.Popen([dpkg_query, "-W", "-f=${Status}", pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
            except OSError as exc:
                LOG.warning("Failed to inspect package %s: %s", pkg, exc)
                results[pkg] = None
                continue

            if process.returncode != 0:
                results[pkg] = False
            elif b"install ok installed" in (stdout or b""):
                results[pkg] = True
            else:
                results[pkg] = None
            continue

        results[pkg] = None
    return results


def inspect_current_system(plan, sysctl_reader=None, package_checker=None):
    reader = sysctl_reader or read_sysctl_value
    kernel_report = {}

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

    package_results = package_checker(plan.packages) if package_checker else check_installed_packages(plan.packages)
    package_details = {}
    missing_packages = []
    installed_packages = []
    unknown_packages = []

    for pkg in plan.packages:
        status = package_results.get(pkg)
        if status is True:
            package_details[pkg] = "installed"
            installed_packages.append(pkg)
        elif status is False:
            package_details[pkg] = "missing"
            missing_packages.append(pkg)
            recommendations.append("package:{0}".format(pkg))
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


class ModeHandler(object):
    def execute(self, args):  # pragma: no cover - interface definition
        raise NotImplementedError


class AdaptiveMode(ModeHandler):
    def __init__(self, inspector=None, config=None):
        self.inspector = inspector or SystemInspector()
        self.config = config

    def execute(self, args):
        resources = self.inspector.collect()
        plan = build_plan(resources, args.oracle_user, args.fmw_user, config=self.config)
        if args.inspect:
            report = inspect_current_system(plan)
            print(json.dumps(report, indent=2, sort_keys=True))
            return
        writer = PlanWriter(dry_run=not args.apply)
        writer.apply_sysctl(plan.kernel.as_sysctl_dict(), PathHelper(args.sysctl_path))
        limits_content = plan.limits.render(args.oracle_user)
        writer.apply_limits(limits_content, PathHelper(args.limits_path))
        print(plan.describe())


class LegacyMode(ModeHandler):
    def __init__(self, runner=None):
        self.runner = runner or LegacyRunner()

    def execute(self, args):
        self.runner.execute(apply_changes=args.apply, dry_run=not args.apply)


class Provisioner(object):
    def __init__(self, plan, writer, dry_run=True, repo_config=None):
        self.plan = plan
        self.writer = writer
        self.dry_run = dry_run
        self.repo_config = repo_config

    def install_packages(self):
        packages = list(self.plan.packages)
        if not packages:
            LOG.info("No packages requested")
            return

        manager = _which("dnf") or _which("yum")
        if manager:
            self._install_with_dnf(manager, packages)
            return
        manager = _which("apt-get") or _which("apt")
        if manager:
            self._install_with_apt(manager, packages)
            return
        raise EnvironmentError("No supported package manager (dnf/yum or apt) is available on this system")

    def _install_with_dnf(self, executable, packages):
        if self.dry_run:
            LOG.info("[dry-run] Would install packages with %s: %s", executable, ", ".join(packages))
            return
        cmd = [executable, "-y", "install"] + packages
        run_command(cmd)

    def _install_with_apt(self, executable, packages):
        if self.dry_run:
            LOG.info("[dry-run] Would install packages with %s: %s", executable, ", ".join(packages))
            return
        cmd = [executable, "install", "-y"] + packages
        run_command(cmd)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Python 2 compatible oracle setup utility")
    parser.add_argument("--oracle-user", default=DEFAULT_ORACLE_USER)
    parser.add_argument("--fmw-user", default="fmw")
    parser.add_argument("--sysctl-path", default="/etc/sysctl.d/99-oracle.conf")
    parser.add_argument("--limits-path", default="/etc/security/limits.d/oracle.conf")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--mode", choices=["adaptive", "legacy"], default="adaptive")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.mode == "legacy":
        handler = LegacyMode()
    else:
        handler = AdaptiveMode()
    handler.execute(args)


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    main(sys.argv[1:])
