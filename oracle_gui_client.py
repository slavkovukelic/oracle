"""Graphical client for remotely executing Oracle tuning scripts.

This module provides both the Tkinter-based GUI front-end as well as a small
collection of helper utilities that can be reused programmatically.  The
interface allows operators to:

* Discover the available scripts in the repository (Python and shell).
* Inspect the command-line parameters exposed by :mod:`oracle_setup` via the
  newly exported :func:`oracle_setup.build_arg_parser` helper.
* Edit the accompanying ``.toml`` configuration file before dispatching the job.
* Transmit both the script and configuration to a remote execution endpoint and
  surface the execution logs in the GUI.

The helper functions are deliberately separated from the GUI logic so that they
can be unit-tested without requiring a graphical environment.  The GUI is
constructed only when :func:`main` is executed.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import importlib.util
import logging
import posixpath
import pathlib
import shlex
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

LOG = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class ArgumentSpec:
    """Description of a command-line argument for GUI rendering."""

    dest: str
    option_strings: Tuple[str, ...]
    kind: str
    default: Any
    help: str
    choices: Optional[Tuple[Any, ...]] = None

    @property
    def display_label(self) -> str:
        if self.option_strings:
            return ", ".join(self.option_strings)
        return self.dest.replace("_", " ")

    @property
    def primary_option(self) -> str:
        for opt in self.option_strings:
            if opt.startswith("--"):
                return opt
        return self.option_strings[0]


def discover_scripts(root: pathlib.Path) -> Dict[str, pathlib.Path]:
    """Return a mapping of script names to paths within *root*.

    Only files ending in ``.py`` or ``.sh`` are considered scripts.  The search
    is shallow because the repository keeps all dispatchable scripts in the top
    level directory.
    """

    scripts: Dict[str, pathlib.Path] = {}
    for path in sorted(root.iterdir()):
        if path.is_file() and path.suffix in {".py", ".sh"}:
            scripts[path.name] = path
    return scripts


def _classify_action(action: argparse.Action) -> str:
    if isinstance(action, argparse._StoreTrueAction):
        return "store_true"
    if isinstance(action, argparse._CountAction):
        return "count"
    return "store"


def build_argument_specs(parser: argparse.ArgumentParser) -> List[ArgumentSpec]:
    """Convert *parser* actions into :class:`ArgumentSpec` objects."""

    specs: List[ArgumentSpec] = []
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction):
            continue
        if not action.option_strings:
            continue
        kind = _classify_action(action)
        default = action.default
        if isinstance(default, pathlib.Path):
            default = str(default)
        choices = tuple(action.choices) if action.choices else None
        help_text = (action.help or "").strip()
        specs.append(
            ArgumentSpec(
                dest=action.dest,
                option_strings=tuple(action.option_strings),
                kind=kind,
                default=default,
                help=help_text,
                choices=choices,
            )
        )
    return specs


def _stringify(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, pathlib.Path):
        return str(value)
    return str(value)


def build_cli_arguments(specs: Iterable[ArgumentSpec], values: Mapping[str, Any]) -> List[str]:
    """Translate GUI values into CLI arguments."""

    args: List[str] = []
    for spec in specs:
        value = values.get(spec.dest, spec.default)
        if spec.kind == "store_true":
            if value:
                args.append(spec.primary_option)
            continue
        if spec.kind == "count":
            try:
                count = int(value)
            except (TypeError, ValueError):
                count = 0
            if count > 0:
                args.extend([spec.primary_option] * count)
            continue

        normalized_value = _stringify(value)
        normalized_default = _stringify(spec.default)
        if not normalized_value:
            continue
        if normalized_default is not None and normalized_value == normalized_default:
            continue
        args.append(spec.primary_option)
        args.append(normalized_value)
    return args


@dataclasses.dataclass(frozen=True)
class ExecutionBundle:
    """Data sent to the remote execution service."""

    script_path: pathlib.Path
    script_content: bytes
    arguments: Tuple[str, ...]
    config_path: pathlib.Path
    config_content: bytes
    bootstrap_path: Optional[pathlib.Path] = None
    bootstrap_content: Optional[bytes] = None
    environment: Tuple[Tuple[str, str], ...] = dataclasses.field(default_factory=tuple)
    perform_mount: bool = False
    mount_device: Optional[str] = None
    mount_point: Optional[str] = None

    @classmethod
    def from_paths(
        cls,
        script_path: pathlib.Path,
        config_path: pathlib.Path,
        config_text: str,
        arguments: Sequence[str],
        *,
        bootstrap_path: Optional[pathlib.Path] = None,
        environment: Optional[Mapping[str, str]] = None,
        perform_mount: bool = False,
        mount_device: Optional[str] = None,
        mount_point: Optional[str] = None,
    ) -> "ExecutionBundle":
        bootstrap_content = bootstrap_path.read_bytes() if bootstrap_path else None
        env_items: Tuple[Tuple[str, str], ...] = tuple(sorted(environment.items())) if environment else tuple()
        return cls(
            script_path=script_path,
            script_content=script_path.read_bytes(),
            arguments=tuple(arguments),
            config_path=config_path,
            config_content=config_text.encode("utf-8"),
            bootstrap_path=bootstrap_path,
            bootstrap_content=bootstrap_content,
            environment=env_items,
            perform_mount=perform_mount,
            mount_device=mount_device,
            mount_point=mount_point,
        )

    def to_payload(self) -> Dict[str, Any]:
        return {
            "script_name": self.script_path.name,
            "script": base64.b64encode(self.script_content).decode("ascii"),
            "arguments": list(self.arguments),
            "config_name": self.config_path.name,
            "config": base64.b64encode(self.config_content).decode("ascii"),
        }


@dataclasses.dataclass
class ExecutionResult:
    status: str
    stdout: str
    stderr: str
    returncode: Optional[int]
    raw: Mapping[str, Any]


@dataclasses.dataclass(frozen=True)
class SSHConnectionInfo:
    """Connection parameters required to reach the remote host over SSH."""

    host: str
    username: str
    port: int = 22
    password: Optional[str] = None
    key_path: Optional[pathlib.Path] = None
    remote_directory: str = "."


class SSHExecutor:
    """Upload the bundle over SSH and execute it on the remote host."""

    def __init__(self, connection: SSHConnectionInfo, connect_timeout: int = 30, command_timeout: int = 600) -> None:
        self.connection = connection
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout

    def execute(self, bundle: ExecutionBundle) -> ExecutionResult:
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - import guard for optional dependency
            raise RuntimeError(
                "Paramiko is required for SSH execution. Install it with 'pip install paramiko'."
            ) from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: Dict[str, Any] = {
            "hostname": self.connection.host,
            "port": self.connection.port,
            "username": self.connection.username,
            "timeout": self.connect_timeout,
            "banner_timeout": self.connect_timeout,
            "auth_timeout": self.connect_timeout,
            "allow_agent": True,
            "look_for_keys": True,
        }
        if self.connection.password:
            connect_kwargs["password"] = self.connection.password
        if self.connection.key_path:
            connect_kwargs["key_filename"] = str(self.connection.key_path)

        try:
            client.connect(**connect_kwargs)
        except Exception as exc:  # pragma: no cover - depends on network environment
            raise RuntimeError(f"Failed to establish SSH connection: {exc}") from exc

        stdout_chunks: List[bytes] = []
        stderr_chunks: List[bytes] = []
        returncode: Optional[int] = None
        remote_dir = (self.connection.remote_directory or ".").replace("\\", "/")
        remote_script_name = bundle.script_path.name
        remote_config_name = bundle.config_path.name
        remote_bootstrap_name: Optional[str] = (
            bundle.bootstrap_path.name if bundle.bootstrap_path else None
        )
        uploaded_files: List[str] = [remote_script_name, remote_config_name]
        if remote_bootstrap_name:
            uploaded_files.append(remote_bootstrap_name)

        mount_requested = bool(bundle.perform_mount)
        mounted = False
        try:
            sftp = client.open_sftp()
            if remote_dir not in ("", "."):
                self._ensure_remote_directory(sftp, remote_dir)
            remote_script = (
                posixpath.join(remote_dir, remote_script_name)
                if remote_dir not in ("", ".")
                else remote_script_name
            )
            remote_config = (
                posixpath.join(remote_dir, remote_config_name)
                if remote_dir not in ("", ".")
                else remote_config_name
            )
            self._upload_file(sftp, remote_script, bundle.script_content)
            self._upload_file(sftp, remote_config, bundle.config_content)

            if bundle.bootstrap_path is not None:
                if bundle.bootstrap_content is None or not remote_bootstrap_name:
                    raise RuntimeError(
                        "Bootstrap script path was provided without corresponding content."
                    )
                remote_bootstrap = (
                    posixpath.join(remote_dir, remote_bootstrap_name)
                    if remote_dir not in ("", ".")
                    else remote_bootstrap_name
                )
                self._upload_file(sftp, remote_bootstrap, bundle.bootstrap_content)
                sftp.chmod(remote_bootstrap, 0o755)
            if bundle.script_path.suffix == ".sh":
                sftp.chmod(remote_script, 0o755)

            sftp.close()

            if mount_requested:
                if not bundle.mount_device or not bundle.mount_point:
                    raise RuntimeError("Mount device and mount point must be provided when mounting is requested.")
                mkdir_command = f"sudo mkdir -p {shlex.quote(bundle.mount_point)}"
                out, err, code = self._exec_remote_command(client, mkdir_command)
                if out:
                    stdout_chunks.append(out)
                if err:
                    stderr_chunks.append(err)
                if code != 0:
                    raise RuntimeError(self._format_remote_failure("create mount point", mkdir_command, code, err))

                mount_command = self._build_mount_command(bundle.mount_device, bundle.mount_point)
                out, err, code = self._exec_remote_command(client, mount_command)
                if out:
                    stdout_chunks.append(out)
                if err:
                    stderr_chunks.append(err)
                if code != 0:
                    raise RuntimeError(self._format_remote_failure("mount repository", mount_command, code, err))
                mounted = True

            command = self._build_command(bundle, remote_dir)
            out, err, returncode = self._exec_remote_command(client, command, timeout=self.command_timeout)
            if out:
                stdout_chunks.append(out)
            if err:
                stderr_chunks.append(err)
        except Exception as exc:
            raise RuntimeError(f"Remote execution failed: {exc}") from exc
        finally:
            cleanup_stdout: List[bytes] = []
            cleanup_stderr: List[bytes] = []
            if mounted and bundle.mount_point:
                try:
                    umount_command = self._build_umount_command(bundle.mount_point)
                    out, err, _ = self._exec_remote_command(client, umount_command)
                    if out:
                        cleanup_stdout.append(out)
                    if err:
                        cleanup_stderr.append(err)
                except Exception as cleanup_exc:  # pragma: no cover - defensive logging
                    LOG.warning("Failed to unmount remote repository: %s", cleanup_exc)
            try:
                extra_out, extra_err = self._cleanup_remote_files(client, remote_dir, uploaded_files)
                cleanup_stdout.extend(extra_out)
                cleanup_stderr.extend(extra_err)
            except Exception as cleanup_exc:  # pragma: no cover - defensive logging
                LOG.warning("Failed to clean up remote files: %s", cleanup_exc)
            client.close()
            if cleanup_stdout:
                LOG.debug(
                    "Remote cleanup stdout: %s",
                    b"".join(cleanup_stdout).decode("utf-8", errors="replace"),
                )
            if cleanup_stderr:
                LOG.debug(
                    "Remote cleanup stderr: %s",
                    b"".join(cleanup_stderr).decode("utf-8", errors="replace"),
                )

        stdout_bytes = b"".join(stdout_chunks)
        stderr_bytes = b"".join(stderr_chunks)
        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        status = "completed" if returncode == 0 else "failed"
        payload = {
            "status": status,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "returncode": returncode,
            "remote_directory": self.connection.remote_directory,
            "host": self.connection.host,
        }
        return ExecutionResult(
            status=status,
            stdout=stdout_text,
            stderr=stderr_text,
            returncode=returncode,
            raw=payload,
        )

    def _exec_remote_command(
        self,
        client: Any,
        command: str,
        *,
        timeout: Optional[int] = None,
    ) -> Tuple[bytes, bytes, int]:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout or self.command_timeout)
        out = stdout.read()
        err = stderr.read()
        code = stdout.channel.recv_exit_status()
        return out, err, code

    def _format_remote_failure(self, action: str, command: str, code: int, stderr: bytes) -> str:
        stderr_text = stderr.decode("utf-8", errors="replace") if stderr else ""
        details = f" (stderr: {stderr_text.strip()})" if stderr_text.strip() else ""
        return f"Failed to {action} (exit status {code}) using command: {command}{details}"

    def _ensure_remote_directory(self, sftp: Any, remote_dir: str) -> None:
        parts = [part for part in remote_dir.split("/") if part and part != "."]
        current = ""
        for part in parts:
            current = f"{current}/{part}" if current else part
            try:
                sftp.stat(current)
            except (FileNotFoundError, OSError):
                sftp.mkdir(current)

    def _upload_file(self, sftp: Any, remote_path: str, content: bytes) -> None:
        with sftp.file(remote_path, "wb") as remote_file:
            remote_file.write(content)

    def _cleanup_remote_files(
        self,
        client: Any,
        remote_dir: str,
        files: Sequence[str],
    ) -> Tuple[List[bytes], List[bytes]]:
        if not files:
            return [], []
        command_parts: List[str] = []
        if remote_dir not in ("", "."):
            command_parts.extend(["cd", shlex.quote(remote_dir), "&&"])
        command_parts.append("rm -f")
        command_parts.extend(shlex.quote(name) for name in files)
        command = " ".join(command_parts)
        out, err, _ = self._exec_remote_command(client, command)
        stdout_chunks = [out] if out else []
        stderr_chunks = [err] if err else []
        return stdout_chunks, stderr_chunks

    def _build_mount_command(self, device: str, mount_point: str) -> str:
        loop_option = " -o loop" if not device.startswith("/dev/") else ""
        return f"sudo mount{loop_option} {shlex.quote(device)} {shlex.quote(mount_point)}"

    def _build_umount_command(self, mount_point: str) -> str:
        return f"sudo umount {shlex.quote(mount_point)}"

    def _build_command(self, bundle: ExecutionBundle, remote_dir: str) -> str:
        command_parts: List[str] = []
        if remote_dir not in ("", "."):
            command_parts.extend(["cd", shlex.quote(remote_dir), "&&"])

        for key, value in bundle.environment:
            command_parts.append(f"{key}={shlex.quote(value)}")

        if bundle.bootstrap_path is not None:
            target_name = bundle.bootstrap_path.name
            interpreter = "bash"
        else:
            target_name = bundle.script_path.name
            suffix = bundle.script_path.suffix.lower()
            if suffix == ".py":
                interpreter = "python3"
            elif suffix == ".sh":
                interpreter = "bash"
            else:
                interpreter = "bash"

        command_parts.append(shlex.quote(interpreter))
        command_parts.append(shlex.quote(target_name))
        for arg in bundle.arguments:
            command_parts.append(shlex.quote(arg))
        return " ".join(command_parts)


def _load_python_parser(script_path: pathlib.Path) -> Optional[argparse.ArgumentParser]:
    spec = importlib.util.spec_from_file_location(f"oracle_gui_{script_path.stem}", script_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[arg-type]
    if hasattr(module, "build_arg_parser"):
        try:
            parser = module.build_arg_parser()
        except Exception as exc:  # pragma: no cover - defensive; dependent on import
            LOG.exception("Failed to build argument parser from %s", script_path)
            raise RuntimeError(f"Failed to build argument parser: {exc}") from exc
        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError("build_arg_parser() must return an ArgumentParser instance")
        return parser
    return None


class OracleSetupClient(tk.Tk):
    """Tkinter application that drives remote Oracle setup execution."""

    def __init__(
        self,
        script_directory: Optional[pathlib.Path] = None,
        config_path: Optional[pathlib.Path] = None,
        ssh_host: str = "localhost",
        ssh_port: int = 22,
        ssh_username: str = "",
        ssh_remote_directory: str = ".",
    ) -> None:
        super().__init__()
        self.title("Oracle Remote Execution Client")
        self.minsize(900, 700)
        self._ui_thread = threading.current_thread()

        self.script_directory = script_directory or pathlib.Path(__file__).resolve().parent
        self.config_path = config_path or self.script_directory / "oracle_setup.toml"

        self.scripts = discover_scripts(self.script_directory)
        self.argument_specs: List[ArgumentSpec] = []
        self.argument_vars: Dict[str, tk.Variable] = {}

        self.script_var = tk.StringVar(value=next(iter(self.scripts), ""))
        self.ssh_host_var = tk.StringVar(value=ssh_host)
        self.ssh_port_var = tk.StringVar(value=str(ssh_port))
        self.ssh_username_var = tk.StringVar(value=ssh_username)
        self.ssh_password_var = tk.StringVar(value="")
        self.ssh_key_var = tk.StringVar(value="")
        self.ssh_remote_dir_var = tk.StringVar(value=ssh_remote_directory)
        self.repo_device_var = tk.StringVar(value="")
        self.repo_mount_var = tk.StringVar(value="")
        self.repo_mount_enabled_var = tk.BooleanVar(value=False)

        self._build_ui()
        self._load_config()
        if self.script_var.get():
            self._on_script_selected()

    # ------------------------------------------------------------------ UI ---
    def _build_ui(self) -> None:
        main = ttk.Frame(self)
        main.pack(fill="both", expand=True, padx=12, pady=12)

        header = ttk.Frame(main)
        header.pack(fill="x", pady=(0, 10))

        ttk.Label(header, text="Script:").pack(side="left")
        self.script_combo = ttk.Combobox(
            header,
            textvariable=self.script_var,
            values=list(self.scripts.keys()),
            state="readonly",
        )
        self.script_combo.pack(side="left", padx=5, fill="x", expand=True)
        self.script_combo.bind("<<ComboboxSelected>>", lambda event: self._on_script_selected())

        self.run_button = ttk.Button(header, text="Run Remotely", command=self._run_script)
        self.run_button.pack(side="left", padx=(10, 0))

        connection_frame = ttk.LabelFrame(main, text="SSH Connection")
        connection_frame.pack(fill="x", expand=False, pady=(0, 10))

        connection_grid = ttk.Frame(connection_frame)
        connection_grid.pack(fill="x", expand=True, padx=8, pady=8)
        for column in range(4):
            connection_grid.columnconfigure(column, weight=1)

        ttk.Label(connection_grid, text="Host:").grid(row=0, column=0, sticky="w")
        ttk.Entry(connection_grid, textvariable=self.ssh_host_var).grid(row=0, column=1, sticky="we", padx=5)

        ttk.Label(connection_grid, text="Port:").grid(row=0, column=2, sticky="w")
        ttk.Entry(connection_grid, textvariable=self.ssh_port_var, width=6).grid(row=0, column=3, sticky="we", padx=5)

        ttk.Label(connection_grid, text="Username:").grid(row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Entry(connection_grid, textvariable=self.ssh_username_var).grid(row=1, column=1, sticky="we", padx=5, pady=(5, 0))

        ttk.Label(connection_grid, text="Password:").grid(row=1, column=2, sticky="w", pady=(5, 0))
        ttk.Entry(connection_grid, textvariable=self.ssh_password_var, show="*").grid(row=1, column=3, sticky="we", padx=5, pady=(5, 0))

        ttk.Label(connection_grid, text="Private key:").grid(row=2, column=0, sticky="w", pady=(5, 0))
        ttk.Entry(connection_grid, textvariable=self.ssh_key_var).grid(row=2, column=1, sticky="we", padx=5, pady=(5, 0))
        ttk.Button(connection_grid, text="Browse", command=self._browse_key_file).grid(row=2, column=2, sticky="we", padx=5, pady=(5, 0))

        ttk.Label(connection_grid, text="Remote directory:").grid(row=3, column=0, sticky="w", pady=(5, 0))
        ttk.Entry(connection_grid, textvariable=self.ssh_remote_dir_var).grid(row=3, column=1, columnspan=3, sticky="we", padx=5, pady=(5, 0))

        repo_frame = ttk.LabelFrame(main, text="Remote Repository / Mounts")
        repo_frame.pack(fill="x", expand=False, pady=(0, 10))

        repo_grid = ttk.Frame(repo_frame)
        repo_grid.pack(fill="x", expand=True, padx=8, pady=8)
        for column in range(2):
            repo_grid.columnconfigure(column, weight=1)

        ttk.Label(repo_grid, text="ISO Path or Device:").grid(row=0, column=0, sticky="w")
        ttk.Entry(repo_grid, textvariable=self.repo_device_var).grid(row=0, column=1, sticky="we", padx=5)

        ttk.Label(repo_grid, text="Mount Point:").grid(row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Entry(repo_grid, textvariable=self.repo_mount_var).grid(row=1, column=1, sticky="we", padx=5, pady=(5, 0))

        ttk.Checkbutton(
            repo_grid,
            text="Perform Mount",
            variable=self.repo_mount_enabled_var,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))

        arguments_frame = ttk.LabelFrame(main, text="Script Parameters")
        arguments_frame.pack(fill="x", expand=False, pady=(0, 10))
        self.arguments_container = ttk.Frame(arguments_frame)
        self.arguments_container.pack(fill="x", expand=True, padx=8, pady=8)
        self.arguments_container.columnconfigure(1, weight=1)

        config_frame = ttk.LabelFrame(main, text="oracle_setup.toml")
        config_frame.pack(fill="both", expand=True, pady=(0, 10))

        config_toolbar = ttk.Frame(config_frame)
        config_toolbar.pack(fill="x", padx=8, pady=(8, 0))
        ttk.Button(config_toolbar, text="Reload", command=self._load_config).pack(side="left")
        ttk.Button(config_toolbar, text="Save", command=self._save_config).pack(side="left", padx=5)

        text_container = ttk.Frame(config_frame)
        text_container.pack(fill="both", expand=True, padx=8, pady=8)
        self.config_text = tk.Text(text_container, wrap="word")
        scrollbar = ttk.Scrollbar(text_container, orient="vertical", command=self.config_text.yview)
        self.config_text.configure(yscrollcommand=scrollbar.set)
        self.config_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        log_frame = ttk.LabelFrame(main, text="Execution Log")
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_frame, wrap="word", height=12, state="disabled", background="#111", foreground="#eee")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=8)

    # ----------------------------------------------------------- ARGUMENTS ---
    def _on_script_selected(self) -> None:
        script_name = self.script_var.get()
        script_path = self.scripts.get(script_name)
        self.argument_vars.clear()
        for child in self.arguments_container.winfo_children():
            child.destroy()

        if not script_path:
            self.argument_specs = []
            ttk.Label(self.arguments_container, text="No script selected.").grid(row=0, column=0, sticky="w")
            return

        if script_path.suffix == ".py":
            try:
                parser = _load_python_parser(script_path)
            except Exception as exc:
                ttk.Label(
                    self.arguments_container,
                    text=f"Failed to load parser: {exc}",
                ).grid(row=0, column=0, sticky="w")
                self.argument_specs = []
                LOG.exception("Unable to load parser for %s", script_path)
                return
            if parser is None:
                ttk.Label(
                    self.arguments_container,
                    text="Unable to introspect script parameters.",
                ).grid(row=0, column=0, sticky="w")
                self.argument_specs = []
                return
            self.argument_specs = build_argument_specs(parser)
        else:
            self.argument_specs = []
            ttk.Label(
                self.arguments_container,
                text="Parameter introspection is only available for Python scripts.",
            ).grid(row=0, column=0, sticky="w")
            return

        if not self.argument_specs:
            ttk.Label(self.arguments_container, text="Script exposes no configurable parameters.").grid(row=0, column=0, sticky="w")
            return

        for idx, spec in enumerate(self.argument_specs):
            row = idx * 2
            if spec.kind == "store_true":
                var = tk.BooleanVar(value=bool(spec.default))
                widget = ttk.Checkbutton(self.arguments_container, text=spec.display_label, variable=var)
                widget.grid(row=row, column=0, columnspan=2, sticky="w", pady=(2, 0))
            else:
                ttk.Label(self.arguments_container, text=spec.display_label).grid(row=row, column=0, sticky="w", pady=(2, 0))
                if spec.kind == "count":
                    var = tk.IntVar(value=int(spec.default or 0))
                    widget = tk.Spinbox(self.arguments_container, from_=0, to=10, textvariable=var, width=5)
                elif spec.choices:
                    var = tk.StringVar(value=str(spec.default) if spec.default is not None else "")
                    widget = ttk.Combobox(
                        self.arguments_container,
                        textvariable=var,
                        values=[str(choice) for choice in spec.choices],
                        state="readonly",
                    )
                else:
                    var = tk.StringVar(value=str(spec.default) if spec.default is not None else "")
                    widget = ttk.Entry(self.arguments_container, textvariable=var)
                widget.grid(row=row, column=1, sticky="we", padx=(5, 0), pady=(2, 0))
            self.argument_vars[spec.dest] = var

            if spec.help:
                help_label = ttk.Label(self.arguments_container, text=spec.help, foreground="#555", wraplength=600)
                help_label.grid(row=row + 1, column=0, columnspan=2, sticky="w", pady=(0, 4))

    # --------------------------------------------------------------- CONFIG ---
    def _load_config(self) -> None:
        try:
            content = self.config_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            content = ""
        self.config_text.delete("1.0", "end")
        self.config_text.insert("1.0", content)

    def _save_config(self) -> None:
        content = self.config_text.get("1.0", "end-1c")
        try:
            self.config_path.write_text(content, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Save failed", f"Unable to write configuration: {exc}")
            return
        self._append_log(f"Saved configuration to {self.config_path}")

    # -------------------------------------------------------------- EXECUTE ---
    def _collect_argument_values(self) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        for dest, variable in self.argument_vars.items():
            values[dest] = variable.get()
        return values

    def _run_script(self) -> None:
        script_name = self.script_var.get()
        script_path = self.scripts.get(script_name)
        if not script_path:
            messagebox.showerror("No script", "Select a script before running.")
            return

        connection = self._build_connection_info()
        if connection is None:
            return

        config_text = self.config_text.get("1.0", "end-1c")
        try:
            self.config_path.write_text(config_text, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Save failed", f"Unable to persist configuration: {exc}")
            return

        argument_values = self._collect_argument_values()
        cli_args = build_cli_arguments(self.argument_specs, argument_values)
        bootstrap_path = self.scripts.get("oracle_setup_bootstrap.sh")
        if bootstrap_path is None:
            candidate = self.script_directory / "oracle_setup_bootstrap.sh"
            if candidate.exists():
                bootstrap_path = candidate
        if bootstrap_path is None:
            messagebox.showerror(
                "Missing bootstrap script",
                "oracle_setup_bootstrap.sh could not be located in the script directory.",
            )
            return

        mount_device = self.repo_device_var.get().strip()
        mount_point = self.repo_mount_var.get().strip()
        perform_mount = bool(self.repo_mount_enabled_var.get())
        if perform_mount and not mount_device:
            messagebox.showerror("Missing ISO path", "Provide the ISO path or device to mount.")
            return
        if perform_mount and not mount_point:
            messagebox.showerror("Missing mount point", "Provide the mount point to use when mounting the repository.")
            return

        normalized_mount_point = mount_point or None
        repo_mode = "local" if normalized_mount_point else "auto"
        env_vars: Dict[str, str] = {
            "ORACLE_BOOTSTRAP_REPO_MODE": repo_mode,
            "ORACLE_BOOTSTRAP_LOCAL_REPO": normalized_mount_point or "/INSTALL",
        }

        normalized_mount_device = mount_device or None

        try:
            bundle = ExecutionBundle.from_paths(
                script_path,
                self.config_path,
                config_text,
                cli_args,
                bootstrap_path=bootstrap_path,
                environment=env_vars,
                perform_mount=perform_mount,
                mount_device=normalized_mount_device,
                mount_point=normalized_mount_point,
            )
        except OSError as exc:
            messagebox.showerror("Bundle creation failed", f"Unable to prepare execution bundle: {exc}")
            return
        executor = SSHExecutor(connection)

        self.run_button.configure(state="disabled")
        self._append_log("Dispatching execution request...")

        thread = threading.Thread(target=self._run_in_background, args=(executor, bundle), daemon=True)
        thread.start()

    def _run_in_background(self, executor: SSHExecutor, bundle: ExecutionBundle) -> None:
        try:
            result = executor.execute(bundle)
        except Exception as exc:  # pragma: no cover - relies on network exceptions
            self.after(0, lambda: self._handle_failure(exc))
            return
        self.after(0, lambda: self._handle_success(result))

    def _handle_failure(self, exc: Exception) -> None:
        self.run_button.configure(state="normal")
        messagebox.showerror("Execution failed", str(exc))
        self._append_log(f"Execution failed: {exc}")

    def _handle_success(self, result: ExecutionResult) -> None:
        self.run_button.configure(state="normal")
        summary = (
            f"Status: {result.status}\n"
            f"Return code: {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}".strip()
        )
        self._append_log(summary)
        if result.returncode not in (0, None):
            messagebox.showwarning("Execution completed with errors", "The remote script returned a non-zero exit code.")

    def _append_log(self, message: str) -> None:
        def append() -> None:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", message + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        if threading.current_thread() is self._ui_thread:
            append()
        else:
            self.after(0, append)

    # ----------------------------------------------------------- SSH UTILS ---
    def _browse_key_file(self) -> None:
        filename = filedialog.askopenfilename(title="Select private key", filetypes=[("All files", "*.*")])
        if filename:
            self.ssh_key_var.set(filename)

    def _build_connection_info(self) -> Optional[SSHConnectionInfo]:
        host = self.ssh_host_var.get().strip()
        if not host:
            messagebox.showerror("Missing host", "Provide the SSH host name or IP address.")
            return None

        username = self.ssh_username_var.get().strip()
        if not username:
            messagebox.showerror("Missing username", "Provide the SSH username to authenticate with.")
            return None

        port_raw = self.ssh_port_var.get().strip() or "22"
        try:
            port = int(port_raw)
        except ValueError:
            messagebox.showerror("Invalid port", "SSH port must be a number.")
            return None
        if not (0 < port < 65536):
            messagebox.showerror("Invalid port", "SSH port must be between 1 and 65535.")
            return None

        password = self.ssh_password_var.get() or None
        key_value = self.ssh_key_var.get().strip()
        key_path = pathlib.Path(key_value).expanduser() if key_value else None
        remote_dir = self.ssh_remote_dir_var.get().strip() or "."

        return SSHConnectionInfo(
            host=host,
            username=username,
            port=port,
            password=password,
            key_path=key_path,
            remote_directory=remote_dir,
        )


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = OracleSetupClient()
    app.mainloop()


if __name__ == "__main__":
    main()
