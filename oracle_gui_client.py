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
import json
import logging
import pathlib
import threading
import tkinter as tk
from tkinter import messagebox, ttk
import urllib.error
import urllib.request
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

    @classmethod
    def from_paths(
        cls,
        script_path: pathlib.Path,
        config_path: pathlib.Path,
        config_text: str,
        arguments: Sequence[str],
    ) -> "ExecutionBundle":
        return cls(
            script_path=script_path,
            script_content=script_path.read_bytes(),
            arguments=tuple(arguments),
            config_path=config_path,
            config_content=config_text.encode("utf-8"),
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


class RemoteExecutor:
    """HTTP client that posts bundles to a remote execution service."""

    def __init__(self, endpoint: str, timeout: int = 30) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    def execute(self, bundle: ExecutionBundle) -> ExecutionResult:
        data = json.dumps(bundle.to_payload()).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response_data = response.read()
                content_type = response.headers.get("Content-Type", "application/json")
        except urllib.error.URLError as exc:  # pragma: no cover - network errors
            raise RuntimeError(f"Failed to contact execution server: {exc}") from exc

        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
        try:
            payload = json.loads(response_data.decode(charset or "utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError("Execution server returned invalid JSON") from exc

        return ExecutionResult(
            status=str(payload.get("status", "unknown")),
            stdout=str(payload.get("stdout", "")),
            stderr=str(payload.get("stderr", "")),
            returncode=payload.get("returncode"),
            raw=payload,
        )


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
        endpoint: str = "http://localhost:8000/execute",
    ) -> None:
        super().__init__()
        self.title("Oracle Remote Execution Client")
        self.minsize(900, 700)
        self._ui_thread = threading.current_thread()

        self.script_directory = script_directory or pathlib.Path(__file__).resolve().parent
        self.config_path = config_path or self.script_directory / "oracle_setup.toml"
        self.endpoint = endpoint

        self.scripts = discover_scripts(self.script_directory)
        self.argument_specs: List[ArgumentSpec] = []
        self.argument_vars: Dict[str, tk.Variable] = {}

        self.script_var = tk.StringVar(value=next(iter(self.scripts), ""))
        self.server_url_var = tk.StringVar(value=self.endpoint)

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

        ttk.Label(header, text="Server endpoint:").pack(side="left", padx=(10, 0))
        server_entry = ttk.Entry(header, textvariable=self.server_url_var, width=40)
        server_entry.pack(side="left", padx=5)

        self.run_button = ttk.Button(header, text="Run Remotely", command=self._run_script)
        self.run_button.pack(side="left", padx=(10, 0))

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

        config_text = self.config_text.get("1.0", "end-1c")
        try:
            self.config_path.write_text(config_text, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Save failed", f"Unable to persist configuration: {exc}")
            return

        argument_values = self._collect_argument_values()
        cli_args = build_cli_arguments(self.argument_specs, argument_values)
        bundle = ExecutionBundle.from_paths(script_path, self.config_path, config_text, cli_args)
        executor = RemoteExecutor(self.server_url_var.get() or self.endpoint)

        self.run_button.configure(state="disabled")
        self._append_log("Dispatching execution request...")

        thread = threading.Thread(target=self._run_in_background, args=(executor, bundle), daemon=True)
        thread.start()

    def _run_in_background(self, executor: RemoteExecutor, bundle: ExecutionBundle) -> None:
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


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = OracleSetupClient()
    app.mainloop()


if __name__ == "__main__":
    main()
