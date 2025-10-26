import base64
import io
import pathlib
import sys
import types
from typing import Any, Dict, Optional

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import oracle_setup

from oracle_gui_client import (
    ExecutionBundle,
    SSHConnectionInfo,
    SSHExecutor,
    build_argument_specs,
    build_cli_arguments,
    discover_scripts,
)


def test_argument_specs_include_known_flags():
    parser = oracle_setup.build_arg_parser()
    specs = build_argument_specs(parser)
    spec_map = {spec.dest: spec for spec in specs}

    assert "mode" in spec_map
    assert spec_map["mode"].choices == ("adaptive", "legacy")
    assert spec_map["apply"].kind == "store_true"
    assert spec_map["verbose"].kind == "count"


def test_build_cli_arguments_handles_boolean_and_count():
    parser = oracle_setup.build_arg_parser()
    specs = build_argument_specs(parser)
    values = {
        "apply": True,
        "mode": "legacy",
        "verbose": 2,
        "oracle_user": "dbadmin",
        "log_format": "json",
    }

    args = build_cli_arguments(specs, values)

    assert args.count("--verbose") == 2
    assert "--apply" in args
    assert "--mode" in args and args[args.index("--mode") + 1] == "legacy"
    assert "--oracle-user" in args and args[args.index("--oracle-user") + 1] == "dbadmin"
    assert "--log-format" in args and args[args.index("--log-format") + 1] == "json"


def test_execution_bundle_payload(tmp_path):
    script_path = tmp_path / "example.py"
    script_path.write_text("print('hello')\n", encoding="utf-8")
    config_path = tmp_path / "config.toml"
    config_text = "[section]\nvalue = 1\n"

    bundle = ExecutionBundle.from_paths(script_path, config_path, config_text, ["--mode", "legacy"])
    payload = bundle.to_payload()

    assert payload["arguments"] == ["--mode", "legacy"]
    assert base64.b64decode(payload["script"]).decode("utf-8") == "print('hello')\n"
    assert base64.b64decode(payload["config"]).decode("utf-8") == config_text


def test_ssh_executor_round_trip(monkeypatch, tmp_path):
    script_path = tmp_path / "example.py"
    script_path.write_text("print('test')\n", encoding="utf-8")
    config_path = tmp_path / "config.toml"
    config_text = "name = 'value'\n"
    bundle = ExecutionBundle.from_paths(script_path, config_path, config_text, ["--mode", "legacy"])

    uploaded: Dict[str, bytes] = {}
    commands = []

    class DummySFTP:
        def __init__(self) -> None:
            self.closed = False

        def file(self, path: str, mode: str):
            class _Writer(io.BytesIO):
                def __init__(self) -> None:
                    super().__init__()

                def close(self_nonlocal) -> None:
                    uploaded[path] = self_nonlocal.getvalue()
                    super().close()

            writer = _Writer()
            return writer

        def chmod(self, path: str, mode: int) -> None:
            return None

        def mkdir(self, path: str) -> None:
            pass

        def stat(self, path: str):
            raise FileNotFoundError

        def close(self) -> None:
            self.closed = True

    class DummyChannel:
        def __init__(self, code: int) -> None:
            self._code = code

        def recv_exit_status(self) -> int:
            return self._code

    class DummyStream(io.BytesIO):
        def __init__(self, data: bytes, code: int) -> None:
            super().__init__(data)
            self.channel = DummyChannel(code)

    class DummySSHClient:
        def __init__(self) -> None:
            self.connected_with: Dict[str, Any] = {}
            self.closed = False

        def set_missing_host_key_policy(self, policy: Any) -> None:
            self.policy = policy

        def connect(self, **kwargs: Any) -> None:
            self.connected_with = kwargs

        def open_sftp(self) -> DummySFTP:
            return DummySFTP()

        def exec_command(self, command: str, timeout: Optional[int] = None):
            commands.append((command, timeout))
            return None, DummyStream(b"ok", 0), DummyStream(b"", 0)

        def close(self) -> None:
            self.closed = True

    class DummyAutoAddPolicy:
        pass

    dummy_module = types.SimpleNamespace(SSHClient=DummySSHClient, AutoAddPolicy=DummyAutoAddPolicy)
    monkeypatch.setitem(sys.modules, "paramiko", dummy_module)

    connection = SSHConnectionInfo(
        host="example.com",
        username="oracle",
        remote_directory="/tmp/gui",
    )
    executor = SSHExecutor(connection)
    result = executor.execute(bundle)

    assert result.status == "completed"
    assert result.stdout == "ok"
    assert uploaded["/tmp/gui/example.py"] == script_path.read_bytes()
    assert uploaded["/tmp/gui/config.toml"] == config_text.encode("utf-8")
    assert commands[0][0].startswith("cd /tmp/gui && python3 example.py --mode legacy")


def test_discover_scripts_includes_repo_files():
    root = pathlib.Path(__file__).resolve().parents[1]
    scripts = discover_scripts(root)
    assert "oracle_setup.py" in scripts
    assert scripts["oracle_setup.py"].is_file()
