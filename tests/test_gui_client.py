import base64
import http.server
import json
import pathlib
import socketserver
import threading
from typing import Any, Dict

import sys

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import oracle_setup

from oracle_gui_client import (
    ExecutionBundle,
    RemoteExecutor,
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


class _RecorderHandler(http.server.BaseHTTPRequestHandler):
    received: Dict[str, Any] = {}

    def do_POST(self) -> None:  # pragma: no cover - exercised via integration test
        length = int(self.headers.get("Content-Length", "0"))
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        _RecorderHandler.received = data
        body = json.dumps({"status": "ok", "stdout": "done", "stderr": "", "returncode": 0}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # pragma: no cover - silence test output
        return


def test_remote_executor_round_trip(tmp_path):
    script_path = tmp_path / "example.py"
    script_path.write_text("print('test')\n", encoding="utf-8")
    config_path = tmp_path / "config.toml"
    config_text = "name = 'value'\n"
    bundle = ExecutionBundle.from_paths(script_path, config_path, config_text, ["--mode", "legacy"])

    class _Server(socketserver.TCPServer):
        allow_reuse_address = True

    server = _Server(("127.0.0.1", 0), _RecorderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_address[1]}"
        executor = RemoteExecutor(endpoint)
        result = executor.execute(bundle)
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert result.status == "ok"
    assert result.stdout == "done"
    assert _RecorderHandler.received["arguments"] == ["--mode", "legacy"]


def test_discover_scripts_includes_repo_files():
    root = pathlib.Path(__file__).resolve().parents[1]
    scripts = discover_scripts(root)
    assert "oracle_setup.py" in scripts
    assert scripts["oracle_setup.py"].is_file()
