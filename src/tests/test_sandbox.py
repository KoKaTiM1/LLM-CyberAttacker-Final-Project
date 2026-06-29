import os
import sys
from pathlib import Path


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.model_config import SANDBOX_COMMAND_TIMEOUT_SECONDS
from modules.sandbox import DockerContainerEnvironment, E2BAPIEnvironment, SandboxManager, VirtualBoxEnvironment


def test_build_python_install_prelude_inlines_timeout_value():
    prelude = DockerContainerEnvironment._build_python_install_prelude(["pwntools"])

    assert f"timeout={SANDBOX_COMMAND_TIMEOUT_SECONDS}" in prelude
    assert "timeout=SANDBOX_COMMAND_TIMEOUT_SECONDS" not in prelude
    assert "'pwntools': 'pwn'" in prelude


def test_docker_runtime_bootstrap_guarantees_python_and_packages():
    bootstrap = DockerContainerEnvironment._build_docker_python_runtime_bootstrap(["pwntools", "requests"])

    assert "command -v python3" in bootstrap
    assert "apt-get install -y --no-install-recommends" in bootstrap
    assert "python3 -m venv /tmp/sandbox_env" in bootstrap
    assert "SANDBOX_PYTHON=/tmp/sandbox_env/bin/python" in bootstrap
    assert "$SANDBOX_PYTHON -m pip install --upgrade pip setuptools wheel" in bootstrap
    assert "pwntools requests" in bootstrap


def test_collect_python_packages_adds_pwntools_when_script_imports_pwn():
    packages = DockerContainerEnvironment._collect_python_packages("from pwn import *", ["requests"])

    assert packages == ["requests", "pwntools"]


def test_e2b_prelude_uses_instance_timeout_and_pwntools_import_map():
    env = E2BAPIEnvironment({"api_key": "test", "command_timeout_seconds": 321})

    prelude = env._build_python_install_prelude(["pwntools", "requests"])

    assert "timeout=321" in prelude
    assert '"pwntools": "pwn"' in prelude or "'pwntools': 'pwn'" in prelude
    assert '"requests"' in prelude or "'requests'" in prelude


def test_virtualbox_guestcontrol_command_repeats_executable_after_separator():
    env = VirtualBoxEnvironment(
        {
            "vm_name": "vm",
            "username": "user",
            "password": "pass",
            "vboxmanage_path": "VBoxManage",
        }
    )

    cmd = env._guestcontrol_run_cmd("/usr/bin/python3", "/tmp/script.py", "arg1")

    assert cmd[0].lower().endswith("vboxmanage.exe") or cmd[0] == "VBoxManage"
    assert cmd[1:9] == [
        "guestcontrol", "vm",
        "run", "--username", "user", "--password", "pass",
        "--exe",
    ]
    assert cmd[9:] == ["/usr/bin/python3", "--", "/tmp/script.py", "arg1"]


def test_virtualbox_prefers_program_files_vboxmanage(monkeypatch):
    preferred = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

    monkeypatch.setattr("modules.sandbox.os.path.exists", lambda path: path == preferred)
    monkeypatch.setattr("modules.sandbox.shutil.which", lambda _: r"C:\Windows\System32\VBoxManage")

    resolved = VirtualBoxEnvironment._resolve_vboxmanage_path("VBoxManage")

    assert resolved == preferred


def test_run_test_on_all_prioritizes_virtualbox_execution():
    class FakeEnv:
        def __init__(self, name):
            self.name = name
            self.is_connected = True

        def execute_script(self, script_content, file_type):
            order.append(self.name)
            return type("Result", (), {"success": True, "execution_time": 0.1, "error": None})()

    order = []
    manager = SandboxManager()
    manager.environments = {
        "Docker_Container": FakeEnv("Docker_Container"),
        "E2B_API": FakeEnv("E2B_API"),
        "VirtualBox": FakeEnv("VirtualBox"),
    }

    manager.run_test_on_all("print('x')")

    assert order == ["VirtualBox", "Docker_Container", "E2B_API"]
