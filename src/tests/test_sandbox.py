import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.model_config import SANDBOX_COMMAND_TIMEOUT_SECONDS
from modules.sandbox import DockerContainerEnvironment


def test_build_python_install_prelude_inlines_timeout_value():
    prelude = DockerContainerEnvironment._build_python_install_prelude(["pwntools"])

    assert f"timeout={SANDBOX_COMMAND_TIMEOUT_SECONDS}" in prelude
    assert "timeout=SANDBOX_COMMAND_TIMEOUT_SECONDS" not in prelude
    assert "'pwntools': 'pwn'" in prelude
