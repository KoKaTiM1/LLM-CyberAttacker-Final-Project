"""
Updated Sandbox System with Correct 3 Environments:
1. Docker Container
2. E2B API
3. VirtualBox
"""

import json
import logging
import re
from abc import ABC, abstractmethod
import subprocess
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import argparse
import tempfile
import os
from datetime import datetime
from .model_config import SANDBOX_COMMAND_TIMEOUT_SECONDS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def analyze_exploitation_results(output: str, error: str = None, 
                               vulnerability_type: str = None) -> dict:
    """
    Analyze exploitation results to determine if attack actually succeeded
    and provide learning feedback for LangGraph
    """
    
    # Success indicators by vulnerability type
    success_patterns = {
        "buffer overflow": [
            "shell spawned", "code execution", "overflow confirmed", 
            "eip control", "return address", "shellcode executed",
            "segmentation fault with control", "generated payload",
            "payload components"
        ],
        "format string": [
            "memory leaked", "stack dumped", "format string exploited",
            "memory read", "arbitrary read", "printf vulnerability confirmed"
        ],
        "use after free": [
            "use after free confirmed", "dangling pointer", 
            "heap manipulation", "freed memory accessed", 
            "memory corruption achieved"
        ],
        "general": [
            "exploit successful", "vulnerability confirmed", "attack succeeded",
            "system compromised", "access gained", "privilege escalation",
            "generated payload", "payload components", "crashed with exit status",
            "likely triggered a crash", "segmentation fault with control"
        ]
    }
    
    # Failure patterns
    failure_patterns = [
        "access denied", "permission denied", "authentication failed",
        "blocked", "filtered", "protected", "mitigation active",
        "aslr enabled", "stack canary", "dep enabled", "segmentation fault",
        "illegal instruction", "core dumped", "killed", "aborted"
    ]
    
    # Learning indicators  
    learning_patterns = {
        "need_privileges": ["permission denied", "access denied", "eacces"],
        "memory_protection": ["segmentation fault", "stack canary", 
                             "aslr", "dep"],
        "input_filtering": ["filtered", "blocked", "sanitized", "escaped"],
        "wrong_offset": ["wrong address", "invalid pointer", "bad offset"],
        "need_different_payload": ["payload failed", "shellcode failed", 
                                 "nop sled"]
    }
    
    output_lower = output.lower() if output else ""
    error_lower = str(error).lower() if error else ""
    combined_text = f"{output_lower} {error_lower}"
    controlled_crash = (
        "segmentation fault with control" in combined_text or
        "returncode=-11" in combined_text or
        "sigsegv" in combined_text
    )
    
    # Check for success
    success_found = []
    patterns_to_check = (success_patterns.get(vulnerability_type, []) + 
                        success_patterns["general"])
    
    for pattern in patterns_to_check:
        if pattern in combined_text:
            success_found.append(pattern)
    if controlled_crash and "segmentation fault with control" not in success_found:
        success_found.append("segmentation fault with control")
    
    # Check for failure reasons
    failures_found = []
    for pattern in failure_patterns:
        if controlled_crash and pattern == "segmentation fault":
            continue
        if pattern in combined_text:
            failures_found.append(pattern)
    
    # Determine learning feedback
    learning_feedback = []
    suggestions = []
    
    for category, patterns in learning_patterns.items():
        for pattern in patterns:
            if pattern in combined_text:
                if category == "need_privileges":
                    suggestions.append("Try privilege escalation techniques")
                    suggestions.append("Look for SUID binaries or sudo misconfigurations")
                elif category == "memory_protection":
                    suggestions.append("Bypass memory protections (ROP, JOP)")
                    suggestions.append("Try information disclosure to leak addresses")
                elif category == "input_filtering":
                    suggestions.append("Try encoding/obfuscation techniques")
                    suggestions.append("Look for filter bypass methods")
                elif category == "wrong_offset":
                    suggestions.append("Recalculate buffer offsets")
                    suggestions.append("Try pattern-based offset discovery")
                elif category == "need_different_payload":
                    suggestions.append("Try different shellcode")
                    suggestions.append("Adjust payload for target architecture")
                
                learning_feedback.append(category)
    
    # Determine overall result
    exploitation_successful = (
        len(success_found) > 0 and
        (len(failures_found) == 0 or controlled_crash)
    )
    
    if (not exploitation_successful and not failures_found and 
        not success_found):
        # No clear indicators - analyze output for hints
        if "error" in combined_text or "fail" in combined_text:
            exploitation_successful = False
            learning_feedback.append("general_failure")
            suggestions.append("Review error messages for specific failure causes")
        elif len(output_lower) < 10:
            # Very short output might indicate crash or termination
            exploitation_successful = False
            learning_feedback.append("possible_crash")
            suggestions.append("Check if exploit causes premature termination")
    
    return {
        "exploitation_successful": exploitation_successful,
        "confidence": "high" if (success_found or failures_found) else "medium",
        "success_indicators": success_found,
        "failure_indicators": failures_found,
        "learning_categories": list(set(learning_feedback)),
        "suggestions": list(set(suggestions)),
        "raw_analysis": {
            "output_length": len(output) if output else 0,
            "error_present": bool(error),
            "vulnerability_type": vulnerability_type
        }
    }


@dataclass
class TestResult:
    """Data class to store test results"""
    environment: str
    success: bool
    output: str
    execution_time: float
    error: Optional[str] = None


class SandboxEnvironment(ABC):
    """Abstract base class for sandbox environments"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.is_connected = False
    
    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the environment"""
        pass
    
    @abstractmethod
    def disconnect(self) -> bool:
        """Disconnect from the environment"""
        pass
    
    @abstractmethod
    def execute_script(self, script_content: str) -> TestResult:
        """Execute script in the environment"""
        pass
    
    @abstractmethod
    def upload_file(self, local_file_path: str, remote_file_path: str = None) -> bool:
        """Upload a file to the sandbox environment"""
        pass
    
    @abstractmethod
    def make_executable(self, file_path: str) -> bool:
        """Make a file executable in the sandbox"""
        pass
    
    @abstractmethod
    def execute_against_target(self, attack_script: str, target_file: str, script_type: str = "python") -> TestResult:
        """Execute attack script against uploaded target file"""
        pass
    
    @abstractmethod
    def check_health(self) -> bool:
        """Check if environment is healthy and ready"""
        pass


class DockerContainerEnvironment(SandboxEnvironment):
    """Docker Container environment implementation with C and Python support"""
    
    # DockerContainerEnvironment.__init__
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Docker_Container", config)
        # Use gcc image with both Python and gcc for multi-language support
        self.image = config.get("image", "gcc:latest")
        self.container_name = config.get("container_name", "sandbox-test")
        self.docker_command = config.get("docker_command", "docker")
        self.container_id = None
        # Config-driven setup commands and Python packages
        self.setup_commands: List[str] = config.get("setup_commands", []) or []
        self.python_packages: List[str] = config.get("python_packages", []) or []

    @staticmethod
    def _build_python_install_prelude(packages: List[str]) -> str:
        """Build the in-container package bootstrap script with concrete values."""
        packages_literal = json.dumps(packages)
        install_timeout = SANDBOX_COMMAND_TIMEOUT_SECONDS
        return f"""
import subprocess
import sys
import importlib

_SANDBOX_PACKAGES = {packages_literal}
_SANDBOX_IMPORT_MAP = {{'pwntools': 'pwn'}}

def _ensure_sandbox_packages():
    for pkg in _SANDBOX_PACKAGES:
        import_name = _SANDBOX_IMPORT_MAP.get(pkg, pkg)
        try:
            importlib.import_module(import_name)
        except ImportError:
            try:
                base_cmd = [sys.executable, '-m', 'pip', 'install', pkg]
                candidate_cmds = [
                    base_cmd + ['--break-system-packages'],
                    base_cmd,
                ]
                last_error = ''
                for cmd in candidate_cmds:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='replace',
                        timeout={install_timeout},
                    )
                    if result.returncode == 0:
                        break
                    last_error = result.stderr
                else:
                    print(f"[sandbox] Failed to install {{pkg}}: {{last_error}}")
            except Exception as e:
                print(f"[sandbox] Error installing {{pkg}}: {{e}}")

_ensure_sandbox_packages()

"""

    
    def connect(self) -> bool:
        """Connect to Docker environment"""
        try:
            # Check if Docker is available
            result = subprocess.run(
                [self.docker_command, "--version"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=5
            )
            
            if result.returncode != 0:
                logger.error("Docker is not available or not installed")
                return False
            
            # Pull the image if needed
            logger.info(f"Pulling Docker image: {self.image}")
            pull_result = subprocess.run(
                [self.docker_command, "pull", self.image],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120
            )
            
            if pull_result.returncode != 0:
                logger.warning(f"Could not pull image {self.image}, using existing")
            
            self.is_connected = True
            logger.info(f"Connected to Docker environment with image: {self.image}")
            return True
            
        except Exception as e:
            logger.error(f"Docker connection error: {e}")
            return False
    
    def disconnect(self) -> bool:
        """Disconnect from Docker environment"""
        try:
            # Clean up any running containers
            if self.container_id:
                subprocess.run(
                    [self.docker_command, "stop", self.container_id],
                    capture_output=True,
                    timeout=10
                )
                subprocess.run(
                    [self.docker_command, "rm", self.container_id],
                    capture_output=True,
                    timeout=10
                )
                self.container_id = None
            
            self.is_connected = False
            logger.info("Disconnected from Docker environment")
            return True
            
        except Exception as e:
            logger.error(f"Docker disconnection error: {e}")
            return False
    
    # DockerContainerEnvironment.execute_script
    def execute_script(self, script_content: str, file_type: str = "python") -> TestResult:
        """Execute script in Docker container with C and Python support (+ setup_commands and python_packages)"""
        start_time = time.time()

        if not self.is_connected:
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=0,
                error="Not connected to Docker environment",
            )

        try:
            if file_type.lower() == "c":
                # For C, reuse existing implementation (no python packages needed)
                return self._execute_c_script(script_content, start_time)

            # Python execution path with on-demand package install and setup_commands
            # Determine packages to ensure inside the container
            packages: List[str] = list(self.python_packages or [])

            # Detect explicit pwntools usage in script
            needs_pwntools = "from pwn import" in script_content or "import pwn" in script_content
            if needs_pwntools and "pwntools" not in packages:
                packages.append("pwntools")

            install_prelude = self._build_python_install_prelude(packages)

            wrapper_path = None

            # Write combined script (installer + user code) to a temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
                f.write(install_prelude + script_content)
                temp_script_path = f.name

            try:
                setup_block = "\n".join(self.setup_commands or [])
                wrapper_script = f"""#!/bin/bash
set -e
cd /tmp
{setup_block}
python3 /script.py
"""

                with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.sh', delete=False, newline='\n'
                ) as wrapper_file:
                    wrapper_file.write(wrapper_script)
                    wrapper_path = wrapper_file.name

                docker_cmd = [
                    self.docker_command, "run", "--rm",
                    "-v", f"{temp_script_path}:/script.py",
                    "-v", f"{wrapper_path}:/wrapper.sh",
                    "-w", "/tmp",
                    self.image,
                    "bash", "/wrapper.sh",
                ]

                result = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                errors='replace',
                timeout=SANDBOX_COMMAND_TIMEOUT_SECONDS
                )

                execution_time = time.time() - start_time

                return TestResult(
                    environment=self.name,
                    success=result.returncode == 0,
                    output=result.stdout,
                    execution_time=execution_time,
                    error=result.stderr if result.returncode != 0 else None,
                )
            finally:
                try:
                    os.unlink(temp_script_path)
                except Exception:
                    pass
                if wrapper_path:
                    try:
                        os.unlink(wrapper_path)
                    except Exception:
                        pass

        except Exception as e:
            execution_time = time.time() - start_time
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=execution_time,
                error=f"Docker execution error: {e}",
            )
    
    def _execute_python_script(self, script_content: str, start_time: float) -> TestResult:
        """Execute Python script in Docker container"""
        # Check if script needs pwntools
        needs_pwntools = "from pwn import" in script_content or "import pwn" in script_content
        
        # Create a temporary file for the Python script
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            if needs_pwntools:
                # Add pwntools installation at the beginning
                install_script = """
import subprocess
import sys
import os

# Install pwntools if not already installed
try:
    import pwn
    print("✅ pwntools already available")
except ImportError:
    print("📦 Installing pwntools...")
    try:
        # Install with break-system-packages flag for newer Python versions
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "pwntools", 
            "--break-system-packages"
        ], capture_output=True, text=True, encoding='utf-8',
                errors='replace',
                timeout=120)
        
        if result.returncode == 0:
            print(" pwntools installation successful")
        else:
            print(" pwntools installation failed:", result.stderr)
    except Exception as e:
        print(f" Installation error: {e}")

# Original script follows:
"""
                f.write(install_script + script_content)
            else:
                f.write(script_content)
            temp_script_path = f.name
        
        try:
            # Use Python from gcc container (which has python3)
            # Create a writable working directory and set proper PATH
            docker_cmd = [
                self.docker_command, "run", "--rm",
                "-v", f"{temp_script_path}:/script.py",
                "-w", "/tmp",  # Set working directory to writable /tmp
                self.image,
                "bash", "-c", "cd /tmp && python3 /script.py"
            ]
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30
            )
            
            execution_time = time.time() - start_time
            
            return TestResult(
                environment=self.name,
                success=result.returncode == 0,
                output=result.stdout,
                execution_time=execution_time,
                error=result.stderr if result.returncode != 0 else None
            )
            
        finally:
            # Clean up temporary file
            os.unlink(temp_script_path)
    
    def _execute_c_script(self, script_content: str, start_time: float) -> TestResult:
        """Execute C script in Docker container with compilation"""
        # Create a temporary file for the C source code
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False, encoding='utf-8') as f:
            f.write(script_content)
            temp_c_path = f.name
        
        try:
            # Use gcc container which has gcc pre-installed
            docker_cmd = [
                self.docker_command, "run", "--rm",
                "-v", f"{temp_c_path}:/program.c",
                self.image,
                "bash", "-c", "gcc -o /program /program.c -w && /program"
            ]
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30
            )
            
            execution_time = time.time() - start_time
            
            return TestResult(
                environment=self.name,
                success=result.returncode == 0,
                output=result.stdout,
                execution_time=execution_time,
                error=result.stderr if result.returncode != 0 else None
            )
            
        finally:
            # Clean up temporary file
            os.unlink(temp_c_path)
    
    def check_health(self) -> bool:
        """Check Docker environment health"""
        if not self.is_connected:
            return False
            
        try:
            # Test Docker with a simple command
            result = subprocess.run(
                [self.docker_command, "run", "--rm", self.image, "python", "-c", "print('OK')"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Docker health check error: {e}")
            return False
    
    def upload_file(self, local_file_path: str, remote_file_path: str = None) -> bool:
        """Upload a file to the Docker container"""
        if not self.is_connected:
            logger.error("Not connected to Docker environment")
            return False
        
        if not os.path.exists(local_file_path):
            logger.error(f"Local file not found: {local_file_path}")
            return False
        
        # Use remote path or default to /tmp/uploaded_file
        if remote_file_path is None:
            filename = os.path.basename(local_file_path)
            remote_file_path = f"/tmp/{filename}"
        
        try:
            # For Docker, we'll store file contents and write them during execution
            # Read the local file content
            with open(local_file_path, 'r') as f:
                file_content = f.read()
            
            # Store the file content for later use - we'll write it when executing
            if not hasattr(self, '_uploaded_files'):
                self._uploaded_files = {}
            
            self._uploaded_files[remote_file_path] = file_content
            
            logger.info(f"File content cached for Docker: {local_file_path} -> {remote_file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Docker file upload error: {e}")
            return False
    
    def make_executable(self, file_path: str) -> bool:
        """Make a file executable in Docker container"""
        if not self.is_connected:
            logger.error("Not connected to Docker environment")
            return False
        
        try:
            result = subprocess.run(
                [self.docker_command, "run", "--rm", "-v", f"{file_path}:{file_path}",
                 self.image, "chmod", "+x", file_path],
                capture_output=True, text=True, encoding='utf-8',
                errors='replace',
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"File made executable in Docker: {file_path}")
                return True
            else:
                logger.error(f"Failed to make executable: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Docker make executable error: {e}")
            return False
    
    def execute_against_target(self, attack_script: str, target_file: str,
                              script_type: str = "python") -> TestResult:
        """Execute attack script against uploaded target file in Docker"""
        start_time = time.time()
        
        if not self.is_connected:
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=0,
                error="Not connected to Docker environment"
            )
        
        try:
            prepared_script = attack_script
            target_source = ""
            if hasattr(self, '_uploaded_files') and target_file in self._uploaded_files:
                target_source = self._uploaded_files[target_file]

            if script_type.lower() == "python":
                prepared_script = re.sub(
                    r"BINARY\s*=\s*['\"]\.\/vulnerable['\"]",
                    f"BINARY = {target_file!r}",
                    prepared_script,
                )
                if "interactive()" in prepared_script:
                    prepared_script = prepared_script.replace(
                        "p.interactive()",
                        (
                            "try:\n"
                            "    output = p.recvrepeat(2)\n"
                            "    if output:\n"
                            "        print(output.decode(errors='replace'))\n"
                            "finally:\n"
                            "    p.close()"
                        ),
                    )

                # Adapt stdin-oriented pwntools scripts for binaries that actually
                # consume the payload via argv[1], such as the sample file demo.
                uses_argv_input = "argv[1]" in target_source and "process(BINARY)" in prepared_script
                if uses_argv_input:
                    buffer_match = re.search(r"char\s+\w+\[(\d+)\]", target_source)
                    if buffer_match:
                        buffer_size = int(buffer_match.group(1))
                        # Heuristic for the demo target: buffer + saved RBP on amd64.
                        prepared_script = re.sub(
                            r"OFFSET\s*=\s*\d+",
                            f"OFFSET = {buffer_size + 8}",
                            prepared_script,
                            count=1,
                        )

                    # argv strings cannot contain NUL bytes, so replace the placeholder
                    # packed address with a printable overwrite of the same width.
                    prepared_script = re.sub(
                        r"p64\([^)]+\)",
                        "b'B' * 8",
                        prepared_script,
                    )
                    prepared_script = re.sub(
                        r"p32\([^)]+\)",
                        "b'B' * 4",
                        prepared_script,
                    )

                    prepared_script = re.sub(
                        r"p\s*=\s*process\(BINARY\)\s*.*?p\.close\(\)",
                        (
                            "import subprocess\n\n"
                            "result = subprocess.run([BINARY, payload], capture_output=True)\n"
                            "if result.stdout:\n"
                            "    print(result.stdout.decode(errors='replace'))\n"
                            "if result.stderr:\n"
                            "    print(result.stderr.decode(errors='replace'))\n"
                            "if result.returncode < 0:\n"
                            "    print('segmentation fault with control')\n"
                            "    print(f'returncode={result.returncode}')\n"
                            "elif result.returncode != 0:\n"
                            "    print(f'returncode={result.returncode}')"
                        ),
                        prepared_script,
                        flags=re.DOTALL,
                    )

                packages: List[str] = list(self.python_packages or [])
                needs_pwntools = "from pwn import" in prepared_script or "import pwn" in prepared_script
                if needs_pwntools and "pwntools" not in packages:
                    packages.append("pwntools")

                install_prelude = self._build_python_install_prelude(packages)
                prepared_script = install_prelude + prepared_script

            # Create temp file for attack script
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{script_type}',
                                           delete=False, encoding='utf-8') as f:
                f.write(prepared_script)
                temp_script_path = f.name
            
            # Create a comprehensive script that handles file creation and execution
            setup_block = "\n".join(self.setup_commands or [])
            target_build_block = ""
            execution_target = target_file
            if target_file.endswith(".c"):
                execution_target = "/tmp/target"
                target_build_block = f"""
echo "Compiling C target: {target_file}"
gcc {target_file} -o {execution_target} -fno-stack-protector -z execstack -no-pie
chmod +x {execution_target}
"""

            wrapper_script = f'''#!/bin/bash

set -e
export TERM=xterm

# One-time container setup for tools and pip packages
{setup_block}

# Create target file if it was uploaded
if [ -n "$TARGET_FILE_CONTENT" ]; then
    echo "Creating target file: {target_file}"
    echo "$TARGET_FILE_CONTENT" > {target_file}
    chmod +x {target_file} 2>/dev/null || true
fi

{target_build_block}

# Execute the attack script
if [ "{script_type}" = "python" ]; then
    python3 /attack.{script_type} {execution_target}
elif [ "{script_type}" = "c" ]; then
    gcc /attack.{script_type} -o /tmp/attack_binary -w && /tmp/attack_binary {target_file}
else
    chmod +x /attack.{script_type} && /attack.{script_type} {execution_target}
fi
'''
            
            # Create wrapper script file with Unix line endings
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.sh', delete=False, newline='\n'
            ) as f:
                f.write(wrapper_script)
                wrapper_path = f.name
            
            # Prepare environment variables
            env_vars = []
            if hasattr(self, '_uploaded_files') and target_file in self._uploaded_files:
                env_vars.extend(["-e", f"TARGET_FILE_CONTENT={self._uploaded_files[target_file]}"])
            
            # Execute in Docker with mounted files
            docker_cmd = [
                self.docker_command, "run", "--rm",
                "-v", f"{temp_script_path}:/attack.{script_type}",
                "-v", f"{wrapper_path}:/wrapper.sh",
                "-w", "/tmp"
            ] + env_vars + [
                self.image,
                "bash", "/wrapper.sh"
            ]
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=SANDBOX_COMMAND_TIMEOUT_SECONDS
            )
            
            execution_time = time.time() - start_time
            
            # Clean up temp files
            try:
                os.unlink(temp_script_path)
                os.unlink(wrapper_path)
            except:
                pass
            
            return TestResult(
                environment=self.name,
                success=result.returncode == 0,
                output=result.stdout,
                execution_time=execution_time,
                error=result.stderr if result.returncode != 0 else None
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            # Clean up temp files
            try:
                os.unlink(temp_script_path)
                os.unlink(wrapper_path)
            except:
                pass
            
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=execution_time,
                error=f"Docker attack execution error: {e}"
            )
        
        
class E2BAPIEnvironment(SandboxEnvironment):
    """E2B API environment implementation using SDK"""
    
    # E2BAPIEnvironment.__init__
    def __init__(self, config: Dict[str, Any]):
        super().__init__("E2B_API", config)
        self.api_key = config.get("api_key", "")
        self.sandbox = None
        # Config-driven Python packages for the E2B sandbox
        self.python_packages: List[str] = config.get("python_packages", []) or []
        
        # Set environment variable for E2B
        os.environ['E2B_API_KEY'] = self.api_key

    def connect(self) -> bool:
        """Connect to E2B API environment"""
        try:
            # Import E2B SDK
            from e2b_code_interpreter import Sandbox
            
            # Create a new sandbox with longer timeout
            self.sandbox = Sandbox.create(timeout=300)
            self.is_connected = True
            logger.info(f"Connected to E2B API with sandbox ID: {self.sandbox.sandbox_id}")
            return True
                
        except ImportError:
            logger.error("E2B SDK not installed. Run: pip install e2b-code-interpreter")
            return False
        except Exception as e:
            logger.error(f"E2B API connection error: {e}")
            return False
    
    def disconnect(self) -> bool:
        """Disconnect from E2B API"""
        if not self.sandbox:
            return True
            
        try:
            if hasattr(self.sandbox, 'close'):
                self.sandbox.close()
            elif hasattr(self.sandbox, 'kill'):
                self.sandbox.kill()
            self.sandbox = None
            self.is_connected = False
            logger.info("Disconnected from E2B API")
            return True
            
        except Exception as e:
            logger.error(f"E2B API disconnection error: {e}")
            return False
    
    # E2BAPIEnvironment.execute_script
    def execute_script(self, script_content: str, file_type: str = "python") -> TestResult:
        """Execute script in E2B API with Python wrapper for C code and on-demand package install"""
        start_time = time.time()
        
        if not self.is_connected or not self.sandbox:
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=0,
                error="Not connected to E2B API environment"
            )
        
        try:
            if file_type.lower() == "c":
                # Create Python wrapper for C code
                final_script = self._create_c_wrapper(script_content)
            else:
                # Python execution with config-driven package installation
                packages: List[str] = list(self.python_packages or [])
                
                # Detect explicit pwntools usage in script
                needs_pwntools = "from pwn import" in script_content or "import pwn" in script_content
                if needs_pwntools and "pwntools" not in packages:
                    packages.append("pwntools")
                
                packages_literal = json.dumps(packages)
                install_script = f"""
import subprocess
import sys
import importlib

_SANDBOX_PACKAGES = {packages_literal}
_SANDBOX_IMPORT_MAP = {{'pwntools': 'pwn'}}

def _ensure_sandbox_packages():
    for pkg in _SANDBOX_PACKAGES:
        import_name = _SANDBOX_IMPORT_MAP.get(pkg, pkg)
        try:
            importlib.import_module(import_name)
        except ImportError:
            try:
                base_cmd = [sys.executable, '-m', 'pip', 'install', pkg]
                candidate_cmds = [
                    base_cmd + ['--break-system-packages'],
                    base_cmd,
                ]
                last_error = ''
                for cmd in candidate_cmds:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                errors='replace',
                timeout=300,
                    )
                    if result.returncode == 0:
                        break
                    last_error = result.stderr
                else:
                    print(f"[sandbox] Failed to install {{pkg}}: {{last_error}}")
            except Exception as e:
                print(f"[sandbox] Error installing {{pkg}}: {{e}}")

_ensure_sandbox_packages()

"""
                final_script = install_script + script_content
                
            execution = self.sandbox.run_code(final_script, timeout=300)
            
            execution_time = time.time() - start_time
            
            # Check if execution was successful
            success = not execution.error
            output = ""
            error = None
            
            # Collect stdout logs
            if hasattr(execution, 'logs') and execution.logs:
                if hasattr(execution.logs, 'stdout') and execution.logs.stdout:
                    output += str(execution.logs.stdout)
                if hasattr(execution.logs, 'stderr') and execution.logs.stderr and execution.error:
                    error = str(execution.logs.stderr)
            
            # If there are results (for expressions), add them to output
            if hasattr(execution, 'results') and execution.results:
                for result in execution.results:
                    if hasattr(result, 'text') and result.text:
                        output += f"\n{str(result.text)}"
            
            return TestResult(
                environment=self.name,
                success=success,
                output=output.strip(),
                execution_time=execution_time,
                error=error
            )
                
        except Exception as e:
            execution_time = time.time() - start_time
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=execution_time,
                error=f"E2B API execution error: {e}"
            )

    def _create_c_wrapper(self, c_code: str) -> str:
        """Create Python wrapper to compile and execute C code in E2B"""
        python_wrapper = f'''
import subprocess
import tempfile
import os

# C source code to compile and execute
c_source = """{c_code}"""

try:
    # Create temporary C file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False, encoding='utf-8') as f:
        f.write(c_source)
        c_file_path = f.name
    
    # Compile the C program
    binary_path = c_file_path.replace('.c', '')
    compile_result = subprocess.run(
        ['gcc', '-o', binary_path, c_file_path, '-w'],
        capture_output=True,
        text=True,
                encoding='utf-8',
                errors='replace'
    )
    
    if compile_result.returncode != 0:
        print(f"C Compilation Error: {{compile_result.stderr}}")
    else:
        print("C compilation successful")
        
        # Execute the compiled program
        exec_result = subprocess.run(
            [binary_path],
            capture_output=True,
            text=True,
            encoding='utf-8',
                errors='replace',
                timeout=10
        )
        
        if exec_result.stdout:
            print(f"Program Output: {{exec_result.stdout}}")
        if exec_result.stderr:
            print(f"Program Error: {{exec_result.stderr}}")
        if exec_result.returncode == 0:
            print("C program executed successfully")
        else:
            print(f"C program failed with return code: {{exec_result.returncode}}")
    
except Exception as e:
    print(f"Python wrapper error: {{e}}")
finally:
    # Clean up temporary files
    try:
        if 'c_file_path' in locals():
            os.unlink(c_file_path)
        if 'binary_path' in locals() and os.path.exists(binary_path):
            os.unlink(binary_path)
    except:
        pass
'''
        return python_wrapper
    
    def check_health(self) -> bool:
        """Check E2B API health"""
        if not self.is_connected or not self.sandbox:
            return False
            
        try:
            # Try a simple command to check if sandbox is responsive
            test_execution = self.sandbox.run_code("print('health_check')", timeout=5)
            return not test_execution.error
            
        except Exception as e:
            logger.error(f"E2B API health check error: {e}")
            return False
    
    def upload_file(self, local_file_path: str, remote_file_path: str = None) -> bool:
        """Upload a file to E2B sandbox"""
        if not self.is_connected or not self.sandbox:
            logger.error("Not connected to E2B environment")
            return False
        
        if not os.path.exists(local_file_path):
            logger.error(f"Local file not found: {local_file_path}")
            return False
        
        try:
            with open(local_file_path, 'r') as f:
                content = f.read()
            
            # Use remote path or default to filename
            if remote_file_path is None:
                remote_file_path = os.path.basename(local_file_path)
            
            # Write file content to E2B sandbox using safe string escaping
            import json
            escaped_content = json.dumps(content)
            
            result = self.sandbox.run_code(f"""
import json
content = json.loads({escaped_content!r})
with open('{remote_file_path}', 'w') as f:
    f.write(content)
print(f"File uploaded: {remote_file_path}")
""", timeout=30)
            
            if not result.error:
                logger.info(f"File uploaded to E2B: {local_file_path} -> {remote_file_path}")
                return True
            else:
                logger.error(f"E2B upload error: {result.error}")
                return False
                
        except Exception as e:
            logger.error(f"E2B file upload error: {e}")
            return False
    
    def make_executable(self, file_path: str) -> bool:
        """Make a file executable in E2B sandbox"""
        if not self.is_connected or not self.sandbox:
            logger.error("Not connected to E2B environment")
            return False
        
        try:
            result = self.sandbox.run_code(f"""
import os
import stat
os.chmod('{file_path}', stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
print(f"File made executable: {file_path}")
""", timeout=10)
            
            if not result.error:
                logger.info(f"File made executable in E2B: {file_path}")
                return True
            else:
                logger.error(f"E2B make executable error: {result.error}")
                return False
                
        except Exception as e:
            logger.error(f"E2B make executable error: {e}")
            return False
    
    def _extract_output(self, result):
        """Extract output from E2B result object with various formats"""
        try:
            # Try multiple ways to get output from E2B result
            if hasattr(result, 'stdout'):
                output = result.stdout
                if hasattr(result, 'stderr') and result.stderr:
                    output += f"\nSTDERR: {result.stderr}"
                return output
            elif hasattr(result, 'logs'):
                # Newer E2B API with logs
                output = ""
                for log in result.logs:
                    if hasattr(log, 'line'):
                        output += log.line + "\n"
                    elif hasattr(log, 'content'):
                        output += log.content + "\n"
                    else:
                        output += str(log) + "\n"
                return output.strip()
            elif hasattr(result, 'output'):
                return str(result.output)
            else:
                # Fallback - convert entire result to string
                return str(result)
        except Exception:
            return str(result)
    
    def execute_against_target(self, attack_script: str, target_file: str, 
                              script_type: str = "python") -> TestResult:
        """Execute attack script against target file in E2B"""
        start_time = time.time()
        
        if not self.is_connected or not self.sandbox:
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=0,
                error="Not connected to E2B environment"
            )
        
        try:
            if script_type.lower() == "python":
                # Execute Python attack script with target file argument
                full_script = f"""
import sys
import os

# Set up target file and arguments
target_file = '{target_file}'
sys.argv = ['attack.py', target_file]

# Attack script:
{attack_script}
"""
            else:
                # For non-Python scripts, save and execute via shell
                full_script = f"""
import subprocess
import os
import sys

# Save attack script
with open('/tmp/attack_script', 'w') as f:
    f.write('''{attack_script}''')

# Make it executable
os.chmod('/tmp/attack_script', 0o755)

# Execute against target
result = subprocess.run(['/tmp/attack_script', '{target_file}'], 
                       capture_output=True, text=True, encoding='utf-8',
                errors='replace',
                timeout=120)
print(result.stdout)
if result.stderr:
    print(f"Error: {{result.stderr}}", file=sys.stderr)
"""
            
            result = self.sandbox.run_code(full_script, timeout=120)
            execution_time = time.time() - start_time
            
            return TestResult(
                environment=self.name,
                success=not result.error,
                output=self._extract_output(result),
                execution_time=execution_time,
                error=result.error if result.error else None
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=execution_time,
                error=f"E2B attack execution error: {e}"
            )


class VirtualBoxEnvironment(SandboxEnvironment):
    """VirtualBox environment implementation"""
    
    # VirtualBoxEnvironment.__init__
    def __init__(self, config: Dict[str, Any]):
        super().__init__("VirtualBox", config)
        self.vm_name = config.get("vm_name", "")
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.vboxmanage_path = config.get("vboxmanage_path", "VBoxManage")
        self.python_path = config.get("python_path", "/usr/bin/python3")
        # Config-driven setup commands and Python packages
        self.setup_commands: List[str] = config.get("setup_commands", []) or []
        self.python_packages: List[str] = config.get("python_packages", []) or []
        # Internal flag to ensure setup_commands run only once per VM session
        self._vm_setup_executed: bool = False

    def connect(self) -> bool:
        """Connect to VirtualBox VM"""
        try:
            # Check if VBoxManage is available
            result = subprocess.run(
                [self.vboxmanage_path, "--version"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=10
            )
            
            if result.returncode != 0:
                logger.error("VBoxManage not found. Please install VirtualBox")
                return False
            
            # Check if VM exists
            vm_result = subprocess.run(
                [self.vboxmanage_path, "showvminfo", self.vm_name, "--machinereadable"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=10
            )
            
            if vm_result.returncode != 0:
                logger.error(f"VM '{self.vm_name}' not found")
                return False
            
            # Check VM state and start if needed
            if "VMState=\"running\"" not in vm_result.stdout:
                logger.info(f"Starting VM: {self.vm_name}")
                start_result = subprocess.run(
                    [self.vboxmanage_path, "startvm", self.vm_name, "--type", "headless"],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                errors='replace',
                timeout=120
                )
                
                if start_result.returncode != 0:
                    logger.error(f"Failed to start VM: {start_result.stderr}")
                    return False
                
                # Wait for VM to boot
                logger.info("Waiting for VM to boot...")
                time.sleep(90)
            
            self.is_connected = True
            logger.info(f"Connected to VirtualBox VM: {self.vm_name}")
            return True
            
        except Exception as e:
            logger.error(f"VirtualBox connection error: {e}")
            return False
    
    def disconnect(self) -> bool:
        """Disconnect from VirtualBox VM"""
        if not self.is_connected:
            return True
            
        try:
            logger.info(f"Initiating graceful shutdown of VM: {self.vm_name}")
            
            # Try graceful shutdown first
            result = subprocess.run(
                [self.vboxmanage_path, "controlvm", self.vm_name, "acpipowerbutton"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30
            )
            
            # Wait for graceful shutdown (regardless of command result)
            max_wait_time = 15  # seconds
            wait_interval = 2   # seconds
            waited = 0
            
            while waited < max_wait_time:
                time.sleep(wait_interval)
                waited += wait_interval
                
                # Check if VM is still running
                check_result = subprocess.run(
                    [self.vboxmanage_path, "showvminfo", self.vm_name, "--machinereadable"],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                errors='replace',
                timeout=10
                )
                
                if check_result.returncode == 0:
                    if "VMState=\"running\"" not in check_result.stdout:
                        logger.info(f"VM {self.vm_name} shut down gracefully")
                        self.is_connected = False
                        return True
                else:
                    # VM might already be stopped
                    logger.info(f"VM {self.vm_name} appears to be stopped")
                    self.is_connected = False
                    return True
            
            # If we get here, graceful shutdown failed - force poweroff
            logger.warning(f"Graceful shutdown timed out, forcing poweroff of VM: {self.vm_name}")
            poweroff_result = subprocess.run(
                [self.vboxmanage_path, "controlvm", self.vm_name, "poweroff"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=15
            )
            
            if poweroff_result.returncode == 0:
                logger.info(f"Successfully forced shutdown of VM: {self.vm_name}")
            else:
                logger.warning(f"Poweroff command failed, but proceeding anyway: {poweroff_result.stderr}")
            
            self.is_connected = False
            logger.info(f"Disconnected from VirtualBox VM: {self.vm_name}")
            return True
            
        except Exception as e:
            logger.error(f"VirtualBox disconnection error: {e}")
            # Even if there's an error, mark as disconnected to prevent hanging
            self.is_connected = False
            return False
    
    # VirtualBoxEnvironment.execute_script
    def execute_script(self, script_content: str, file_type: str = "python") -> TestResult:
        """Execute script in VirtualBox VM with C and Python support, including setup_commands and python_packages"""
        start_time = time.time()
        
        if not self.is_connected:
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=0,
                error="Not connected to VirtualBox environment"
            )
        
        try:
            # Run one-time VM setup commands if configured
            if self.setup_commands and not getattr(self, "_vm_setup_executed", False):
                for cmd in self.setup_commands:
                    try:
                        setup_cmd = [
                            self.vboxmanage_path, "guestcontrol", self.vm_name,
                            "run", "--username", self.username, "--password", self.password,
                            "--exe", "/bin/bash", "--", "/bin/bash", "-lc", cmd,
                        ]
                        subprocess.run(
                            setup_cmd,
                            capture_output=True,
                            text=True,
                            encoding='utf-8',
                errors='replace',
                timeout=300,
                        )
                    except Exception as setup_err:
                        logger.warning(f"VirtualBox setup command failed (ignored): {setup_err}")
                self._vm_setup_executed = True
            
            if file_type.lower() == "c":
                return self._execute_c_script_vm(script_content, start_time)
            
            # Python execution with config-driven package installation
            packages: List[str] = list(self.python_packages or [])
            
            # Detect explicit pwntools usage in script
            needs_pwntools = "from pwn import" in script_content or "import pwn" in script_content
            if needs_pwntools and "pwntools" not in packages:
                packages.append("pwntools")
            
            packages_literal = json.dumps(packages)
            install_script = f"""
import subprocess
import sys
import importlib
import os

_SANDBOX_PACKAGES = {packages_literal}
_SANDBOX_IMPORT_MAP = {{'pwntools': 'pwn'}}
_VENV_PATH = '/home/sandbox/env_sandbox'

def _ensure_sandbox_packages():
    # Use venv python if available
    venv_python = os.path.join(_VENV_PATH, 'bin', 'python')
    venv_pip = os.path.join(_VENV_PATH, 'bin', 'pip')
    
    # Check if venv exists and use it
    if os.path.exists(venv_python):
        print(f"[sandbox] Using virtual environment: {{_VENV_PATH}}")
        sys.executable = venv_python
    else:
        print(f"[sandbox] Warning: venv not found at {{_VENV_PATH}}, using system Python")
    
    for pkg in _SANDBOX_PACKAGES:
        import_name = _SANDBOX_IMPORT_MAP.get(pkg, pkg)
        try:
            importlib.import_module(import_name)
            print(f"[sandbox] Package {{pkg}} already installed")
        except ImportError:
            print(f"[sandbox] Installing {{pkg}}...")
            try:
                # Install using venv pip if available
                if os.path.exists(venv_pip):
                    install_cmd = [venv_pip, 'install', pkg]
                else:
                    install_cmd = [sys.executable, '-m', 'pip', 'install', pkg]
                
                print(f"[sandbox] Running: {{' '.join(install_cmd)}}")
                result = subprocess.run(
                    install_cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode == 0:
                    print(f"[sandbox] Successfully installed {{pkg}}")
                else:
                    print(f"[sandbox] Failed to install {{pkg}}: {{result.stderr}}")
            except Exception as e:
                print(f"[sandbox] Error installing {{pkg}}: {{e}}")

_ensure_sandbox_packages()

"""
            combined_script = install_script + script_content
            
            # Reuse existing VM Python execution helper with the combined script
            return self._execute_python_script_vm(combined_script, start_time)
                
        except Exception as e:
            execution_time = time.time() - start_time
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=execution_time,
                error=f"VirtualBox execution error: {e}"
            )

    def _execute_python_script_vm(self, script_content: str, start_time: float) -> TestResult:
        """Execute Python script in VirtualBox VM"""
        # Note: script_content already includes installer prelude from execute_script()
        # which properly handles --break-system-packages flag
        
        # Create a temporary script file path in the VM
        script_file = "/tmp/sandbox_script.py"
        
        # Create a temporary file on the host system first
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(script_content)
            temp_host_file = temp_file.name
        
        try:
            # Copy script from host to VM using guestcontrol
            copy_cmd = [
                self.vboxmanage_path, "guestcontrol", self.vm_name,
                "copyto", "--username", self.username, "--password", self.password,
                temp_host_file, script_file
            ]
            
            copy_result = subprocess.run(
                copy_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=500
            )
        finally:
            # Clean up temporary host file
            try:
                os.unlink(temp_host_file)
            except Exception:
                pass
        
        if copy_result.returncode != 0:
            execution_time = time.time() - start_time
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=execution_time,
                error=f"Failed to copy script to VM: {copy_result.stderr}"
            )
        
        # Execute script in VM using venv Python
        venv_python = "/home/sandbox/env_sandbox/bin/python"
        exec_cmd = [
            self.vboxmanage_path, "guestcontrol", self.vm_name,
            "run", "--username", self.username, "--password", self.password,
            "--exe", venv_python, "--", script_file
        ]
        
        exec_result = subprocess.run(
            exec_cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
                errors='replace',
                timeout=500
        )
        
        execution_time = time.time() - start_time
        
        return TestResult(
            environment=self.name,
            success=exec_result.returncode == 0,
            output=exec_result.stdout,
            execution_time=execution_time,
            error=exec_result.stderr if exec_result.returncode != 0 else None
        )
    
    def _execute_c_script_vm(self, script_content: str, start_time: float) -> TestResult:
        """Execute C script in VirtualBox VM with compilation"""
        # Create temporary file paths in the VM
        c_file = "/tmp/sandbox_script.c"
        binary_file = "/tmp/sandbox_program"
        
        # Create a temporary file on the host system first
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(script_content)
            temp_host_file = temp_file.name
        
        try:
            # Copy C source from host to VM
            copy_cmd = [
                self.vboxmanage_path, "guestcontrol", self.vm_name,
                "copyto", "--username", self.username, "--password", self.password,
                temp_host_file, c_file
            ]
            
            copy_result = subprocess.run(
                copy_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=500
            )
        finally:
            # Clean up temporary host file
            try:
                os.unlink(temp_host_file)
            except Exception:
                pass
        
        if copy_result.returncode != 0:
            execution_time = time.time() - start_time
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=execution_time,
                error=f"Failed to copy C file to VM: {copy_result.stderr}"
            )
        
        # Compile C program in VM
        compile_cmd = [
            self.vboxmanage_path, "guestcontrol", self.vm_name,
            "run", "--username", self.username, "--password", self.password,
            "--exe", "/usr/bin/gcc", "--", "-o", binary_file, c_file, "-w"
        ]
        
        compile_result = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
                errors='replace',
                timeout=500
        )
        
        if compile_result.returncode != 0:
            execution_time = time.time() - start_time
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=execution_time,
                error=f"C compilation failed: {compile_result.stderr}"
            )
        
        # Execute compiled program in VM
        exec_cmd = [
            self.vboxmanage_path, "guestcontrol", self.vm_name,
            "run", "--username", self.username, "--password", self.password,
            "--exe", binary_file
        ]
        
        exec_result = subprocess.run(
            exec_cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
                errors='replace',
                timeout=500
        )
        
        execution_time = time.time() - start_time
        
        return TestResult(
            environment=self.name,
            success=exec_result.returncode == 0,
            output=exec_result.stdout,
            execution_time=execution_time,
            error=exec_result.stderr if exec_result.returncode != 0 else None
        )
    
    def check_health(self) -> bool:
        """Check VirtualBox VM health"""
        if not self.is_connected:
            return False
            
        try:
            # Check VM state
            result = subprocess.run(
                [self.vboxmanage_path, "showvminfo", self.vm_name, "--machinereadable"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=10
            )
            
            if result.returncode == 0 and "VMState=\"running\"" in result.stdout:
                # Try a simple command to verify guest functionality
                test_cmd = [
                    self.vboxmanage_path, "guestcontrol", self.vm_name,
                    "run", "--username", self.username, "--password", self.password,
                    "--exe", "/bin/echo", "--", "echo", "OK"
                ]
                
                test_result = subprocess.run(
                    test_cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                errors='replace',
                timeout=500
                )
                
                return test_result.returncode == 0
            
            return False
            
        except Exception as e:
            logger.error(f"VirtualBox health check error: {e}")
            return False
    
    def upload_file(self, local_file_path: str, remote_file_path: str = None) -> bool:
        """Upload a file to VirtualBox VM"""
        if not self.is_connected:
            logger.error("Not connected to VirtualBox environment")
            return False
        
        if not os.path.exists(local_file_path):
            logger.error(f"Local file not found: {local_file_path}")
            return False
        
        # Use remote path or default to /tmp/filename
        if remote_file_path is None:
            filename = os.path.basename(local_file_path)
            remote_file_path = f"/tmp/{filename}"
        
        try:
            # Copy file to VM using guestcontrol
            copy_cmd = [
                self.vboxmanage_path, "guestcontrol", self.vm_name,
                "copyto", "--username", self.username, "--password", self.password,
                local_file_path, remote_file_path
            ]
            
            result = subprocess.run(
                copy_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=500
            )
            
            if result.returncode == 0:
                logger.info(f"File uploaded to VirtualBox: {local_file_path} -> {remote_file_path}")
                return True
            else:
                logger.error(f"VirtualBox upload error: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"VirtualBox file upload error: {e}")
            return False
    
    def make_executable(self, file_path: str) -> bool:
        """Make a file executable in VirtualBox VM"""
        if not self.is_connected:
            logger.error("Not connected to VirtualBox environment")
            return False
        
        try:
            chmod_cmd = [
                self.vboxmanage_path, "guestcontrol", self.vm_name,
                "run", "--username", self.username, "--password", self.password,
                "--exe", "/bin/chmod", "--", "+x", file_path
            ]
            
            result = subprocess.run(
                chmod_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=500
            )
            
            if result.returncode == 0:
                logger.info(f"File made executable in VirtualBox: {file_path}")
                return True
            else:
                logger.error(f"VirtualBox make executable error: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"VirtualBox make executable error: {e}")
            return False
    
    def execute_against_target(self, attack_script: str, target_file: str, 
                              script_type: str = "python") -> TestResult:
        """Execute attack script against target file in VirtualBox VM"""
        start_time = time.time()
        
        if not self.is_connected:
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=0,
                error="Not connected to VirtualBox environment"
            )
        
        try:
            # Create temporary script file on host
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{script_type}', 
                                           delete=False, encoding='utf-8') as f:
                f.write(attack_script)
                temp_script_path = f.name
            
            script_file_vm = f"/tmp/attack_script.{script_type}"
            
            # Copy attack script to VM
            copy_cmd = [
                self.vboxmanage_path, "guestcontrol", self.vm_name,
                "copyto", "--username", self.username, "--password", self.password,
                temp_script_path, script_file_vm
            ]
            
            copy_result = subprocess.run(
                copy_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=500
            )
            
            # Clean up temp file
            try:
                os.unlink(temp_script_path)
            except:
                pass
            
            if copy_result.returncode != 0:
                execution_time = time.time() - start_time
                return TestResult(
                    environment=self.name,
                    success=False,
                    output="",
                    execution_time=execution_time,
                    error=f"Failed to copy attack script to VM: {copy_result.stderr}"
                )
            
            # Execute attack script based on type
            if script_type.lower() == "python":
                exec_cmd = [
                    self.vboxmanage_path, "guestcontrol", self.vm_name,
                    "run", "--username", self.username, "--password", self.password,
                    "--exe", "/usr/bin/python3", "--", script_file_vm, target_file
                ]
            elif script_type.lower() == "c":
                # Compile and execute C script
                binary_file = "/tmp/attack_binary"
                
                # First compile
                compile_cmd = [
                    self.vboxmanage_path, "guestcontrol", self.vm_name,
                    "run", "--username", self.username, "--password", self.password,
                    "--exe", "/usr/bin/gcc", "--", script_file_vm, "-o", binary_file, "-w"
                ]
                
                compile_result = subprocess.run(
                    compile_cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                errors='replace',
                timeout=500
                )
                
                if compile_result.returncode != 0:
                    execution_time = time.time() - start_time
                    return TestResult(
                        environment=self.name,
                        success=False,
                        output="",
                        execution_time=execution_time,
                        error=f"C compilation failed: {compile_result.stderr}"
                    )
                
                # Then execute
                exec_cmd = [
                    self.vboxmanage_path, "guestcontrol", self.vm_name,
                    "run", "--username", self.username, "--password", self.password,
                    "--exe", binary_file, "--", target_file
                ]
            else:
                # For shell scripts
                exec_cmd = [
                    self.vboxmanage_path, "guestcontrol", self.vm_name,
                    "run", "--username", self.username, "--password", self.password,
                    "--exe", "/bin/sh", "--", script_file_vm, target_file
                ]
            
            # Execute the attack
            exec_result = subprocess.run(
                exec_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=500  # Longer timeout for complex attacks
            )
            
            execution_time = time.time() - start_time
            
            return TestResult(
                environment=self.name,
                success=exec_result.returncode == 0,
                output=exec_result.stdout,
                execution_time=execution_time,
                error=exec_result.stderr if exec_result.returncode != 0 else None
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=execution_time,
                error=f"VirtualBox attack execution error: {e}"
            )


class SandboxManager:
    """Main sandbox manager class"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.environments = {}
        self.test_results = []
        self.config = {}
        
        if config_file:
            self.load_config(config_file)
    
    def load_config(self, config_file: str) -> bool:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
            
            # Initialize environments from config
            env_configs = self.config.get("environments", {})
            
            for env_type, env_config in env_configs.items():
                if env_config.get("enabled", False):
                    self.add_environment(env_type, env_config)
            
            logger.info(f"Loaded configuration from {config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return False
    
    def add_environment(self, env_type: str, config: Dict[str, Any]) -> bool:
        """Add a new environment to the sandbox"""
        try:
            if env_type.lower() == "docker":
                env = DockerContainerEnvironment(config)
            elif env_type.lower() == "e2b":
                env = E2BAPIEnvironment(config)
            elif env_type.lower() == "virtualbox":
                env = VirtualBoxEnvironment(config)
            else:
                logger.error(f"Unknown environment type: {env_type}")
                return False
            
            self.environments[env.name] = env
            logger.info(f"Added {env_type} environment: {env.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add environment {env_type}: {e}")
            return False
    
    def connect_all(self) -> bool:
        """Connect to all environments with optimal ordering"""
        success = True
        
        # Connect in optimal order: VirtualBox first (slow boot), then fast environments
        connection_order = []
        
        # VirtualBox first (takes longest to boot)
        for name, env in self.environments.items():
            if "VirtualBox" in name:
                connection_order.append((name, env))
        
        # Then other environments (Docker, E2B)
        for name, env in self.environments.items():
            if "VirtualBox" not in name:
                connection_order.append((name, env))
        
        for name, env in connection_order:
            logger.info(f"Connecting to {name}...")
            if not env.connect():
                logger.error(f"Failed to connect to {name}")
                success = False
            else:
                logger.info(f"Successfully connected to {name}")
        return success
    
    def disconnect_all(self) -> bool:
        """Disconnect from all environments"""
        success = True
        for name, env in self.environments.items():
            if not env.disconnect():
                logger.error(f"Failed to disconnect from {name}")
                success = False
        return success
    
    def run_test_on_all(self, script_content: str, file_type: str = "python") -> Dict[str, TestResult]:
        """Run test script on all connected environments with language detection"""
        results = {}
        
        # Auto-detect file type if not specified
        if file_type == "python" and self._is_c_code(script_content):
            file_type = "c"
            logger.info(f"Auto-detected file type: {file_type}")
        
        for name, env in self.environments.items():
            if not env.is_connected:
                logger.warning(f"Environment {name} is not connected, skipping")
                continue
            
            logger.info(f"Running {file_type} script on {name}")
            result = env.execute_script(script_content, file_type)
            results[name] = result
            self.test_results.append(result)
            
            status_msg = f"{name} - Success: {result.success}, Time: {result.execution_time:.2f}s"
            logger.info(status_msg)
            if result.error:
                logger.error(f"{name} - Error: {result.error}")
        
        return results
    
    def _is_c_code(self, script_content: str) -> bool:
        """Enhanced heuristic to detect if script content is C code vs Python"""
        # Strong Python indicators that override C detection
        python_indicators = [
            '#!/usr/bin/env python',
            'import ',
            'from ',
            'def ',
            'class ',
            '"""',
            "'''",
            'if __name__ == "__main__":'
        ]
        
        # C-specific indicators
        c_indicators = [
            '#include <',
            'int main(',
            'void main(',
            'printf(',
            'scanf(',
            'malloc(',
            'free(',
            'strcpy('
        ]
        
        content_lower = script_content.lower()
        
        # Check for Python indicators first - if found, it's definitely Python
        if any(indicator.lower() in content_lower for indicator in python_indicators):
            logger.debug("Detected Python script based on Python-specific indicators")
            return False
            
        # Only check for C indicators if no Python indicators found
        is_c = any(indicator.lower() in content_lower for indicator in c_indicators)
        if is_c:
            logger.debug("Detected C code based on C-specific indicators")
        else:
            logger.debug("No clear language indicators found, defaulting to Python")
            
        return is_c
    
    def execute_exploit(self, exploit_script: str, 
                       vulnerability_data: dict = None) -> dict:
        """
        Execute exploit with detailed logging and analysis for LangGraph.
        This is the main method LangGraph should call.
        """
        # Create logs directory
        os.makedirs('logs', exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Connect to environments if not already connected
        if not any(env.is_connected for env in self.environments.values()):
            logger.info("Connecting to sandbox environments...")
            if not self.connect_all():
                return {
                    'status': 'error',
                    'message': 'Failed to connect to sandbox environments',
                    'timestamp': timestamp
                }
        
        logger.info("=== EXECUTING EXPLOIT IN SANDBOX ===")
        
        # Auto-detect file type and execute exploit on all environments
        file_type = "c" if self._is_c_code(exploit_script) else "python"
        logger.info(f"Detected script type: {file_type}")
        results = self.run_test_on_all(exploit_script, file_type)
        
        # Analyze results with intelligence
        detailed_results = {}
        exploitation_successful = False
        
        for env_name, result in results.items():
            # Perform intelligent analysis
            vulnerability_type = self._extract_vulnerability_type(vulnerability_data)
            
            analysis = analyze_exploitation_results(
                output=result.output,
                error=result.error,
                vulnerability_type=vulnerability_type
            )
            
            # Check if any environment had successful exploitation
            if analysis["exploitation_successful"]:
                exploitation_successful = True
            
            # Log analysis results
            if analysis["exploitation_successful"]:
                logger.info(f"{env_name}: EXPLOITATION SUCCESSFUL!")
                if analysis["success_indicators"]:
                    logger.info(f"Success indicators: {analysis['success_indicators']}")
            else:
                logger.info(f"{env_name}: Exploitation failed or unclear")
                if analysis["failure_indicators"]:
                    logger.info(f"Failure reasons: {analysis['failure_indicators']}")
                if analysis["suggestions"]:
                    logger.info(f"Suggestions: {analysis['suggestions'][:2]}")
            
            # Store detailed result
            detailed_results[env_name] = {
                "success": result.success,
                "execution_time": result.execution_time,
                "output": result.output,
                "error": result.error,
                "exploitation_analysis": analysis
            }
        
        # Prepare complete log data
        log_data = {
            "timestamp": timestamp,
            "vulnerability": vulnerability_data or {},
            "exploit_script": exploit_script,
            "results": detailed_results,
            "overall_exploitation_successful": exploitation_successful,
            "environments_tested": list(results.keys()),
            "summary": self.get_test_summary()
        }
        
        # Save to logs file
        log_filename = f"logs/exploit_{timestamp}.json"
        try:
            with open(log_filename, 'w') as f:
                json.dump(log_data, f, indent=2)
            logger.info(f"Results saved to: {log_filename}")
        except Exception as e:
            logger.error(f"Failed to save log file: {e}")
            log_filename = None
        
        # Return structured data for LangGraph
                # Return per-environment results as expected by callers
        return detailed_results

    
    def _extract_key_suggestions(self, detailed_results: dict) -> list:
        """Extract key learning suggestions from all environment results"""
        all_suggestions = []
        for env_data in detailed_results.values():
            analysis = env_data.get('exploitation_analysis', {})
            suggestions = analysis.get('suggestions', [])
            all_suggestions.extend(suggestions)
        
        # Return unique suggestions, limit to top 5
        unique_suggestions = list(set(all_suggestions))
        return unique_suggestions[:5]
    
    def run_test_on_environment(self, env_name: str, script_content: str, file_type: str = "python") -> Optional[TestResult]:
        """Run test script on a specific environment with language support"""
        if env_name not in self.environments:
            logger.error(f"Environment {env_name} not found")
            return None
        
        env = self.environments[env_name]
        if not env.is_connected:
            logger.error(f"Environment {env_name} is not connected")
            return None
        
        # Auto-detect file type if not specified
        if file_type == "python" and self._is_c_code(script_content):
            file_type = "c"
        
        logger.info(f"Running {file_type} test on {env_name}")
        result = env.execute_script(script_content, file_type)
        self.test_results.append(result)
        
        status_msg = f"{env_name} - Success: {result.success}, Time: {result.execution_time:.2f}s"
        logger.info(status_msg)
        if result.error:
            logger.error(f"{env_name} - Error: {result.error}")
        
        return result
    
    def check_all_health(self) -> Dict[str, bool]:
        """Check health of all environments"""
        health_status = {}
        for name, env in self.environments.items():
            health_status[name] = env.check_health()
            status = "healthy" if health_status[name] else "unhealthy"
            logger.info(f"{name} is {status}")
        return health_status
    
    def get_test_summary(self) -> Dict[str, Any]:
        """Get summary of all test results"""
        if not self.test_results:
            return {"message": "No tests have been run"}
        
        total_tests = len(self.test_results)
        successful_tests = sum(1 for r in self.test_results if r.success)
        failed_tests = sum(1 for r in self.test_results if not r.success)
        avg_time = sum(r.execution_time for r in self.test_results) / total_tests
        
        summary = {
            "total_tests": total_tests,
            "successful_tests": successful_tests,
            "failed_tests": failed_tests,
            "success_rate": f"{(successful_tests/total_tests)*100:.1f}%",
            "average_execution_time": f"{avg_time:.4f}s",
            "environments_tested": list(set(r.environment for r in self.test_results))
        }
        
        return summary
    
    def get_predefined_scripts(self) -> Dict[str, str]:
        """Get predefined test scripts from config"""
        return self.config.get("test_scripts", {})
    
    def list_environments(self) -> List[str]:
        """Get list of available environments"""
        return list(self.environments.keys())
    
    def upload_vulnerable_file(self, local_file_path: str, remote_file_path: str = None) -> Dict[str, bool]:
        """Upload vulnerable file to all connected environments"""
        results = {}
        
        if not os.path.exists(local_file_path):
            logger.error(f"Local file not found: {local_file_path}")
            return {env_name: False for env_name in self.environments.keys()}
        
        for name, env in self.environments.items():
            if not env.is_connected:
                logger.warning(f"Environment {name} is not connected, skipping upload")
                results[name] = False
                continue
                
            logger.info(f"Uploading file to {name}...")
            success = env.upload_file(local_file_path, remote_file_path)
            results[name] = success
            
            if success:
                logger.info(f"Successfully uploaded to {name}")
                # Make file executable if it's a binary or script
                remote_ext = os.path.splitext(remote_file_path or "")[1].lower()
                file_ext = os.path.splitext(local_file_path)[1].lower()
                if remote_ext in ['.c', '.cpp', '.sh', '.py', ''] or file_ext in ['.c', '.cpp', '.sh', '.py', ''] or not file_ext:
                    env.make_executable(remote_file_path or f"/tmp/{os.path.basename(local_file_path)}")
            else:
                logger.error(f"Failed to upload to {name}")
        
        return results

    @staticmethod
    def _extract_vulnerability_type(vulnerability_data: dict = None) -> Optional[str]:
        """Normalize vulnerability type across both single-item and list-based payloads."""
        if not vulnerability_data:
            return None
        if isinstance(vulnerability_data, dict):
            if vulnerability_data.get("Type"):
                return str(vulnerability_data.get("Type", "")).lower()
            vulns = vulnerability_data.get("vulnerabilities")
            if isinstance(vulns, list) and vulns and isinstance(vulns[0], dict):
                vuln_type = vulns[0].get("Type")
                if vuln_type:
                    return str(vuln_type).lower()
        return None
    
    def generate_and_execute_attack(self, vulnerable_file_path: str, 
                                   attack_script: str, 
                                   script_type: str = "python",
                                   vulnerability_data: dict = None) -> dict:
        """
        Generate attack script and execute against uploaded vulnerable file.
        This is the main method for Agent to use.
        """
        # Create logs directory
        os.makedirs('logs', exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Connect to environments if not already connected
        if not any(env.is_connected for env in self.environments.values()):
            logger.info("Connecting to sandbox environments...")
            if not self.connect_all():
                return {
                    'status': 'error',
                    'message': 'Failed to connect to sandbox environments',
                    'timestamp': timestamp
                }
        
        logger.info("=== EXECUTING ATTACK AGAINST TARGET FILE ===")
        logger.info(f"Target file: {vulnerable_file_path}")
        logger.info(f"Attack script type: {script_type}")
        
        # Execute attack on all environments
        results = {}
        exploitation_successful = False
        
        for env_name, env in self.environments.items():
            if not env.is_connected:
                logger.warning(f"Environment {env_name} is not connected, skipping")
                continue
            
            logger.info(f"Executing attack on {env_name}")
            result = env.execute_against_target(attack_script, vulnerable_file_path, script_type)
            results[env_name] = result
            self.test_results.append(result)
            
            # Analyze results with intelligence
            vulnerability_type = self._extract_vulnerability_type(vulnerability_data)
            
            analysis = analyze_exploitation_results(
                output=result.output,
                error=result.error,
                vulnerability_type=vulnerability_type
            )
            
            # Check if any environment had successful exploitation
            if analysis["exploitation_successful"]:
                exploitation_successful = True
            
            # Log analysis results
            if analysis["exploitation_successful"]:
                logger.info(f"{env_name}: ATTACK SUCCESSFUL!")
                if analysis["success_indicators"]:
                    logger.info(f"Success indicators: {analysis['success_indicators']}")
            else:
                logger.warning(f"{env_name}: Attack failed or unclear result")
                if analysis.get("failure_indicators"):
                    logger.info(f"Failure reasons: {analysis['failure_indicators']}")
                if analysis.get("learning_categories"):
                    logger.info(f"Learning feedback: {analysis['learning_categories']}")
        
        # Prepare comprehensive result
        final_result = {
            'status': 'success' if exploitation_successful else 'failed',
            'exploitation_successful': exploitation_successful,
            'timestamp': timestamp,
            'target_file': vulnerable_file_path,
            'attack_type': script_type,
            'environment_results': {},
            'learning_insights': [],
            'recommendations': []
        }
        
        # Process each environment result
        for env_name, result in results.items():
            vulnerability_type = self._extract_vulnerability_type(vulnerability_data)
                
            analysis = analyze_exploitation_results(
                output=result.output,
                error=result.error,
                vulnerability_type=vulnerability_type
            )
            
            final_result['environment_results'][env_name] = {
                'success': result.success,
                'output': result.output,
                'error': result.error,
                'execution_time': result.execution_time,
                'exploitation_successful': analysis["exploitation_successful"],
                'analysis': analysis
            }
            
            # Collect learning insights
            if analysis.get("learning_categories"):
                final_result['learning_insights'].extend(analysis["learning_categories"])
            
            if analysis.get("suggestions"):
                final_result['recommendations'].extend(analysis["suggestions"])
        
        # Log to file for LangGraph learning
        log_file = f'logs/attack_{timestamp}.json'
        try:
            with open(log_file, 'w') as f:
                json.dump(final_result, f, indent=2)
            logger.info(f"Attack results logged to: {log_file}")
        except Exception as e:
            logger.error(f"Failed to save attack log: {e}")
        
        # Print summary
        if exploitation_successful:
            logger.info("=== ATTACK SUMMARY: SUCCESS ===")
            successful_envs = [name for name, data in final_result['environment_results'].items() 
                             if data['exploitation_successful']]
            logger.info(f"Successful environments: {', '.join(successful_envs)}")
        else:
            logger.info("=== ATTACK SUMMARY: FAILED ===")
            logger.info("No environment showed clear signs of successful exploitation")
            if final_result['learning_insights']:
                logger.info("Learning insights for improvement:")
                for insight in set(final_result['learning_insights']):
                    logger.info(f"  - {insight}")
        
        return final_result


def interactive_mode(sandbox: SandboxManager):
    """Interactive mode for sandbox testing"""
    print("\n=== Interactive Sandbox Mode ===")
    print("Available commands:")
    print("1. list - List available environments")
    print("2. connect - Connect to all environments")
    print("3. health - Check health of all environments")
    print("4. test <script_name> - Run predefined test script")
    print("5. custom - Run custom script")
    print("6. summary - Show test summary")
    print("7. disconnect - Disconnect all environments")
    print("8. quit - Exit interactive mode")
    
    while True:
        try:
            command = input("\n> ").strip().lower()
            
            if command == "quit" or command == "exit":
                break
            elif command == "list":
                envs = sandbox.list_environments()
                print(f"Available environments: {', '.join(envs)}")
            elif command == "connect":
                if sandbox.connect_all():
                    print("Connected to all available environments")
                else:
                    print("Failed to connect to some environments")
            elif command == "health":
                health = sandbox.check_all_health()
                for env, status in health.items():
                    print(f"{env}: {'✓ Healthy' if status else '✗ Unhealthy'}")
            elif command.startswith("test "):
                script_name = command.split(" ", 1)[1]
                scripts = sandbox.get_predefined_scripts()
                if script_name in scripts:
                    results = sandbox.run_test_on_all(scripts[script_name])
                    print(f"Test '{script_name}' completed on {len(results)} environments")
                else:
                    available = ', '.join(scripts.keys())
                    print(f"Script '{script_name}' not found. Available: {available}")
            elif command == "custom":
                print("Enter your Python script (end with 'END' on a new line):")
                script_lines = []
                while True:
                    line = input()
                    if line.strip() == "END":
                        break
                    script_lines.append(line)
                
                if script_lines:
                    script = '\n'.join(script_lines)
                    results = sandbox.run_test_on_all(script)
                    print(f"Custom script completed on {len(results)} environments")
            elif command == "summary":
                summary = sandbox.get_test_summary()
                print(json.dumps(summary, indent=2))
            elif command == "disconnect":
                sandbox.disconnect_all()
                print("Disconnected from all environments")
            else:
                print("Unknown command. Type 'quit' to exit.")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Multi-Environment Sandbox System")
    parser.add_argument("--config", "-c", help="Configuration file path", 
                       default="sandbox_config.json")
    parser.add_argument("--interactive", "-i", action="store_true", 
                       help="Run in interactive mode")
    parser.add_argument("--test", "-t", help="Run specific test script")
    
    args = parser.parse_args()
    
    # Initialize sandbox manager
    sandbox = SandboxManager(args.config)
    
    # If no environments from config, show error
    if not sandbox.environments:
        logger.error("No environments configured. Please check your configuration file.")
        return
    
    if args.interactive:
        interactive_mode(sandbox)
    else:
        # Connect to all environments
        if sandbox.connect_all():
            logger.info("All environments connected successfully")
            
            # Run test
            if args.test:
                scripts = sandbox.get_predefined_scripts()
                if args.test in scripts:
                    sandbox.run_test_on_all(scripts[args.test])
                else:
                    logger.error(f"Test script '{args.test}' not found")
            else:
                # Run default basic test
                basic_script = """
import sys
print(f"Python version: {sys.version}")
print("Hello from sandbox test!")
result = 2 + 2
print(f"2 + 2 = {result}")

# Test some basic operations
numbers = [1, 2, 3, 4, 5]
squared = [x**2 for x in numbers]
print(f"Squared numbers: {squared}")
"""
                sandbox.run_test_on_all(basic_script)
            
            # Print summary
            summary = sandbox.get_test_summary()
            print(f"\nTest Summary:")
            print(json.dumps(summary, indent=2))
            
            # Disconnect from all environments
            sandbox.disconnect_all()
        else:
            logger.error("Failed to connect to one or more environments")


if __name__ == "__main__":
    main()
