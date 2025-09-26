"""
Updated Sandbox System with Correct 3 Environments:
1. Docker Container
2. E2B API
3. VirtualBox
"""

import json
import logging
from abc import ABC, abstractmethod
import subprocess
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import argparse
import tempfile
import os
from datetime import datetime

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
            "segmentation fault with control"
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
            "system compromised", "access gained", "privilege escalation"
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
    error_lower = error.lower() if error else ""
    combined_text = f"{output_lower} {error_lower}"
    
    # Check for success
    success_found = []
    patterns_to_check = (success_patterns.get(vulnerability_type, []) + 
                        success_patterns["general"])
    
    for pattern in patterns_to_check:
        if pattern in combined_text:
            success_found.append(pattern)
    
    # Check for failure reasons
    failures_found = []
    for pattern in failure_patterns:
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
    exploitation_successful = (len(success_found) > 0 and 
                             len(failures_found) == 0)
    
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
    def check_health(self) -> bool:
        """Check if environment is healthy and ready"""
        pass


class DockerContainerEnvironment(SandboxEnvironment):
    """Docker Container environment implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("Docker_Container", config)
        self.image = config.get("image", "python:3.11-slim")
        self.container_name = config.get("container_name", "sandbox-test")
        self.docker_command = config.get("docker_command", "docker")
        self.container_id = None
    
    def connect(self) -> bool:
        """Connect to Docker environment"""
        try:
            # Check if Docker is available
            result = subprocess.run(
                [self.docker_command, "--version"],
                capture_output=True,
                text=True,
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
                timeout=60
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
    
    def execute_script(self, script_content: str) -> TestResult:
        """Execute script in Docker container"""
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
            # Create a temporary file for the script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(script_content)
                temp_script_path = f.name
            
            try:
                # Run the script in a Docker container
                docker_cmd = [
                    self.docker_command, "run", "--rm",
                    "-v", f"{temp_script_path}:/script.py",
                    self.image,
                    "python", "/script.py"
                ]
                
                result = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
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
                
        except Exception as e:
            execution_time = time.time() - start_time
            return TestResult(
                environment=self.name,
                success=False,
                output="",
                execution_time=execution_time,
                error=f"Docker execution error: {e}"
            )
    
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


class E2BAPIEnvironment(SandboxEnvironment):
    """E2B API environment implementation using SDK"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("E2B_API", config)
        self.api_key = config.get("api_key", "")
        self.sandbox = None
        
        # Set environment variable for E2B
        os.environ['E2B_API_KEY'] = self.api_key
    
    def connect(self) -> bool:
        """Connect to E2B API environment"""
        try:
            # Import E2B SDK
            from e2b_code_interpreter import Sandbox
            
            # Create a new sandbox
            self.sandbox = Sandbox.create(timeout=60)
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
    
    def execute_script(self, script_content: str) -> TestResult:
        """Execute script in E2B API"""
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
            # Execute the script using E2B SDK
            execution = self.sandbox.run_code(script_content, timeout=30)
            
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


class VirtualBoxEnvironment(SandboxEnvironment):
    """VirtualBox environment implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("VirtualBox", config)
        self.vm_name = config.get("vm_name", "")
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.vboxmanage_path = config.get("vboxmanage_path", "VBoxManage")
        self.python_path = config.get("python_path", "/usr/bin/python3")
    
    def connect(self) -> bool:
        """Connect to VirtualBox VM"""
        try:
            # Check if VBoxManage is available
            result = subprocess.run(
                [self.vboxmanage_path, "--version"],
                capture_output=True,
                text=True,
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
                    timeout=60
                )
                
                if start_result.returncode != 0:
                    logger.error(f"Failed to start VM: {start_result.stderr}")
                    return False
                
                # Wait for VM to boot
                logger.info("Waiting for VM to boot...")
                time.sleep(45)
            
            self.is_connected = True
            logger.info(f"Connected to VirtualBox VM: {self.vm_name}")
            return True
            
        except Exception as e:
            logger.error(f"VirtualBox connection error: {e}")
            return False
    
    def disconnect(self) -> bool:
        """Disconnect from VirtualBox VM"""
        try:
            # Save state of the VM
            result = subprocess.run(
                [self.vboxmanage_path, "controlvm", self.vm_name, "savestate"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            self.is_connected = False
            logger.info(f"Disconnected from VirtualBox VM: {self.vm_name}")
            return True
            
        except Exception as e:
            logger.error(f"VirtualBox disconnection error: {e}")
            return False
    
    def execute_script(self, script_content: str) -> TestResult:
        """Execute script in VirtualBox VM"""
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
            # Create a temporary script file path in the VM
            script_file = "/tmp/sandbox_script.py"
            
            # Copy script to VM using guestcontrol
            copy_cmd = [
                self.vboxmanage_path, "guestcontrol", self.vm_name,
                "copyto", "--username", self.username, "--password", self.password,
                "/dev/stdin", script_file
            ]
            
            copy_result = subprocess.run(
                copy_cmd,
                input=script_content,
                text=True,
                capture_output=True,
                timeout=30
            )
            
            if copy_result.returncode != 0:
                execution_time = time.time() - start_time
                return TestResult(
                    environment=self.name,
                    success=False,
                    output="",
                    execution_time=execution_time,
                    error=f"Failed to copy script to VM: {copy_result.stderr}"
                )
            
            # Execute script in VM
            exec_cmd = [
                self.vboxmanage_path, "guestcontrol", self.vm_name,
                "run", "--username", self.username, "--password", self.password,
                "--exe", self.python_path, "--", "python3", script_file
            ]
            
            exec_result = subprocess.run(
                exec_cmd,
                capture_output=True,
                text=True,
                timeout=60
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
                error=f"VirtualBox execution error: {e}"
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
                    timeout=10
                )
                
                return test_result.returncode == 0
            
            return False
            
        except Exception as e:
            logger.error(f"VirtualBox health check error: {e}")
            return False


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
        """Connect to all environments"""
        success = True
        for name, env in self.environments.items():
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
    
    def run_test_on_all(self, script_content: str) -> Dict[str, TestResult]:
        """Run test script on all connected environments"""
        results = {}
        
        for name, env in self.environments.items():
            if not env.is_connected:
                logger.warning(f"Environment {name} is not connected, skipping")
                continue
            
            logger.info(f"Running test on {name}")
            result = env.execute_script(script_content)
            results[name] = result
            self.test_results.append(result)
            
            status_msg = f"{name} - Success: {result.success}, Time: {result.execution_time:.2f}s"
            logger.info(status_msg)
            if result.error:
                logger.error(f"{name} - Error: {result.error}")
        
        return results
    
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
        
        # Execute exploit on all environments
        results = self.run_test_on_all(exploit_script)
        
        # Analyze results with intelligence
        detailed_results = {}
        exploitation_successful = False
        
        for env_name, result in results.items():
            # Perform intelligent analysis
            vulnerability_type = None
            if vulnerability_data:
                vulnerability_type = vulnerability_data.get('Type', '').lower()
            
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
        return {
            'status': 'success',
            'exploitation_successful': exploitation_successful,
            'environments_tested': len(results),
            'results': detailed_results,
            'logs_saved_to': log_filename,
            'timestamp': timestamp,
            'summary': {
                'total_environments': len(results),
                'successful_executions': sum(1 for r in results.values() if r.success),
                'successful_exploitations': sum(1 for env_name in detailed_results 
                                               if detailed_results[env_name]['exploitation_analysis']['exploitation_successful']),
                'learning_suggestions': self._extract_key_suggestions(detailed_results)
            }
        }
    
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
    
    def run_test_on_environment(self, env_name: str, script_content: str) -> Optional[TestResult]:
        """Run test script on a specific environment"""
        if env_name not in self.environments:
            logger.error(f"Environment {env_name} not found")
            return None
        
        env = self.environments[env_name]
        if not env.is_connected:
            logger.error(f"Environment {env_name} is not connected")
            return None
        
        logger.info(f"Running test on {env_name}")
        result = env.execute_script(script_content)
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
                       default="sandbox_config_final.json")
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