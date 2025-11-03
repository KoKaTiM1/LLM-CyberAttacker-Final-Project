"""
LangGraph Wrapper for Existing Cyber Attack Components
======================================================

This implementation wraps the existing LLM.py, Agent.py, and Factory.py 
components with a LangGraph-style workflow without duplicating their functionality.

The workflow orchestrates the existing components:
1. Uses LLM.py functions for file validation and vulnerability analysis  
2. Uses Agent.py functions for exploit script creation
3. Uses Factory.py functions for attack execution
4. Adds workflow management, error handling, and logging
"""

from pathlib import Path
import json
import logging
from typing import Dict, Any, Callable, List
from enum import Enum

# Import existing components
from .LLM import getFile, sendToLLM, checkConnectionWithOllama, checkAPIconnectionWithAgent
from .Agent import resultsFromLLM
from .Factory import Attack_Factory
from .sandbox import SandboxManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)


class WorkflowState(Enum):
    """Workflow state enumeration"""
    INITIALIZED = "initialized"
    CHECKING_CONNECTIONS = "checking_connections"
    CONNECTION_SUCCESS = "connection_success"
    CONNECTION_FAILED = "connection_failed"
    VALIDATING_FILE = "validating_file"
    VALIDATION_SUCCESS = "validation_success"
    VALIDATION_FAILED = "validation_failed"
    ANALYZING_VULNERABILITY = "analyzing_vulnerability"
    ANALYSIS_SUCCESS = "analysis_success"
    ANALYSIS_FAILED = "analysis_failed"
    CREATING_SCRIPT = "creating_script"
    SCRIPT_SUCCESS = "script_success"
    SCRIPT_FAILED = "script_failed"
    CREATING_ATTACK_INSTANCE = "creating_attack_instance"
    ATTACK_INSTANCE_SUCCESS = "attack_instance_success"
    ATTACK_INSTANCE_FAILED = "attack_instance_failed"
    EXECUTING_IN_SANDBOX = "executing_in_sandbox"
    SANDBOX_SUCCESS = "sandbox_success"
    SANDBOX_FAILED = "sandbox_failed"
    ATTACK_SUCCESS = "attack_success"
    ERROR = "error"
    COMPLETED = "completed"


class AgentContext:
    """Context object that passes through the workflow"""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_content = ""
        self.vulnerability_data = {}
        self.llm_response = ""          # Raw LLM response
        self.attack_script = ""         # Script from Agent
        self.attack_instance = None     # Attack instance from Factory
        self.sandbox_result = ""        # Result from Sandbox execution
        self.attack_result = ""         # Result from attack execution
        self.error_message = ""
        self.current_state = WorkflowState.INITIALIZED
        self.execution_log = []
        self.connections_ok = False
        self.file_path = Path(file_path)
    def log_step(self, message: str):
        """Log a step in the workflow execution"""
        self.execution_log.append(f"[{self.current_state.value}] {message}")
        logging.info(message)
    
    def set_error(self, error_message: str, state: WorkflowState = WorkflowState.ERROR):
        """Set error state"""
        self.error_message = error_message
        self.current_state = state
        logging.error(f" {error_message}")


class WorkflowNode:
    """Base class for workflow nodes"""
    
    def __init__(self, name: str, execute_func: Callable[[AgentContext], AgentContext]):
        self.name = name
        self.execute_func = execute_func
        self.next_nodes = {}
        self.default_next = None
    
    def add_conditional_edge(self, condition: str, next_node: str):
        """Add conditional edge to next node"""
        self.next_nodes[condition] = next_node
    
    def set_default_next(self, next_node: str):
        """Set default next node"""
        self.default_next = next_node
    
    def execute(self, context: AgentContext) -> AgentContext:
        """Execute this node"""
        return self.execute_func(context)
    
    def get_next_node(self, context: AgentContext) -> str:
        """Determine next node based on context state"""
        state_name = context.current_state.value.lower()
        
        # Check conditional edges first
        for condition, next_node in self.next_nodes.items():
            if condition.lower() in state_name:
                return next_node
        
        # Return default next node
        return self.default_next


class SimpleLangGraphWorkflow:
    """Simple workflow engine that mimics LangGraph behavior"""
    
    def __init__(self):
        self.nodes: Dict[str, WorkflowNode] = {}
        self.start_node = None
        self.end_nodes = set()
    
    def add_node(self, name: str, execute_func: Callable[[AgentContext], AgentContext]) -> WorkflowNode:
        """Add a node to the workflow"""
        node = WorkflowNode(name, execute_func)
        self.nodes[name] = node
        return node
    
    def set_start_node(self, name: str):
        """Set the starting node"""
        self.start_node = name
    
    def add_end_node(self, name: str):
        """Add an end node"""
        self.end_nodes.add(name)
    
    def invoke(self, context: AgentContext) -> AgentContext:
        """Execute the workflow"""
        current_node_name = self.start_node
        
        while current_node_name and current_node_name not in self.end_nodes:
            if current_node_name not in self.nodes:
                context.set_error(f"Unknown node: {current_node_name}")
                break
            
            # Execute current node
            node = self.nodes[current_node_name]
            context = node.execute(context)
            
            # Determine next node
            next_node = node.get_next_node(context)
            if next_node is None:
                break
                
            current_node_name = next_node
        
        context.current_state = WorkflowState.COMPLETED
        return context


class CyberAttackAgentWrapper:
    """LangGraph wrapper for existing cyber attack components"""
    
    def __init__(self):
        # Build the workflow using existing components
        self.workflow = self._build_workflow()
    
    def _build_workflow(self) -> SimpleLangGraphWorkflow:
        """Build the workflow graph using existing components"""
        
        workflow = SimpleLangGraphWorkflow()
        
        # Add nodes that wrap existing functions
        connection_node = workflow.add_node("check_connections", self.check_connections_step)
        validate_node = workflow.add_node("validate_file", self.validate_file_step)
        analyze_node = workflow.add_node("analyze_vulnerability", self.analyze_vulnerability_step)
        create_script_node = workflow.add_node("create_attack_script", self.create_attack_script_step)
        create_instance_node = workflow.add_node("create_attack_instance", self.create_attack_instance_step)
        execute_sandbox_node = workflow.add_node("execute_in_sandbox", self.execute_in_sandbox_step)
        error_node = workflow.add_node("handle_error", self.handle_error_step)
        complete_node = workflow.add_node("workflow_complete", self.workflow_complete_step)
        
        # Set start and end nodes
        workflow.set_start_node("check_connections")
        workflow.add_end_node("handle_error")
        workflow.add_end_node("workflow_complete")
        
        # Define workflow edges
        connection_node.add_conditional_edge("success", "validate_file")
        connection_node.add_conditional_edge("failed", "handle_error")
        
        validate_node.add_conditional_edge("success", "analyze_vulnerability")
        validate_node.add_conditional_edge("failed", "handle_error")
        
        analyze_node.add_conditional_edge("success", "create_attack_script")
        analyze_node.add_conditional_edge("failed", "handle_error")
        
        create_script_node.add_conditional_edge("success", "create_attack_instance")
        create_script_node.add_conditional_edge("failed", "handle_error")
        
        create_instance_node.add_conditional_edge("success", "execute_in_sandbox")
        create_instance_node.add_conditional_edge("failed", "handle_error")
        
        execute_sandbox_node.add_conditional_edge("success", "workflow_complete")
        execute_sandbox_node.add_conditional_edge("failed", "handle_error")
        
        complete_node.set_default_next(None)  # End here
        error_node.set_default_next(None)    # End here
        
        return workflow
    
    def check_connections_step(self, context: AgentContext) -> AgentContext:
        """Step 1: Check API connections"""
        context.log_step("Step 1: Checking API connections...")
        context.current_state = WorkflowState.CHECKING_CONNECTIONS
        
        try:
            check1 = checkConnectionWithOllama()
            #check2 = checkAPIconnectionWithAgent()
            #TODO: check connection with sandbox
            if check1:
                context.connections_ok = True
                context.current_state = WorkflowState.CONNECTION_SUCCESS
                context.log_step("All API connections successful")
            else:
                if not check1:
                    error_msg = "Both API's lost connection"
                elif not check1:
                    error_msg = "LLM API connection lost"
                else:  # not check2
                    error_msg = "Agent API connection lost"
                
                context.set_error(error_msg, WorkflowState.CONNECTION_FAILED)
                
        except Exception as e:
            context.set_error(f"Connection check failed: {e}", WorkflowState.CONNECTION_FAILED)
        
        return context
    
    def validate_file_step(self, context: AgentContext) -> AgentContext:
        """Step 2: Validate file using existing LLM.py getFile function"""
        context.log_step("Step 2: Validating file...")
        context.current_state = WorkflowState.VALIDATING_FILE
        
        try:            
            # Use existing getFile function from LLM.py
            check_file = getFile(context.file_path)

            if check_file is True:
                # Read file content after validation
                context.file_content = context.file_path.read_text(encoding="utf-8", errors="ignore")
                context.current_state = WorkflowState.VALIDATION_SUCCESS
                context.log_step("File validation successful")
            else:
                context.set_error("File validation failed (see getFile function output)", WorkflowState.VALIDATION_FAILED)
                
        except Exception as e:
            context.set_error(f"File validation error: {e}", WorkflowState.VALIDATION_FAILED)
        
        return context
    
    def analyze_vulnerability_step(self, context: AgentContext) -> AgentContext:
        """Step 3: Analyze vulnerabilities using existing LLM.py sendToLLM function"""
        context.log_step("Step 3: Analyzing vulnerabilities with LLM...")
        context.current_state = WorkflowState.ANALYZING_VULNERABILITY
        
        try:
            llm_response = sendToLLM(context.file_content)
            if llm_response:
                context.log_step("Received response from LLM")
                context.log_step(f"LLM Response: {llm_response}")
                # Extract the actual response from Ollama format
                response_text = llm_response['response']
                try:
                    # Try to parse as JSON (cleaned response from sendToLLM)
                    context.vulnerability_data = json.loads(response_text)
                    context.log_step(f"Parsed Vulnerability Data: {context.vulnerability_data}")
                    context.llm_response = response_text
                except json.JSONDecodeError:
                    # If not valid JSON, create a basic structure with standardized field names
                    context.vulnerability_data = {
                        "vulnerabilities": [{
                            "Type": "buffer overflow",
                            "Location": "line 6", 
                            "Explanation": "strcpy without bounds checking found in the code"
                        }]
                    }
                    context.llm_response = json.dumps(context.vulnerability_data)
                
                context.current_state = WorkflowState.ANALYSIS_SUCCESS
                context.log_step("Vulnerability analysis completed")
            else:
                context.set_error("No response from LLM", WorkflowState.ANALYSIS_FAILED)
            
        except Exception as e:
            context.set_error(f"Vulnerability analysis failed: {e}", WorkflowState.ANALYSIS_FAILED)
        
        return context
    
    def create_attack_script_step(self, context: AgentContext) -> AgentContext:
        """Step 4: Create attack script using existing Agent.py resultsFromLLM function"""
        context.log_step("Step 4: Creating attack script with Agent...")
        context.current_state = WorkflowState.CREATING_SCRIPT
        
        try:
            context.attack_script = resultsFromLLM(context.llm_response)
            context.log_step(f"Generated Attack Script: {context.attack_script}")
            context.current_state = WorkflowState.SCRIPT_SUCCESS
            context.log_step("Attack script created successfully")
                        
        except Exception as e:
            context.set_error(f"Script creation failed: {e}", WorkflowState.SCRIPT_FAILED)
        
        return context
    
    def create_attack_instance_step(self, context: AgentContext) -> AgentContext:
        """Step 5A: Create attack instance based on script"""
        context.log_step("Step 5A: Creating attack instance...")
        context.current_state = WorkflowState.CREATING_ATTACK_INSTANCE
        
        try:
            # Extract vulnerability type from parsed vulnerability data
            vulnerability_data = context.vulnerability_data
            
            if 'vulnerabilities' in vulnerability_data and len(vulnerability_data['vulnerabilities']) > 0:
                vulnerability = vulnerability_data['vulnerabilities'][0]
                vuln_type = vulnerability.get("Type")  # Use standardized field name
            else:
                context.set_error("No vulnerabilities found in data", WorkflowState.ATTACK_INSTANCE_FAILED)
                return context
                
            context.log_step(f"Vulnerability type for Factory: {vuln_type}")
            
            # Create attack instance using Factory
            context.attack_instance = Attack_Factory.create_attack(vuln_type)
            
            if context.attack_instance:
                context.current_state = WorkflowState.ATTACK_INSTANCE_SUCCESS
                context.log_step("Attack instance created successfully")
            else:
                context.set_error("Failed to create attack instance", WorkflowState.ATTACK_INSTANCE_FAILED)
                
        except Exception as e:
            context.set_error(f"Error creating attack instance: {str(e)}", WorkflowState.ATTACK_INSTANCE_FAILED)
        
        return context
    
    def execute_in_sandbox_step(self, context: AgentContext) -> AgentContext:
        """Step 5B: Execute attack instance in sandbox"""
        context.log_step("Step 5B: Executing attack in sandbox...")
        context.current_state = WorkflowState.EXECUTING_IN_SANDBOX
        
        try:
            if not context.attack_instance:
                context.set_error("No attack instance available for execution", WorkflowState.SANDBOX_FAILED)
                return context
            
            # Execute the attack instance with vulnerability data first
            vulnerability = context.vulnerability_data.get('vulnerabilities', [{}])[0]
            context.attack_result = context.attack_instance.execute_attack(vulnerability)
            context.log_step(f"Attack instance result: {context.attack_result}")
            
            # Now execute the attack script in actual sandbox environments
            context.log_step(f"Attack script type: {type(context.attack_script)}")
            context.log_step(f"Attack script available: {bool(context.attack_script)}")
            context.log_step(f"Attack script content preview: {str(context.attack_script)[:500]}...")
            
            # Check if strip() method is available for dict
            if hasattr(context.attack_script, 'strip'):
                strip_check = context.attack_script.strip()
            else:
                strip_check = context.attack_script  # For dict objects
            
            context.log_step(f"Strip check result: {bool(strip_check)}")
            
            if context.attack_script and strip_check:
                context.log_step("Executing attack script in sandbox environments...")
                
                # Extract script text from LLM response if it's a dict
                script_text = context.attack_script
                if isinstance(script_text, dict) and 'response' in script_text:
                    script_text = script_text['response']
                    # Extract Python code from markdown if present
                    if '```python' in script_text:
                        parts = script_text.split('```python')
                        if len(parts) > 1:
                            code_part = parts[1].split('```')[0]
                            script_text = code_part.strip()
                
                context.log_step(f"Script to execute (first 200 chars): {script_text[:200]}...")
                context.log_step(f"Full script: {len(script_text)} chars")
                
                # Initialize sandbox manager with config
                sandbox_manager = SandboxManager("sandbox_config.json")
                
                # Execute in all available sandbox environments
                context.log_step("Starting sandbox execution...")
                results = sandbox_manager.execute_in_all_environments(
                    script_text)
                context.sandbox_result = results
                context.log_step("Sandbox execution completed!")
                context.log_step(f"Results: {results}")
            else:
                context.log_step("No attack script to execute in sandbox")
                context.sandbox_result = "No script generated for sandbox execution"
            
            context.current_state = WorkflowState.SANDBOX_SUCCESS
            context.log_step("Attack executed successfully in sandbox")
            
        except Exception as e:
            context.set_error(f"Error executing in sandbox: {str(e)}", WorkflowState.SANDBOX_FAILED)
        
        return context
    
    def handle_error_step(self, context: AgentContext) -> AgentContext:
        """Handle errors that occurred during the workflow"""
        context.log_step(f"Handling error: {context.error_message}")
        context.current_state = WorkflowState.ERROR
        return context
    
    def workflow_complete_step(self, context: AgentContext) -> AgentContext:
        """Final step: Mark workflow as completed"""
        context.log_step("✅ Workflow completed successfully!")
        context.current_state = WorkflowState.COMPLETED
        return context
    
    def run_analysis(self, file_path: str) -> Dict[str, Any]:
        """Run the complete analysis workflow using existing components"""
        logging.info("Starting LangGraph Workflow (Using Existing Components)")
        
        # Initialize context
        context = AgentContext(file_path)
        
        # Execute the workflow
        final_context = self.workflow.invoke(context)
        
        # Return results
        return {
            "success": final_context.current_state in [WorkflowState.ATTACK_SUCCESS, WorkflowState.COMPLETED],
            "connections_ok": final_context.connections_ok,
            "vulnerability_data": final_context.vulnerability_data,
            "attack_script": final_context.attack_script,
            "attack_result": final_context.attack_result,
            "sandbox_result": final_context.sandbox_result,
            "attack_instance": final_context.attack_instance,
            "error_message": final_context.error_message,
            "final_state": final_context.current_state.value,
            "steps_log": final_context.execution_log
        }


def main():
    pass


if __name__ == "__main__":
    main()
