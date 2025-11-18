from abc import ABC, abstractmethod
from .sandbox import SandboxManager
import json
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)


class Attack_Base(ABC):
    """Base class for all attack types"""

    @abstractmethod
    def execute_attack(self, vulnerability_data: dict):
        """Execute the specific attack"""
        pass

    @abstractmethod
    def get_attack_type(self) -> str:
        """Return the attack type name"""
        pass


class Buffer_Overflow_Attack(Attack_Base):

    def execute_attack(self, vulnerability_data: dict):
        sandbox_manager = SandboxManager()
        if sandbox_manager.connect_all():
            script="print('test')"
            if sandbox_manager.run_test_on_all(script):
                return True

    def get_attack_type(self) -> str:
        """Return attack type name"""
        return "buffer_overflow"



class Format_String_Attack(Attack_Base):

    def execute_attack(self, vulnerability_data: dict):
        return f"Executing format_string attack at {vulnerability_data.get('Location', 'unknown location')}"

    def get_attack_type(self) -> str:
        return "format_string"


class Use_After_Free_Attack(Attack_Base):

    def execute_attack(self, vulnerability_data: dict):
        return f"Executing use_after_free attack at {vulnerability_data.get('Location', 'unknown location')}"

    def get_attack_type(self) -> str:
        return "use_after_free"


class Attack_Factory:
    """Factory class for creating attack objects based on vulnerability type"""

    # Registry mapping vulnerability types to attack classes
    _attack_registry = {
        "buffer overflow": Buffer_Overflow_Attack,
        "buffer overflow via unsafe use of strcpy": Buffer_Overflow_Attack,
        "buffer overflow via unsafe copy": Buffer_Overflow_Attack,  # ADD THIS NEW ONE
        "buffer overflow via strcpy": Buffer_Overflow_Attack,
        "format string": Format_String_Attack,
        "use after free": Use_After_Free_Attack,
    }

    @classmethod
    def create_attack(cls, vulnerability_type: str):
        """Create and return appropriate attack object based on vulnerability type"""

        # Normalize input to lowercase for comparisons
        normalized_type = vulnerability_type.lower().strip()

        # Exact registry lookup first
        attack_class = cls._attack_registry.get(normalized_type)
        if attack_class:
            return attack_class()

        # Fuzzy / substring matching to handle descriptive LLM outputs
        # Buffer overflow variants
        if ("buffer overflow" in normalized_type or
                "strcpy" in normalized_type or
                "unsafe copy" in normalized_type or
                "unsafe use of strcpy" in normalized_type):
            return Buffer_Overflow_Attack()

        # Format string variants
        if ("format string" in normalized_type or
                "printf" in normalized_type or
                "format-string" in normalized_type):
            return Format_String_Attack()

        # Use-after-free variants
        if ("use after free" in normalized_type or
                "use-after-free" in normalized_type or
                "uaf" in normalized_type):
            return Use_After_Free_Attack()
        # No match found - raise error with helpful message
        msg = "Unsupported vulnerability type: {}".format(
            vulnerability_type
        )
        raise ValueError(msg)

    @classmethod
    def register_attack(cls, vulnerability_type: str, attack_class: type):

        if not issubclass(attack_class, Attack_Base):
            raise ValueError("Attack class must inherit from Attack Base")

        cls._attack_registry[vulnerability_type.lower()] = attack_class


def process_vulnerability_and_attack(llm_result: str) -> str:

    try:
        vulnerability_data = json.loads(llm_result)

        if not vulnerability_data.get("Type"):
            raise ValueError("Missing vulnerability type in LLM result")

        if not vulnerability_data.get("Location"):
            raise ValueError("Missing vulnerability location in LLM result")

        if not vulnerability_data.get("Explanation"):
            raise ValueError("Missing vulnerability explanation in LLM result")

        attack = Attack_Factory.create_attack(vulnerability_data["Type"])

        result = attack.execute_attack(vulnerability_data)

        logging.info(f"Attack Type: {attack.get_attack_type()}")
        logging.info(f"Vulnerability: {vulnerability_data['Type']}")
        logging.info(f"Location: {vulnerability_data['Location']}")
        logging.info(f"Result: {result}")

        return result

    except json.JSONDecodeError as e:
        error_msg = f"Failed to parse LLM result JSON: {e}"
        logging.error(error_msg)
        return error_msg

    except ValueError as e:
        error_msg = f"Vulnerability processing error: {e}"
        logging.error(error_msg)
        return error_msg

    except Exception as e:
        error_msg = f"Unexpected error in attack processing: {e}"
        logging.error(error_msg)
        return error_msg
