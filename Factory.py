from abc import ABC, abstractmethod
import json


class AttackBase(ABC):
    """Base class for all attack types"""

    @abstractmethod
    def execute_attack(self, vulnerability_data: dict):
        """Execute the specific attack"""
        pass

    @abstractmethod
    def get_attack_type(self) -> str:
        """Return the attack type name"""
        pass


class BufferOverflowAttack(AttackBase):
    """Concrete implementation for Buffer Overflow attacks"""

    def execute_attack(self, vulnerability_data: dict):
        """Execute Buffer Overflow attack based on vulnerability data"""
        return f"Executing Buffer Overflow attack at {vulnerability_data.get('Location', 'unknown location')}"

    def get_attack_type(self) -> str:
        """Return attack type name"""
        return "Buffer Overflow"



class FormatStringAttack(AttackBase):

    def execute_attack(self, vulnerability_data: dict):
        return f"Executing Format String attack at {vulnerability_data.get('Location', 'unknown location')}"

    def get_attack_type(self) -> str:
        return "Format String"


class UseAfterFreeAttack(AttackBase):

    def execute_attack(self, vulnerability_data: dict):
        return f"Executing Use After Free attack at {vulnerability_data.get('Location', 'unknown location')}"

    def get_attack_type(self) -> str:
        return "Use After Free"


class AttackFactory:
    """Factory class for creating attack objects based on vulnerability type"""

    # Registry mapping vulnerability types to attack classes
    _attack_registry = {
        "buffer overflow": BufferOverflowAttack,
    }

    @classmethod
    def create_attack(cls, vulnerability_type: str):
        """Create and return appropriate attack object based on vulnerability type"""

        # Normalize input to lowercase
        normalized_type = vulnerability_type.lower().strip()

        # Find matching attack class in registry
        for registered_type, attack_class in cls._attack_registry.items():
            if registered_type in normalized_type or normalized_type in registered_type:
                return attack_class()  # Create and return attack instance

        # No match found - raise error
        raise ValueError(f"Unsupported vulnerability type: {vulnerability_type}")

    @classmethod
    def register_attack(cls, vulnerability_type: str, attack_class: type):

        if not issubclass(attack_class, AttackBase):
            raise ValueError("Attack class must inherit from AttackBase")

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

        attack = AttackFactory.create_attack(vulnerability_data["Type"])

        result = attack.execute_attack(vulnerability_data)

        print(f"Attack Type: {attack.get_attack_type()}")
        print(f"Vulnerability: {vulnerability_data['Type']}")
        print(f"Location: {vulnerability_data['Location']}")
        print(f"Result: {result}")

        return result

    except json.JSONDecodeError as e:
        error_msg = f"Failed to parse LLM result JSON: {e}"
        print(error_msg)
        return error_msg

    except ValueError as e:
        error_msg = f"Vulnerability processing error: {e}"
        print(error_msg)
        return error_msg

    except Exception as e:
        error_msg = f"Unexpected error in attack processing: {e}"
        print(error_msg)
        return error_msg
