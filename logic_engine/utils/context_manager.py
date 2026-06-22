import os
import re
from typing import Dict, Any, Optional
from logic_engine.blackboard import Blackboard
from logic_engine.utils.logger import audit_logger

class ContextManager:
    """
    Manages environmental and semantic context for the agentic scanning process.
    Extracts configuration requirements and system prerequisites to build
    a semantic 'Rules of the World' model on the Blackboard.
    """

    def __init__(self, project_root: str, knowledge_base_path: str, blackboard: Blackboard):
        self.project_root = project_root
        self.knowledge_base_path = knowledge_base_path
        self.blackboard = blackboard
        self.context: Dict[str, Any] = {}

    def extract_environmental_context(self, config_file_path: str):
        """
        Parses a configuration file (e.g., config.inc.php.dist) to extract
        environmental variables and system settings.
        """
        audit_logger.info(f"Extracting environmental context from {config_file_path}")
        
        if not os.path.exists(config_file_path):
            audit_logger.error(f"Configuration file not found: {config_file_path}")
            return

        try:
            with open(config_file_path, 'r') as f:
                content = f.read()

            # Extract PHP variables for DVWA
            # Example: $_DVWA[ 'db_user' ] = getenv('DB_USER') ?: 'dvwa';
            # We look for the default values provided by getenv
            
            # Match $_DVWA[ 'key' ] = getenv('KEY') ?: 'value';
            pattern = r"_\$_DVWA\s*\[\s*['\"](\w+)['\"]\s*\]\s*=\s*getenv\(['\"]\w+['\"]\)\s*:\?\s*['\"]([^'\"]+)['\"];"
            matches = re.findall(pattern, content)
            
            for key, value in matches:
                self.context[f"DVWA_{key.upper()}"] = value
                self.blackboard.add_fact(f"env_config_{key.lower()}", value)

            # Extract defined constants
            # Example: define ('MYSQL', 'mysql');
            const_pattern = r"define\s*\(\s*['\"](\w+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\);"
            const_matches = re.findall(const_pattern, content)
            for key, value in const_matches:
                self.context[key] = value
                self.blackboard.add_fact(f"env_const_{key.lower()}", value)

            # Also look for direct assignments if getenv is not used
            # Example: $DBMS = 'MySQL';
            var_pattern = r"\$(\w+)\s*=\s*['\"]([^'\"]+)['\"];"
            var_matches = re.findall(var_pattern, content)
            for key, value in var_matches:
                # Avoid overwriting the ones we already got or common things
                if key not in self.context:
                    self.context[f"DVWA_{key.upper()}"] = value
                    self.blackboard.add_fact(f"env_var_{key.lower()}", value)

            audit_logger.info(f"Successfully extracted context: {self.context}")
            self.blackboard.add_fact("environmental_context", self.context)

        except Exception as e:
            audit_logger.error(f"Failed to extract environmental context: {e}")

    def extract_prerequisite_rules(self, prerequisites_file: str):
        """
        Parses the obsidian_vault/rules/prerequisites.md to extract
        high-level system requirements and bootstrapping information.
        """
        audit_logger.info(f"Extracting prerequisite rules from {prerequisites_file}")
        
        if not os.path.exists(prerequisites_file):
            audit_logger.error(f"Prerequisites file not found: {prerequisites_file}")
            return

        try:
            with open(prerequisites_file, 'r') as f:
                content = f.read()

            # Parse the table for Configuration Settings & Global Constants
            # | Key | Value / Placeholder | Origin File |
            # | :--- | :--- | :--- |
            # | `MYSQL` | `mysql` | [[files/config_config_inc_php\|config/config.inc.php]] |
            
            table_pattern = r"\|\s*`(\w+)`\s*\|\s*`([^`]+)`\s*\|\s*\[\[[^\]]+\]\]\s*\|"
            matches = re.findall(table_pattern, content)

            for key, value in matches:
                self.context[key] = value
                self.blackboard.add_fact(f"prerequisite_{key.lower()}", value)
                audit_logger.info(f"Extracted prerequisite: {key} = {value}")

            # Add the full context to blackboard
            self.blackboard.add_fact("system_prerequisites", self.context)

        except Exception as e:
            audit_logger.error(f"Failed to extract prerequisite rules: {e}")

    def get_context(self) -> Dict[str, Any]:
        return self.context
