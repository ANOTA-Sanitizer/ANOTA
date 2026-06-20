import os
import re
import glob
from typing import List, Dict, Any, Optional
from logic_engine.utils.logger import audit_logger

class CodebaseScanner:
    """
    Scans a target codebase to identify entrypoints, technical context, and attack surface.
    Uses RAG (Retrieval-Augmented Generation) to enrich findings with knowledge from an Obsidian vault.
    """

    def __init__(self, target_path: str, knowledge_base_path: str):
        self.target_path = os.path.abspath(target_path)
        self.knowledge_base_path = os.path.abspath(knowledge_base_path)
        self.behaviors_path = os.path.join(self.knowledge_base_path, "behaviors")
        self.files_path = os.path.join(self.knowledge_base_path, "files")
        
        # Common web extensions
        self.entrypoint_extensions = {'.php', '.js', '.py', '.html', '.asp', '.jsp', '.rb', '.go', '.java'}
        
        # Heuristic patterns for technical context
        self.context_patterns = {
            "db_type": {
                "patterns": [r"mysql_connect", r"mysqli_connect", r"PDO\(.*mysql", r"sqlite_open", r"MongoClient\("],
                "mapping": {"mysql": "mysql", "sqlite": "sqlite", "mongodb": "mongodb"}
            },
            "auth_mechanism": {
                "patterns": [r"session_start\(", r"JWT", r"OAuth", r"password_verify\(", r"bcrypt"],
                "mapping": {"session": "session", "jwt": "jwt", "oauth": "oauth"}
            },
            "config_file": {
                "patterns": [r"config\.inc\.php", r"settings\.py", r"\.env", r"config\.json", r"web\.config"],
                "mapping": {"config": "configuration_file"}
            }
        }

        # Mapping of attack surface types to behavior keywords in Obsidian vault
        self.attack_type_to_keyword = {
            "sql_injection": "Sqli",
            "file_inclusion": "Fi",
            "command_injection": "Exec",
            "user_input": "Input", # Fallback
            "xss": "Xss",
            "csrf": "Csrf",
            "authbypass": "Authbypass",
            "brute": "Brute",
            "captcha": "Captcha",
            "cryptography": "Cryptography",
            "csp": "Csp",
            "open_redirect": "Open_redirect",
            "javascript": "Javascript",
            "upload": "Upload",
            "weak_id": "Weak_id",
            "bac": "Bac"
        }

    def scan(self) -> Dict[str, Any]:
        """Performs the full scan of the target directory."""
        audit_logger.log_event("codebase_scanner", "scan_start", input_data={"path": self.target_path})
        
        results = {
            "entrypoints": [],
            "technical_context": {},
            "attack_surface": []
        }

        if not os.path.exists(self.target_path):
            audit_logger.log_event("codebase_scanner", "scan_error", error=f"Target path {self.target_path} does not exist.")
            return results

        for root, _, files in os.walk(self.target_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.target_path)
                ext = os.path.splitext(file)[1].lower()

                # 1. Identify Entrypoints
                if ext in self.entrypoint_extensions:
                    entrypoint = {"path": rel_path, "type": ext.lstrip('.')}
                    # RAG enrichment: look for file knowledge
                    file_knowledge = self._get_file_knowledge(rel_path)
                    if file_knowledge:
                        entrypoint["knowledge"] = file_knowledge
                    results["entrypoints"].append(entrypoint)

                # 2. Extract Technical Context & Attack Surface
                self._analyze_file(file_path, rel_path, results)

        audit_logger.log_event("codebase_scanner", "scan_complete", output_data=results)
        return results

    def _analyze_file(self, full_path: str, rel_path: str, results: Dict[str, Any]):
        """Analyzes a single file for context and vulnerabilities."""
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for technical context
            for key, config in self.context_patterns.items():
                for pattern in config["patterns"]:
                    if re.search(pattern, content, re.IGNORECASE):
                        # Try to find the specific mapping if available
                        found_val = config.get("mapping", {}).get(key, key)
                        results["technical_context"][key] = found_val
                        break

            # Check for attack surface
            attack_patterns = {
                "user_input": [r"\$_GET", r"\$_POST", r"\$_REQUEST"],
                "sql_injection": [r"query\(", r"mysqli_query\(", r"execute\("],
                "file_inclusion": [r"file_get_contents\(", r"include\(", r"require\("],
                "command_injection": [r"exec\(", r"system\(", r"passthru\(", r"shell_exec\("],
                "xss": [r"echo\s+['\"]<\s*script", r"print\s+['\"]<\s*script"], # simple xss
            }

            for area, patterns in attack_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        finding = {
                            "file": rel_path,
                            "type": area,
                            "line": content.count('\n', 0, match.start()) + 1,
                            "snippet": match.group().strip()
                        }
                        
                        # RAG enrichment: correlate with behaviors
                        behavior = self._correlate_with_behavior(area)
                        if behavior:
                            finding["behavior_model"] = behavior
                            
                        results["attack_surface"].append(finding)
                        break # One match per area per file is enough for a baseline

        except Exception as e:
            audit_logger.log_event("codebase_scanner", "file_analysis_error", input_data={"file": rel_path}, error=str(e))

    def _get_file_knowledge(self, rel_path: str) -> Optional[str]:
        """Attempts to find knowledge for a file in the Obsidian files directory."""
        # Convert rel_path like 'vulnerabilities/api/src/User.php' 
        # to 'vulnerabilities_api_src_User_php.md' style if it follows knowledge pattern
        # Or more simply, just try to find a direct match after replacing slashes and dots.
        
        # Pattern 1: direct match with underscores
        clean_name = rel_path.replace('/', '_').replace('.', '_')
        possible_file = os.path.join(self.files_path, f"{clean_name}.md")
        
        if os.path.exists(possible_file):
            try:
                with open(possible_file, 'r', encoding='utf-8') as f:
                    return f.read().strip()
            except:
                pass

        # Pattern 2: simple filename match (e.g. login.php -> login_php.md)
        filename = os.path.basename(rel_path)
        clean_filename = filename.replace('.', '_')
        possible_file_simple = os.path.join(self.files_path, f"{clean_filename}.md")
        
        if os.path.exists(possible_file_simple):
            try:
                with open(possible_file_simple, 'r', encoding='utf-8') as f:
                    return f.read().strip()
            except:
                pass
                
        return None

    def _correlate_with_behavior(self, attack_type: str) -> Optional[str]:
        """Finds relevant behavior models in the Obsidian behaviors directory."""
        keyword = self.attack_type_to_keyword.get(attack_type)
        if not keyword:
            return None

        # Look for any file that contains the keyword in its name
        # e.g. Sqli_Index_*.md
        search_pattern = os.path.join(self.behaviors_path, f"{keyword}_Index_*.md")
        matches = glob.glob(search_pattern)
        
        if matches:
            # Return the first match as the most relevant behavior model
            # In a real implementation, we might want to return all or use semantic search
            return os.path.basename(matches[0])
            
        return None

if __name__ == "__main__":
    # Simple CLI for testing
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--rules", required=True)
    args = parser.parse_args()
    
    scanner = CodebaseScanner(args.target, args.rules)
    print(scanner.scan())

