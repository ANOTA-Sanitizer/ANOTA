import os
import yaml
import re
from datetime import datetime

class KnowledgeProjector:
    """
    Materializes logic-relevant entities and findings into Markdown notes (Obsidian Vault).
    Ensures non-destructive updates for human-edited sections.
    """
    def __init__(self, vault_root="Vault"):
        self.vault_root = vault_root
        self._ensure_dirs()

    def _ensure_dirs(self):
        for sub in ["Findings", "States", "Actions", "Code"]:
            os.makedirs(os.path.join(self.vault_root, sub), exist_ok=True)

    def materialize_finding(self, data):
        """
        Creates or updates a finding note.
        """
        trace_id = data.get("id", "unknown")
        filename = f"{trace_id}.md"
        filepath = os.path.join(self.vault_root, "Findings", filename)
        
        # 1. Extract existing human rationale if file exists
        human_rationale = ""
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                content = f.read()
                match = re.search(r"## Human Rationale\n(.*?)(?=\n##|$)", content, re.DOTALL)
                if match:
                    human_rationale = match.group(1).strip()

        # 2. Build Markdown content
        frontmatter = {
            "id": trace_id,
            "type": "vulnerability_finding",
            "target": data.get("target"),
            "confidence": data.get("confidence"),
            "model": data.get("model"),
            "timestamp": datetime.now().isoformat()
        }
        
        md_content = f"""---
{yaml.dump(frontmatter, default_flow_style=False)}---

# {data.get('title', 'Vulnerability Finding')}

## Agent Rationale
{data.get('rationale', 'N/A')}

## Evidence
{data.get('evidence', 'N/A')}
"""

        if human_rationale:
            md_content += f"""
## Human Rationale
{human_rationale}
"""

        # 3. Write to file
        with open(filepath, "w") as f:
            f.write(md_content)
            
        # 4. Update Activity Log
        self._log_activity(f"Promoted finding {trace_id}: {data.get('title')}")
        
        return filepath

    def materialize_state(self, state_name, details):
        """
        Creates or updates a state note in Vault/States.
        """
        filepath = os.path.join(self.vault_root, "States", f"{state_name}.md")
        content = f"# State: {state_name}\n\n{details}\n"
        with open(filepath, "w") as f:
            f.write(content)
        self._log_activity(f"Materialized state: {state_name}")
        return filepath

    def materialize_action(self, action_name, details):
        """
        Creates or updates an action note in Vault/Actions.
        """
        filepath = os.path.join(self.vault_root, "Actions", f"{action_name}.md")
        content = f"# Action/Transition: {action_name}\n\n{details}\n"
        with open(filepath, "w") as f:
            f.write(content)
        self._log_activity(f"Materialized action: {action_name}")
        return filepath

    def _log_activity(self, message):
        log_path = os.path.join(self.vault_root, "ActivityLog.md")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path, "a") as f:
            f.write(f"- [{timestamp}] {message}\n")
