import json
import os
from datetime import datetime
from typing import Optional, Dict, Any
from logic_engine.utils.logger import audit_logger

class Blackboard:
    def __init__(self, filepath="logic_engine/blackboard.json"):
        self.filepath = filepath
        self.state = {
            "facts": [],
            "hypotheses": [],
            "verified_findings": [],
            "current_context": {}
        }
        self._load()

    def _load(self):
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r") as f:
                    self.state = json.load(f)
            except json.JSONDecodeError:
                # If file is corrupted, we start with empty state
                pass

    def _save(self):
        with open(self.filepath, "w") as f:
            json.dump(self.state, f, indent=4)
        audit_logger.log_event("blackboard", "save_state", input_data=self.state)

    def add_fact(self, *args, metadata: Optional[Dict[str, Any]] = None):
        """Adds a new fact to the blackboard. Supports (content) or (key, value) or (structured_dict)."""
        fact_entry = {"timestamp": datetime.now().isoformat()}
        
        if len(args) == 1:
            if isinstance(args[0], dict):
                fact_entry.update(args[0])
            else:
                fact_entry["content"] = args[0]
        elif len(args) == 2:
            fact_entry["key"] = args[0]
            fact_entry["value"] = args[1]
        else:
            raise ValueError("add_fact takes either 1 or 2 arguments")
        
        if metadata:
            fact_entry["metadata"] = metadata
            
        self.state["facts"].append(fact_entry)
        self._save()

    def add_hypothesis(self, hypothesis: Any, metadata: Optional[Dict[str, Any]] = None):
        """Adds a new hypothesis to the blackboard."""
        hypothesis_entry = {
            "content": hypothesis,
            "timestamp": datetime.now().isoformat(),
            "status": "pending"
        }
        if metadata:
            hypothesis_entry["metadata"] = metadata
        self.state["hypotheses"].append(hypothesis_entry)
        self._save()

    def add_verified_finding(self, finding: Any, metadata: Optional[Dict[str, Any]] = None):
        """Adds a verified finding to the blackboard."""
        finding_entry = {
            "timestamp": datetime.now().isoformat()
        }
        
        if isinstance(finding, dict):
            finding_entry.update(finding)
        else:
            finding_entry["content"] = finding

        if metadata:
            finding_entry["metadata"] = metadata
        self.state["verified_findings"].append(finding_entry)
        self._save()

    def update_context(self, key, value):
        """Updates the current context."""
        self.state["current_context"][key] = value
        self._save()

    def get_all(self):
        """Returns the full blackboard state."""
        return self.state

    def get_latest_fact(self, key: Optional[str] = None):
        """Returns the latest fact. If key is provided, returns the value of the latest fact matching the key."""
        if not self.state["facts"]:
            return None
        
        if key:
            # Filter facts by key
            matching_facts = [f for f in self.state["facts"] if f.get("key") == key]
            if not matching_facts:
                return None
            last_fact = matching_facts[-1]
            return last_fact.get("value") if "value" in last_fact else last_fact.get("content")
        else:
            return self.state["facts"][-1]

    def get_latest_fact_entry(self, key: Optional[str] = None):
        """Returns the latest fact entry (including metadata)."""
        if not self.state["facts"]:
            return None
        
        if key:
            # Filter facts by key
            matching_facts = [f for f in self.state["facts"] if f.get("key") == key]
            if not matching_facts:
                return None
            return matching_facts[-1]
        else:
            return self.state["facts"][-1]

    def clear(self):
        """Clears the blackboard state."""
        self.state = {
            "facts": [],
            "hypotheses": [],
            "verified_findings": [],
            "current_context": {}
        }
        self._save()

# Global instance
blackboard = Blackboard()
