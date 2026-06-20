import json
import os
from datetime import datetime
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

    def add_fact(self, fact):
        """Adds a new fact to the blackboard."""
        fact_entry = {
            "content": fact,
            "timestamp": datetime.now().isoformat()
        }
        self.state["facts"].append(fact_entry)
        self._save()

    def add_hypothesis(self, hypothesis):
        """Adds a new hypothesis to the blackboard."""
        hypothesis_entry = {
            "content": hypothesis,
            "timestamp": datetime.now().isoformat(),
            "status": "pending"
        }
        self.state["hypotheses"].append(hypothesis_entry)
        self._save()

    def add_verified_finding(self, finding):
        """Adds a verified finding to the blackboard."""
        finding_entry = {
            "content": finding,
            "timestamp": datetime.now().isoformat()
        }
        self.state["verified_findings"].append(finding_entry)
        self._save()

    def update_context(self, key, value):
        """Updates the current context."""
        self.state["current_context"][key] = value
        self._save()

    def get_all(self):
        return self.state

# Global instance
blackboard = Blackboard()
