import json
import os
from datetime import datetime

class AgentAuditLogger:
    def __init__(self, log_dir="logs/agent_audit"):
        self.log_dir = log_dir
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def log_event(self, agent_id, action, input_data=None, output_data=None, error=None):
        """
        Logs a single agent event as a JSON file for a complete audit trail.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{agent_id}_{timestamp}.json"
        filepath = os.path.join(self.log_dir, filename)

        event = {
            "timestamp": datetime.now().isoformat(),
            "agent_id": agent_id,
            "action": action,
            "input": input_data,
            "output": output_data,
            "error": str(error) if error else None
        }

        with open(filepath, "w") as f:
            json.dump(event, f, indent=4)
        
        return filepath

# Global instance for easy import
audit_logger = AgentAuditLogger()
