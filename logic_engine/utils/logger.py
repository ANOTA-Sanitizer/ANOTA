import json
import os
import glob
import logging
from datetime import datetime, timedelta
from typing import Union, Any

# Configure standard logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mac-dast")

class AgentAuditLogger:
    def __init__(self, log_dir="logs/agent_audit", max_days=7):
        self.log_dir = log_dir
        self.max_days = max_days
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        self.prune_old_logs()

    def prune_old_logs(self):
        """Removes log files older than max_days."""
        now = datetime.now()
        cutoff = now - timedelta(days=self.max_days)
        
        log_files = glob.glob(os.path.join(self.log_dir, "*.json"))
        for filepath in log_files:
            try:
                file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                if file_time < cutoff:
                    os.remove(filepath)
            except Exception as e:
                logger.error(f"Error pruning log file {filepath}: {e}")

    def log_event(self, agent_id: str, action: str, input_data: Any = None, output_data: Any = None, error: Union[Exception, str] = None) -> str:
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

    def info(self, msg: str):
        logger.info(msg)

    def error(self, msg: str):
        logger.error(msg)

# Global instances for easy import
audit_logger = AgentAuditLogger()
