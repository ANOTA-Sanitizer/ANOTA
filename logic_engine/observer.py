import json
import socket
import logging
import threading
from logic_engine.blackboard import blackboard
from logic_engine.utils.logger import audit_logger

class Observer:
    def __init__(self, socket_path="/tmp/anota_syscall.sock"):
        self.socket_path = socket_path
        self.running = False
        self.thread = None
        self.logger = logging.getLogger("Observer")

    def _normalize(self, raw_data: str) -> dict:
        """Parses and normalizes raw event data from the socket."""
        try:
            data = json.loads(raw_data)
            if not isinstance(data, dict):
                return {}
            
            if "type" not in data:
                data["type"] = "unknown"
            
            return data
        except json.JSONDecodeError:
            self.logger.error(f"Failed to decode JSON: {raw_data}")
            return {}

    def _listen_loop(self):
        """Internal loop for the listening thread."""
        self.logger.info(f"Starting observer loop on {self.socket_path}")
        
        while self.running:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                try:
                    client.connect(self.socket_path)
                    while self.running:
                        data = client.recv(4096)
                        if not data:
                            break
                        
                        raw_event = data.decode('utf-8')
                        normalized_fact = self._normalize(raw_event)
                        
                        if normalized_fact:
                            blackboard.add_fact(normalized_fact)
                            audit_logger.log_event("observer", "fact_injected", input_data=normalized_fact)
                except (ConnectionRefusedError, FileNotFoundError):
                    # Socket not available yet, wait and retry
                    import time
                    time.sleep(1)
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error in observer loop: {e}")
                    break
        
        self.logger.info("Observer loop stopped.")

    def start_listening(self):
        """Starts the observer in a background thread."""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._listen_loop, daemon=True)
        self.thread.start()
        self.logger.info("Observer thread started.")

    def stop_listening(self):
        """Stops the observer."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        self.logger.info("Observer stopped.")

# Global instance for easy import
observer = Observer()
