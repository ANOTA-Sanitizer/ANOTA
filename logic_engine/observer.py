import json
import socket
import logging
import os
import threading
from logic_engine.blackboard import blackboard
from logic_engine.utils.logger import audit_logger

class Observer:
    def __init__(self, control_socket_path=None, telemetry_socket_path=None):
        self.control_socket_path = control_socket_path or "/tmp/anota_syscall.sock"
        self.telemetry_socket_path = telemetry_socket_path or "/tmp/anota_telemetry.sock"
        self.running = False
        self.threads = []
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

    def _telemetry_server_loop(self):
        """Internal loop for the telemetry server thread."""
        self.logger.info(f"Starting telemetry server on {self.telemetry_socket_path}")
        
        if os.path.exists(self.telemetry_socket_path):
            os.remove(self.telemetry_socket_path)
        
        while self.running:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                    server.bind(self.telemetry_socket_path)
                    server.listen(5)
                    server.settimeout(1.0)
                    
                    while self.running:
                        try:
                            try:
                                conn, _ = server.accept()
                            except socket.timeout:
                                continue
                            except Exception as e:
                                if self.running:
                                    self.logger.error(f"Error accepting connection: {e}")
                                continue
                            
                            with conn:
                                try:
                                    while self.running:
                                        data = conn.recv(4096)
                                        if not data:
                                            break
                                        
                                        raw_event = data.decode('utf-8')
                                        normalized_fact = self._normalize(raw_event)
                                        
                                        if normalized_fact:
                                            blackboard.add_fact("last_observation", normalized_fact)
                                            audit_logger.log_event("observer", "fact_injected", input_data=normalized_fact)
                                except Exception as e:
                                    if self.running:
                                        self.logger.error(f"Error processing connection data: {e}")
                        except Exception as e:
                            if self.running:
                                self.logger.error(f"Unexpected error in telemetry loop: {e}")
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error in telemetry server: {e}")
                import time
                time.sleep(1)
        
        if os.path.exists(self.telemetry_socket_path):
            os.remove(self.telemetry_socket_path)
        self.logger.info("Telemetry server stopped.")

    def _control_client_loop(self):
        """Internal loop for the control client thread."""
        self.logger.info(f"Starting control client connecting to {self.control_socket_path}")
        
        while self.running:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(self.control_socket_path)
                    self.logger.info("Connected to control socket.")
                    
                    while self.running:
                        try:
                            data = client.recv(4096)
                            if not data:
                                self.logger.info("Control socket connection closed. Reconnecting...")
                                break
                            
                            raw_event = data.decode('utf-8')
                            normalized_fact = self._normalize(raw_event)
                            
                            if normalized_fact:
                                blackboard.add_fact("last_observation", normalized_fact)
                                audit_logger.log_event("observer", "fact_injected", input_data=normalized_fact)
                                
                        except Exception as e:
                            if self.running:
                                self.logger.error(f"Error receiving from control socket: {e}")
                            break
            except Exception as e:
                if self.running:
                    self.logger.error(f"Error in control client: {e}. Retrying in 1s...")
                import time
                time.sleep(1)
        self.logger.info("Control client stopped.")

    def start_listening(self):
        """Starts the observer in background threads."""
        if self.running:
            return
        
        self.running = True
        
        t_server = threading.Thread(target=self._telemetry_server_loop, daemon=True)
        t_client = threading.Thread(target=self._control_client_loop, daemon=True)
        
        self.threads = [t_server, t_client]
        for t in self.threads:
            t.start()
            
        self.logger.info("Observer threads started (Telemetry Server & Control Client).")

    def stop_listening(self):
        """Stops the observer."""
        self.running = False
        for t in self.threads:
            t.join(timeout=2)
        self.threads = []
        self.logger.info("Observer stopped.")


# Global instance for easy import
observer = Observer()
