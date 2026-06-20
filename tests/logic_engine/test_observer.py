import unittest
from unittest.mock import MagicMock, patch
import json
import threading
import time
from logic_engine.observer import Observer

class TestObserver(unittest.TestCase):
    def setUp(self):
        self.socket_path = "/tmp/test_anota_syscall.sock"
        self.observer = Observer(socket_path=self.socket_path)

    @patch("logic_engine.observer.blackboard")
    @patch("logic_engine.observer.audit_logger")
    @patch("socket.socket")
    def test_normalize_valid_json(self, mock_socket, mock_audit, mock_blackboard):
        valid_json = '{"type": "syscall", "syscall": "openat", "pid": 1234}'
        normalized = self.observer._normalize(valid_json)
        self.assertEqual(normalized["type"], "syscall")
        self.assertEqual(normalized["pid"], 1234)

    @patch("logic_engine.observer.blackboard")
    @patch("logic_engine.observer.audit_logger")
    @patch("socket.socket")
    def test_normalize_invalid_json(self, mock_socket, mock_audit, mock_blackboard):
        invalid_json = '{"type": "syscall", "pid": 1234' # Missing closing brace
        normalized = self.observer._normalize(invalid_json)
        self.assertEqual(normalized, {})

    @patch("logic_engine.observer.blackboard")
    @patch("logic_engine.observer.audit_logger")
    @patch("socket.socket")
    def test_listen_loop_integration(self, mock_socket, mock_audit, mock_blackboard):
        # Mock socket behavior
        mock_client = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_client
        
        # Simulate receiving one valid event then connection closed
        event_data = json.dumps({"type": "syscall", "syscall": "read"}).encode('utf-8')
        mock_client.recv.side_effect = [event_data, b'']

        # Run observer in a thread so we can stop it
        self.observer.start_listening()
        
        # Give it a moment to process
        time.sleep(0.1)
        self.observer.stop_listening()

        # Verify fact was added to blackboard
        mock_blackboard.add_fact.assert_called()
        args, _ = mock_blackboard.add_fact.call_args
        self.assertEqual(args[0]["type"], "syscall")
        
        # Verify audit log was called
        mock_audit.log_event.assert_called()

if __name__ == "__main__":
    unittest.main()
