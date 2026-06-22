import subprocess
import os
import json
import re
import tempfile
from .coverage_parser import PHPXdebugParser

class PHPRunner:
    """
    Executes PHP scripts with Xdebug instrumentation and extracts telemetry data.
    """
    def __init__(self, php_bin="php"):
        self.php_bin = php_bin
        self.parser = PHPXdebugParser()
        self.instrument_script = os.path.join(
            os.path.dirname(__file__), "instrument.php"
        )

    def run(self, script_path, args=None, env=None):
        """
        Runs a PHP script and returns the parsed telemetry.
        """
        if args is None:
            args = []
        
        # Use a temporary file for telemetry to avoid stdout pollution
        fd, temp_path = tempfile.mkstemp(suffix=".json", prefix="anota_telemetry_")
        os.close(fd)

        # Merge custom env if provided
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        
        run_env["ANOTA_TELEMETRY_TARGET"] = temp_path
        # Also provide the observer socket path if it's not already set
        if "ANOTA_OBSERVER_SOCKET" not in run_env:
            run_env["ANOTA_OBSERVER_SOCKET"] = "/tmp/anota_telemetry.sock"
        
        # Command to run PHP with auto-prepend
        cmd = [
            self.php_bin,
            "-d", f"auto_prepend_file={self.instrument_script}",
            "-d", "xdebug.mode=coverage",
            script_path
        ] + args
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=run_env
            )
            
            # Try reading from file first
            if os.path.exists(temp_path) and os.path.getsize(temp_path) > 0:
                with open(temp_path, "r") as f:
                    try:
                        raw_telemetry = json.load(f)
                        return self._process_raw_telemetry(raw_telemetry)
                    except json.JSONDecodeError:
                        pass # Fallback to stdout parsing
            
            # Fallback to stdout parsing (e.g. if file_put_contents failed)
            return self._extract_telemetry_from_stdout(result.stdout)
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _process_raw_telemetry(self, raw_telemetry):
        """
        Processes the raw dictionary from PHP into the final telemetry format.
        """
        # Parse coverage part using existing parser
        coverage_data = self.parser.parse_raw_data(raw_telemetry.get("coverage", {}))
        
        # Enrich with state
        coverage_data["state"] = raw_telemetry.get("state", {})
        return coverage_data

    def _extract_telemetry_from_stdout(self, output):
        """
        Extracts the JSON telemetry block from the raw PHP output (fallback).
        """
        pattern = r"---ANOTA_TELEMETRY_START---\n(.*?)\n---ANOTA_TELEMETRY_END---"
        match = re.search(pattern, output, re.DOTALL)
        
        if not match:
            return {"type": "telemetry", "files": {}, "state": {}, "error": "No telemetry found"}

        try:
            raw_telemetry = json.loads(match.group(1))
            return self._process_raw_telemetry(raw_telemetry)
        except json.JSONDecodeError:
            return {"type": "telemetry", "error": "Failed to decode telemetry JSON"}
