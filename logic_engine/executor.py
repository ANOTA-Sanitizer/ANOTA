import os
import tempfile
import json
import subprocess
import asyncio
import re
from typing import Any, Dict, Optional
from logic_engine.utils.logger import logger
from logic_engine.utils.payload_generator import PayloadGenerator

class PHPRunner:
    """Runs PHP scripts and captures their output."""
    def run(self, file_path: str) -> Dict[str, Any]:
        try:
            result = subprocess.run(['php', file_path], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Try to parse JSON if it looks like JSON
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {"status": "success", "output": result.stdout}
            else:
                return {"status": "error", "message": result.stderr}
        except Exception as e:
            return {"status": "error", "message": str(e)}

class Executor:
    """
    Executes security payloads against a target.
    """
    def __init__(self, base_url: str = "http://localhost/dvwa"):
        self.php_runner = PHPRunner()
        self.payload_generator = PayloadGenerator()
        self.base_url = base_url.rstrip('/')

    async def run_payload(self, challenge: Dict[str, Any], codebase: Any, target_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes a payload against the target.
        """
        target_str = challenge.get("target", "")
        description = challenge.get("description", "")
        v_type = challenge.get("type", "unknown")
        
        if not target_str:
            return {"status": "error", "message": "No target specified in challenge"}
        
        # 1. Parse target (e.g., "vulnerabilities/api/index.php:42")
        try:
            if ":" in target_str:
                file_rel_path, line_num = target_str.split(":")
                line_num = int(line_num)
            else:
                file_rel_path = target_str
                line_num = None
        except ValueError:
            return {"status": "error", "message": f"Invalid target format: {target_str}"}
        
        # 2. Generate Payload
        try:
            payload = await self.payload_generator.generate_payload(v_type, {
                "file": file_rel_path,
                "line": line_num,
                "description": description
            }, target_config=target_config)
            
            # If the payload is wrapped in a dict (as seen in test), extract it
            if isinstance(payload, dict) and "payload" in payload:
                payload = payload["payload"]
        except Exception as e:
            return {"status": "error", "message": f"Failed to generate payload: {str(e)}"}
        
        if not payload:
            return {"status": "error", "message": "Generated payload is empty"}


        # 3. Execute simulation (using PHP runner to simulate a web request)
        # We create a wrapper script that sets up the environment (like $_GET) and then includes the target.
        
        # We'll assume the target is relative to the project root (the codebase path)
        # The codebase path is passed via the orchestrator/executor context.
        # For now, we'll try to find the target file in the current working directory or relative to it.
        # In the tests, the repo_path is provided.
        
        target_full_path = file_rel_path # This is a relative path from the project root
        
        # Since we are in a headless environment, we simulate the HTTP request by running a PHP script
        # that populates $_GET/$_POST and then includes the target file.
        
        wrapper_content = f"""<?php
// Simulated Web Request for {target_str}
// Payload: {payload}

$_GET['id'] = "{payload}";
$_GET['input'] = "{payload}";
$_GET['user'] = "{payload}";
$_GET['q'] = "{payload}";

require_once "{target_full_path}";
?>
"""
        
        try:
            with tempfile.NamedTemporaryFile(suffix=".php", mode='w', delete=False) as tmp:
                tmp.write(wrapper_content)
                tmp_path = tmp.name

            logger.info(f"    [>] Running simulated payload on {target_full_path} via wrapper: {tmp_path}")
            
            # Run the wrapper script
            telemetry = self.php_runner.run(tmp_path)
            
            return {
                "status": "success",
                "telemetry": telemetry,
                "location": {
                    "file": file_rel_path,
                    "line_range": [line_num, line_num] if line_num else None
                }
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "location": {
                    "file": file_rel_path,
                    "line_range": [line_num, line_num] if line_num else None
                }
            }
        finally:
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except:
                    pass
