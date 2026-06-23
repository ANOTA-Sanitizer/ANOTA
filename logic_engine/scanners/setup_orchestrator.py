import os
import asyncio
from typing import Dict, Any

class TargetSetupOrchestrator:
    """
    Orchestrates the setup of a target environment for dynamic testing.
    Detects the environment (Docker, Local PHP, etc.) and executes setup commands.
    """

    def __init__(self, target_root: str):
        self.target_root = os.path.abspath(target_root)

    async def setup(self) -> Dict[str, Any]:
        """
        Attempts to set up the target environment.
        Returns a dictionary containing the status and details of the setup.
        """
        results = {
            "status": "not_started",
            "method": None,
            "command": None,
            "output": "",
            "error": None
        }

        # 1. Check for Docker (compose.yml or docker-compose.yml)
        docker_compose_file = self._find_docker_compose()
        if docker_compose_file:
            results["method"] = "docker"
            results["command"] = "docker compose up -d"
            working_dir = os.path.dirname(docker_compose_file)
            return await self._run_command(results, ["docker", "compose", "up", "-d"], working_dir)

        # 2. Check for Local PHP setup (e.g., DVWA setup.php)
        php_setup_file = self._find_php_setup()
        if php_setup_file:
            results["method"] = "php_local"
            results["command"] = f"php {os.path.basename(php_setup_file)}"
            working_dir = os.path.dirname(php_setup_file)
            return await self._run_command(results, ["php", os.path.basename(php_setup_file)], working_dir)

        # If no setup method found
        results["status"] = "skipped"
        return results

    def _find_docker_compose(self) -> str:
        for filename in ["compose.yml", "docker-compose.yml", "compose.yaml", "docker-compose.yaml"]:
            path = os.path.join(self.target_root, filename)
            if os.path.exists(path):
                return path
        return None

    def _find_php_setup(self) -> str:
        for root, _, files in os.walk(self.target_root):
            if "setup.php" in files:
                return os.path.join(root, "setup.php")
        return None

    async def _run_command(self, results: Dict[str, Any], cmd: list[str], working_dir: str) -> Dict[str, Any]:
        results["status"] = "running"
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=working_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()
            
            results["output"] = stdout.decode().strip()
            if stderr:
                results["error"] = stderr.decode().strip()

            if process.returncode == 0:
                results["status"] = "success"
            else:
                results["status"] = "failed"

        except Exception as e:
            results["status"] = "failed"
            results["error"] = str(e)

        return results
