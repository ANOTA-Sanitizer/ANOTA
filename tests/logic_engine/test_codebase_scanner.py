import unittest
import os
import tempfile
import shutil
from logic_engine.codebase_scanner import CodebaseScanner

class TestCodebaseScanner(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Create a temp directory structure
        self.test_dir = tempfile.mkdtemp()
        self.target_path = os.path.join(self.test_dir, "target")
        self.external_path = os.path.join(self.test_dir, "external")
        self.rules_path = os.path.join(self.test_dir, "rules")
        
        os.makedirs(self.target_path)
        os.makedirs(self.external_path)
        os.makedirs(self.rules_path)
        
        # Create a safe file inside target
        self.safe_file = os.path.join(self.target_path, "index.php")
        with open(self.safe_file, "w") as f:
            f.write("<?php echo 'hello'; mysql_connect(); ?>")
            
        # Create an unsafe file outside target
        self.unsafe_file = os.path.join(self.external_path, "secret.php")
        with open(self.unsafe_file, "w") as f:
            f.write("<?php echo 'secret'; ?>")

    async def asyncTearDown(self):
        shutil.rmtree(self.test_dir)

    async def test_scan_finds_safe_files(self):
        scanner = CodebaseScanner(self.target_path, self.rules_path)
        results = await scanner.scan()
        
        entrypoints = [e["path"] for e in results["entrypoints"]]
        self.assertIn("index.php", entrypoints)
        # Note: results["technical_context"] might not have 'db_type' if not matched exactly
        # In the current implementation, it depends on the regex.
        # Let's see what it actually produces.

    async def test_scan_confines_to_target_path(self):
        # Add a symlink pointing outside target_path
        symlink_path = os.path.join(self.target_path, "linked_secret.php")
        try:
            os.symlink(self.unsafe_file, symlink_path)
        except OSError:
            # Skip if symlink creation is not supported/allowed on the platform/OS configuration
            self.skipTest("Symlinks not supported/allowed")

        scanner = CodebaseScanner(self.target_path, self.rules_path)
        results = await scanner.scan()
        
        entrypoints = [e["path"] for e in results["entrypoints"]]
        # The symlink is outside target_path after realpath resolution, so it must be skipped!
        self.assertNotIn("linked_secret.php", entrypoints)

if __name__ == "__main__":
    unittest.main()
