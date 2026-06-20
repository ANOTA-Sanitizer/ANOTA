import os
import re
import glob
from logic_engine.utils.logger import audit_logger
from logic_engine.blackboard import blackboard

class KnowledgeScanner:
    def __init__(self, vault_path="../Qbrain/obsidian_vault"):
        self.vault_path = os.path.abspath(vault_path)
        # Handles both standard [[link|alias]] and escaped [[link\|alias]]
        self.wiki_link_pattern = re.compile(r"\[\[([^|\]]+?)(?:\\?\|([^\]]+))?\]\]")
        # Regex to match headings: # Heading, ## Heading, etc.
        self.heading_pattern = re.compile(r"^(#{1,6})\s+(.*)$", re.MULTILINE)

    def scan_vault(self):
        """Scans the vault for files and extracts wiki-links and heading structures."""
        audit_logger.log_event("knowledge_scanner", "scan_vault_start", input_data={"path": self.vault_path})
        
        knowledge_map = {}
        
        # Walk through the vault
        for root, dirs, files in os.walk(self.vault_path):
            for file in files:
                if file.endswith(".md"):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, self.vault_path)
                    knowledge_map[relative_path] = self._process_file(file_path)

        blackboard.update_context("knowledge_map", knowledge_map)
        audit_logger.log_event("knowledge_scanner", "scan_vault_complete", output_data={"file_count": len(knowledge_map)})
        return knowledge_map

    def _process_file(self, file_path):
        """Processes a single file to extract links and headings."""
        content = ""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            audit_logger.log_event("knowledge_scanner", "file_read_error", input_data={"file": file_path}, error=e)
            return {"error": str(e)}

        links = self._extract_links(content)
        headings = self._extract_headings(content)

        return {
            "links": links,
            "headings": headings
        }

    def _extract_links(self, content):
        """Extracts wiki-links from content."""
        links = []
        for match in self.wiki_link_pattern.finditer(content):
            target = match.group(1).strip().rstrip('\\')
            alias = match.group(2).strip() if match.group(2) else target
            links.append({"target": target, "alias": alias})
        return links

    def _extract_headings(self, content):
        """Extracts headings from content."""
        headings = []
        # We use re.finditer to get all matches with their positions if needed, 
        # but for now just a list of headings is enough.
        for match in self.heading_pattern.finditer(content):
            level = len(match.group(1))
            text = match.group(2).strip()
            headings.append({"level": level, "text": text})
        return headings

    def get_content_by_heading(self, file_path, heading_text):
        """Extracts content following a specific heading until the next heading of same or higher level."""
        relative_path = os.path.relpath(file_path, self.vault_path)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            audit_logger.log_event("knowledge_scanner", "get_content_error", input_data={"file": file_path, "heading": heading_text}, error=e)
            return None

        start_index = -1
        end_index = len(lines)
        current_level = 0

        # Find the heading
        for i, line in enumerate(lines):
            heading_match = self.heading_pattern.match(line)
            if heading_match:
                if heading_match.group(2).strip() == heading_text:
                    start_index = i + 1
                    current_level = len(heading_match.group(1))
                    break

        if start_index == -1:
            return None

        # Find the end (next heading of same or higher level)
        for i in range(start_index, len(lines)):
            heading_match = self.heading_pattern.match(lines[i])
            if heading_match:
                new_level = len(heading_match.group(1))
                if new_level <= current_level:
                    end_index = i
                    break

        return "".join(lines[start_index:end_index]).strip()

# Global instance
knowledge_scanner = KnowledgeScanner()
