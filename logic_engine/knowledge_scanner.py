import os
import re
import glob
import asyncio
from typing import List, Dict, Any, Optional
from logic_engine.utils.logger import audit_logger
from logic_engine.utils.semantic_reader import SemanticReader
from logic_engine.utils.agentic_prober import AgenticProber

class StructuralIndex(dict):
    """Represents a lightweight structural index of the knowledge vault."""
    @property
    def files(self) -> Dict[str, Dict[str, Any]]:
        return self

    def add_file(self, rel_path: str, structure: Dict[str, Any]):
        self[rel_path] = structure

    def get_file_structure(self, rel_path: str) -> Optional[Dict[str, Any]]:
        return self.get(rel_path)

    def find_relevant_files(self, keyword: str) -> List[str]:
        """Finds files whose names or headings might match a keyword."""
        matches = []
        for rel_path, structure in self.items():
            if keyword.lower() in rel_path.lower():
                matches.append(rel_path)
            else:
                for heading in structure.get("headings", []):
                    if keyword.lower() in heading["text"].lower():
                        matches.append(rel_path)
                        break
        return matches

class KnowledgeScanner:
    """
    Scans a target codebase to identify entrypoints, technical context, and attack surface.
    Uses RAG (Retrieval-Augmented Generation) to enrich findings with knowledge from an Obsidian vault.
    Uses ContextManager to build a semantic model of environmental requirements.
    """

    def __init__(self, vault_path: str):
        self.vault_path = os.path.abspath(vault_path)
        self.reader = SemanticReader()
        self.prober = AgenticProber()
        self.wiki_link_pattern = re.compile(r"\[\[([^|\]]+?)(?:\\?\|([^\]]+))?\]\]")
        self.heading_pattern = re.compile(r"^(#{1,6})\s+(.*)$", re.MULTILINE)

    async def scan_relevant_vault(self, entrypoints: Any) -> StructuralIndex:
        """
        Performs a targeted scan of the knowledge vault.
        Instead of scanning everything, it only performs agentic enrichment on files
        defined as entrypoints in behavior files.
        """
        if isinstance(entrypoints, dict):
            entrypoints = list(entrypoints.values())
        elif not isinstance(entrypoints, list):
            entrypoints = []

        audit_logger.log_event("knowledge_scanner", "scan_relevant_vault_start", input_data={"entrypoint_count": len(entrypoints)})
        
        # 1. Structural Scan (build the lightweight index)
        index = self._structural_scan()
        
        # 2. Targeted Agentic Enrichment
        # We want to find AKUs (Atomic Knowledge Units) for the relevant entrypoints.
        # We'll attach these AKUs to the index.
        print("[*] Starting targeted agentic enrichment of behavior entrypoints...")
        
        # Identify which rel_paths in knowledge_map correspond to behavior entrypoints
        target_rel_paths = []
        for entrypoint in entrypoints:
            e_path = entrypoint["path"]
            # Transform codebase path to vault relative path
            # e.g. vulnerabilities/api/index.php -> files/vulnerabilities_api_index_php.md
            v_rel_path = f"files/{e_path.replace('/', '_').replace('.', '_')}.md"
            if index.get_file_structure(v_rel_path):
                target_rel_paths.append(v_rel_path)
        
        print(f"    [+] Targeted {len(target_rel_paths)} files for enrichment out of {len(index.files)} total files in index.")
        
        # Enrich the index with AKUs for the target files
        await self._agentic_enrichment(index, target_rel_paths)
        
        audit_logger.log_event("knowledge_scanner", "scan_relevant_vault_complete", output_data={
            "file_count": len(index.files), 
            "akus_count": sum(len(index.get_file_structure(fp).get("akus", [])) for fp in index.files)
        })
        return index

    async def scan_vault(self) -> StructuralIndex:
        """Performs a full scan of the knowledge vault."""
        return await self.scan_relevant_vault([])

    def _structural_scan(self) -> StructuralIndex:
        """Rapidly builds the structural map of the vault."""
        index = StructuralIndex()
        for root, dirs, files in os.walk(self.vault_path):
            for file in files:
                if file.endswith(".md"):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.vault_path)
                    structure = self._process_file(file_path)
                    if structure:
                        index.add_file(rel_path, structure)
        return index

    def _process_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Extracts basic structure from a file."""
        content = ""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            audit_logger.log_event("knowledge_scanner", "file_process_error", input_data={"file": file_path}, error=str(e))
            return None
        
        return {
            "links": self._extract_links(content),
            "headings": self._extract_headings(content),
            "akus": [] # To be populated during enrichment
        }

    def _extract_links(self, content: str) -> List[Dict[str, str]]:
        links = []
        for match in self.wiki_link_pattern.finditer(content):
            target = match.group(1).strip()
            target = target.rstrip('\\')
            alias = match.group(2).strip() if match.group(2) else target
            links.append({"target": target, "alias": alias})
        return links

    def _extract_headings(self, content: str) -> List[Dict[str, Any]]:
        headings = []
        for match in self.heading_pattern.finditer(content):
            level = len(match.group(1))
            text = match.group(2).strip()
            headings.append({"level": level, "text": text})
        return headings

    async def _agentic_enrichment(self, index: StructuralIndex, target_rel_paths: Optional[List[str]] = None) -> None:
        """Uses the LLM to extract Atomic Knowledge Units (AKUs) from headings."""
        paths_to_scan = target_rel_paths if target_rel_paths is not None else list(index.keys())
        
        for rel_path in paths_to_scan:
            structure = index.get_file_structure(rel_path)
            if not structure or not structure.get("headings"):
                continue
                
            full_path = os.path.join(self.vault_path, rel_path)
            
            for heading in structure["headings"]:
                # Extract AKU from the specific heading content
                content = self.reader.read_by_heading(full_path, heading["text"])
                if not content:
                    continue
                
                # Extract AKU from the specific heading content
                aku = await self.prober.extract_aku(content, rel_path, heading["text"])
                if aku:
                    # Ensure the AKU has its source context
                    if "source" not in aku:
                         aku["source"] = f"file: {rel_path} | heading: {heading['text']}"
                    structure["akus"].append(aku)

# Global instance
knowledge_scanner = KnowledgeScanner("/home/kali/Desktop/Qbrain/obsidian_vault")
