import os
from typing import List, Dict, Any, Optional
from logic_engine.knowledge_scanner import KnowledgeScanner, StructuralIndex
from logic_engine.utils.logger import audit_logger

class AgenticKnowledgeScanner(KnowledgeScanner):
    """
    Advanced knowledge scanner that uses semantic chunking to extract 
    Atomic Knowledge Units (AKUs) even when they don't align with 
    formal Markdown headings.
    """

    def __init__(self, vault_path: str, prefix: Optional[str] = None):
        super().__init__(vault_path, prefix)

    async def scan_with_semantic_chunking(self, target_rel_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Performs a semantic scan of specified files.
        """
        all_akus = []
        audit_logger.log_event("agentic_knowledge_scanner", "semantic_scan_start", input_data={"path_count": len(target_rel_paths)})

        for rel_path in target_rel_paths:
            full_path = os.path.join(self.vault_path, rel_path)
            if not os.path.exists(full_path):
                continue

            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # 1. Use the agent to find semantic boundaries/chunks
                chunks = await self._get_semantic_chunks(content, rel_path)
                
                # 2. Extract AKUs from each chunk
                for chunk in chunks:
                    aku = await self.prober.extract_aku(
                        chunk["content"], 
                        rel_path, 
                        chunk["context"]
                    )
                    if aku:
                        # Ensure source context is rich
                        if "source" not in aku:
                            aku["source"] = f"file: {rel_path} | chunk: {chunk['context'][:50]}..."
                        all_akus.append(aku)

            except Exception as e:
                audit_logger.log_event("agentic_knowledge_scanner", "chunking_error", input_data={"file": rel_path}, error=str(e))

        audit_logger.log_event("agentic_knowledge_scanner", "semantic_scan_complete", output_data={"akus_found": len(all_akus)})
        return all_akus
