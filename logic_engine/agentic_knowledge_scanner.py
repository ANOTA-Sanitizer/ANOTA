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

    async def _get_semantic_chunks(self, content: str, rel_path: str) -> List[Dict[str, Any]]:
        """
        Uses the LLM to identify logically distinct semantic chunks within the text.
        """
        system_prompt = (
            "You are a semantic analysis agent. Your task is to decompose a text into a list of "
            "logically distinct, self-contained semantic chunks. Each chunk should represent a "
            "single coherent idea, rule, or piece of information. "
            "\n\n"
            "Output must be a JSON list of objects, each with these keys: "
            "- 'content': The actual text of the chunk. "
            "- 'context': A short, descriptive summary of what this chunk is about (e.g., 'Definition of X', 'Security Rule for Y')."
        )
        
        user_prompt = f"Source File: {rel_path}\n\nText to chunk:\n{content}"

        try:
            response = await self.prober.llm.ainvoke([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ])
            
            raw_content = response.content if hasattr(response, 'content') else str(response)
            
            # Parse JSON from response
            chunks = []
            if "```json" in raw_content:
                import re
                json_match = re.search(r"```json\n(.*?)\n```", raw_content, re.DOTALL)
                if json_match:
                    import json
                    chunks = json.loads(json_match.group(1))
            else:
                import json
                try:
                    chunks = json.loads(raw_content)
                except json.JSONDecodeError:
                    # Try to find any JSON-like structure
                    import re
                    json_match = re.search(r"\[.*\]", raw_content, re.DOTALL)
                    if json_match:
                        try:
                            chunks = json.loads(json_match.group(0))
                        except json.JSONDecodeError:
                            pass
            
            # Validate chunks
            valid_chunks = []
            for c in chunks:
                if isinstance(c, dict) and "content" in c and "context" in c:
                    valid_chunks.append(c)
            
            return valid_chunks

        except Exception as e:
            audit_logger.log_event("agentic_knowledge_scanner", "chunking_llm_error", error=str(e))
            return []
