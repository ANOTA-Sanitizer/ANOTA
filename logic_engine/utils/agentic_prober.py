import os
import json
import asyncio
import re
import glob
import logging
from typing import Any, Dict, List, Optional
from logic_engine.agent_config import AgentConfig
from langchain_core.messages import HumanMessage, SystemMessage
from logic_engine.utils.semantic_reader import SemanticReader

# Configure local logger
logger = logging.getLogger(__name__)

class AgenticProber:
    """
    Uses an LLM to intelligently probe files for security-relevant information
    without reading the entire file.
    
    Now enhanced with context-awareness to use environmental prerequisites.
    """

    def __init__(self, model_type: str = "reasoning", prefix: Optional[str] = None):
        self.llm = AgentConfig.get_llm(model_type=model_type)
        self.reader = SemanticReader()
        self.prefix = prefix

    async def probe_file_for_vulnerabilities(
        self, 
        file_path: str, 
        target_areas: List[str], 
        context: Optional[Dict[str, Any]] = None,
        rel_path: Optional[str] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Probes a file for specific types of vulnerabilities and leads using semantic analysis.
        
        Args:
            file_path: Absolute path to the file.
            target_areas: List of vulnerability types to look for.
            context: Environmental context (e.g., DB type, auth requirements).
            rel_path: Optional relative path for findings.
        """
        results = {"findings": [], "leads": []}
        
        # 1. Get a high-level overview (first 100 lines) to understand context
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                context_snippet = "".join(lines[:100])
        except Exception as e:
            logger.error(f"Error reading file for probe: {e}")
            return results
        
        if not context_snippet:
            return results
        
        # Build a system prompt that incorporates the environmental context
        system_prompt_parts = [
            "You are a professional security researcher conducting a deep-dive technical analysis. "
            "Your task is to identify technical traces and suspicious data flows that constitute potential vulnerabilities or interesting leads. "
            "STRICT RULE: DO NOT provide 'best practice' advice, 'refactoring suggestions', or 'deprecation warnings'. "
            "Your output must focus on WHAT IS THERE and HOW IT FLOWS, not how it SHOULD be. "
            "\n\n"
            "Output MUST be a single JSON object with two keys: 'findings' and 'leads'.\n"
            "Each list should contain objects following these schemas:\n\n"
            "Findings:\n"
            "- 'type': The technical category (e.g., 'SQL Injection', 'XSS', 'Unsanitized Input').\n"
            "- 'description': A precise technical observation of the vulnerability (e.g., 'User-controlled $_GET[id] flows directly into mysqli_query').\n"
            "- 'line_range': The estimated line numbers (e.g., [10, 15]).\n"
            "- 'confidence': A score from 0.0 to 1.0.\n"
            "- 'intent': Your objective for this probe.\n"
            "- 'assumptions': Technical assumptions made (e.g., ['$conn is a mysqli object']).\n"
            "- 'information_gaps': Missing information needed to confirm this finding (e.g., ['definition of $conn']).\n"
            "- 'resolution_strategy': How to close the gaps (e.g., ['Trace $conn initialization']).\n\n"
            "Leads:\n"
            "- 'type': The lead type (e.g., LEAD_FUNCTION_CALL, LEAD_FILE_INCLUDE).\n"
            "- 'description': A technical description of why this is a suspicious junction for tracing.\n"
            "- 'pivot_target': The function name, variable, or file to investigate.\n"
            "- 'line_range': The estimated line numbers (e.g., [10, 15]).\n"
            "- 'confidence': A score from 0.0 to 1.0.\n"
            "- 'intent': Your objective for tracing this lead.\n"
            "- 'assumptions': Technical assumptions made.\n"
            "- 'information_gaps': Missing information needed to resolve this lead.\n"
            "- 'resolution_strategy': How to resolve the gap (e.g., ['Search codebase for definition of pivot_target']).\n"
        ]
        
        if context:
            system_prompt_parts.append("\n\n### Environmental Context (IMPORTANT)")
            system_prompt_parts.append("The following environmental facts are known about the target system:")
            for key, value in context.items():
                system_prompt_parts.append(f"- {key}: {value}")
            system_prompt_parts.append("\nUse this context to refine your analysis (e.g., prioritize MySQL payloads if the DB is MySQL).")
        
        system_prompt = "\n".join(system_prompt_parts)
        
        user_prompt = (
            f"File: {file_path}\n"
            f"Target Areas: {', '.join(target_areas)}\n\n"
            f"Code Snippet:\n{context_snippet}\n\n"
            "Identify vulnerabilities matching the target areas and suspicious leads. If none are found, return {'findings': [], 'leads': []}. "
            "Remember: NO ADVICE. ONLY TECHNICAL TRACES."
        )
        
        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            # Log the LLM call for transparency
            from logic_engine.utils.logger import audit_logger
            audit_logger.log_llm_call(
                agent_id=self.prefix or "agentic_prober",
                component="probe_file_for_vulnerabilities",
                prompt=user_prompt,
                response=str(response.content) if hasattr(response, 'content') else str(response)
            )
            
            raw_data = response.content if isinstance(response.content, list) else []
            if isinstance(response.content, str):
                try:
                    raw_data = json.loads(response.content)
                except json.JSONDecodeError:
                    # Handle cases where LLM might return markdown-wrapped JSON
                    if "```json" in response.content:
                        json_str = re.search(r"```json\n(.*?)\n```", response.content, re.DOTALL)
                        if json_str:
                            raw_data = json.loads(json_str.group(1))
                    else:
                        raw_data = {"findings": [], "leads": []}
            
            if isinstance(raw_data, dict):
                # Validate findings
                for f in raw_data.get("findings", []):
                    if all(k in f for k in ("type", "description", "line_range", "confidence")):
                        f["file"] = rel_path if rel_path else file_path
                        results["findings"].append(f)
                
                # Validate leads
                for l in raw_data.get("leads", []):
                    if all(k in l for k in ("type", "description", "pivot_target", "line_range", "confidence")):
                        l["file"] = rel_path if rel_path else file_path
                        results["leads"].append(l)
            
            return results
        except Exception as e:
            logger.error(f"Error in probe_file_for_vulnerabilities: {e}")
            return {"findings": [], "leads": []}




    async def probe_for_context(self, file_path: str, query: str) -> str:
        """
        Uses the LLM to find specific technical context within a file.
        """
        try:
            file_size = os.path.getsize(file_path)
            if file_size < 10000: # < 10KB
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    content = "".join(lines[:200])
        except Exception as e:
            return f"Error probing context: {e}"

        system_prompt = (
            "You are a technical context extraction agent. Your task is to answer questions "
            "about a specific piece of code. Provide a concise, accurate response based "
            "ONLY on the provided code."
        )

        user_prompt = f"Code:\n{content}\n\nQuestion: {query}"

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            # Log the LLM call for transparency
            from logic_engine.utils.logger import audit_logger
            audit_logger.log_llm_call(
                agent_id=self.prefix or "agentic_prober",
                component="probe_for_context",
                prompt=user_prompt,
                response=str(response.content) if hasattr(response, 'content') else str(response)
            )

            return response.content
        except Exception as e:
            return f"Error probing context: {e}"

    async def extract_aku(self, content: str, rel_path: str, heading_text: str) -> Optional[Dict[str, Any]]:
        """
        Uses an LLM to extract an Atomic Knowledge Unit (AKU) from a piece of content.
        """
        system_prompt = (
            "You are a knowledge extraction agent. Your task is to transform a section of text "
            "from a documentation vault into a single, self-contained Atomic Knowledge Unit (AKU). "
            "\n\n"
            "An AKU must be a single, high-density fact or rule. It should be understandable "
            "without reading the surrounding text. "
            "\n\n"
            "Output must be a JSON object with these keys: "
            "- 'id': A unique, slug-style identifier (e.g., 'rule_sql_injection_low')."
            "- 'title': A concise, descriptive title."
            "- 'content': The actual rule or fact in a clear, imperative sentence."
            "- 'tags': A list of relevant tags (e.g., ['sql_injection', 'low_security', 'php'])."
            "- 'source': The context of the source (e.g., 'file: vulnerabilities/sqli/source/low.php | heading: Rule')."
        )

        user_prompt = (
            f"Source File: {rel_path}\n"
            f"Heading: {heading_text}\n\n"
            f"Content:\n{content}\n\n"
            "Extract one AKU from this content. If the content does not contain a clear rule, "
            "fact, or instruction, return null."
        )

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            # Log the LLM call for transparency
            from logic_engine.utils.logger import audit_logger
            audit_logger.log_llm_call(
                agent_id="agentic_knowledge_scanner",
                component="extract_aku",
                prompt=user_prompt,
                response=str(response.content) if hasattr(response, 'content') else str(response)
            )

            aku = response.content
            if isinstance(aku, str):
                try:
                    aku = json.loads(aku)
                except json.JSONDecodeError:
                    # Handle cases where LLM might return markdown-wrapped JSON
                    if "```json" in aku:
                        json_str = re.search(r"```json\n(.*?)\n```", aku, re.DOTALL)
                        if json_str:
                            aku = json.loads(json_str.group(1))
                    else:
                        return None
            
            if isinstance(aku, dict) and all(k in aku for k in ("id", "title", "content", "tags", "source")):
                return aku
            
        except Exception as e:
            # print(f"Error extracting AKU: {e}")
            pass
            
        return None

    async def extract_akus_from_headings(self, file_path: str, rel_path: str, headings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extracts multiple AKUs from a list of provided headings in a file.
        """
        akus = []
        for heading in headings:
            content = self.reader.read_by_heading(file_path, heading["text"])
            if not content:
                continue
            
            aku = await self.extract_aku(content, rel_path, heading["text"])
            if aku:
                if "source" not in aku:
                     aku["source"] = f"file: {rel_path} | heading: {heading['text']}"
                akus.append(aku)
        return akus
