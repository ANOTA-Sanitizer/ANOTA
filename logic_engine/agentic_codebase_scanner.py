import os
import json
import re
from typing import List, Dict, Any, Optional
from logic_engine.codebase_scanner import CodebaseScanner
from logic_engine.utils.logger import audit_logger

class AgenticCodebaseScanner(CodebaseScanner):
    """
    Advanced codebase scanner that uses the 'Probe-and-Synthesize' pattern.
    It identifies suspected vulnerable areas, probes them with context-aware payloads,
    and then synthesizes the findings into high-fidelity Code Facts.
    """

    async def scan_and_synthesize(self, knowledge_index: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Performs the full probe-and-synthesize workflow.
        """
        audit_logger.log_event("agentic_codebase_scanner", "scan_synthesize_start", input_data={"path": self.target_path})
        
        # 1. Run the baseline scan to identify potential entrypoints and attack surfaces
        baseline_results = await self.scan(knowledge_index=knowledge_index)
        
        code_facts = []
        
        # 2. Deep-dive into identified attack surface areas
        attack_surface = baseline_results.get("attack_surface", [])
        
        print(f"[*] Found {len(attack_surface)} potential findings in baseline scan. Starting deep-dive synthesis...")

        # We'll group findings by file to avoid redundant probes
        findings_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for finding in attack_surface:
            f_path = finding["file"]
            if f_path not in findings_by_file:
                findings_by_file[f_path] = []
            findings_by_file[f_path].append(finding)

        for rel_path, file_findings in findings_by_file.items():
            full_path = os.path.join(self.target_path, rel_path)
            if not os.path.exists(full_path):
                continue

            print(f"    [>] Synthesizing facts for {rel_path}...")
            
            # 3. Synthesize findings into Code Facts
            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code_content = f.read()
                
                # We now synthesize MULTIPLE facts per file to avoid the "one-fact-per-file" limitation
                new_facts = await self._synthesize_code_facts(rel_path, code_content, file_findings, knowledge_index)
                if new_facts:
                    code_facts.extend(new_facts)
            except Exception as e:
                audit_logger.log_event("agentic_codebase_scanner", "synthesis_error", input_data={"file": rel_path}, error=str(e))

        audit_logger.log_event("agentic_codebase_scanner", "scan_synthesize_complete", output_data={"facts_found": len(code_facts)})
        return code_facts



    async def _synthesize_code_facts(self, rel_path: str, code_content: str, findings: List[Dict[str, Any]], knowledge_index: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Uses an LLM to synthesize code structure and probe findings into a list of structured Code Facts.
        """
        system_prompt = (
            "You are a senior security researcher. Your task is to synthesize code analysis and "
            "vulnerability probe results into a list of high-fidelity 'Code Facts'. "
            "\n\n"
            "A Code Fact must be a single, verifiable technical observation that captures the full context of a vulnerability. "
            "\n\n"
            "Output must be a JSON list of objects, where each object represents a unique finding with these keys: "
            "- 'id': A unique, slug-style identifier (e.g., 'fact_sqli_vulnerabilities_api_user_php')."
            "- 'type': The category (e.g., 'vulnerability', 'sink', 'source', 'sanitizer')."
            "- 'description': A technical, precise explanation of the vulnerability."
            "- 'attack_surface': A structured object describing how to trigger it: { 'endpoint': '...', 'parameter': '...', 'method': '...' }."
            "- 'data_flow_path': A logical sequence of code locations: [ {'file': '...', 'line': 10, 'action': '...'}, ... ]."
            "- 'evidence_chain': A concise list of string observations (e.g., ['Source: $_GET[id]', 'Sink: mysqli_query', 'Missing: sanitization'])."
            "- 'location': The file and line number(s) where the sink is located."
            "- 'confidence': A score from 0.0 to 1.0."
            "- 'knowledge_context': A summary of relevant security rules or business logic from the knowledge vault that applies to this finding."
        )

        # We provide a summarized version of the findings to stay within token limits
        findings_summary = []
        for f in findings:
            findings_summary.append({
                "type": f["type"],
                "line_range": f["line_range"],
                "snippet": f.get("snippet", ""),
                "method": f.get("method", "static")
            })

        relevant_knowledge_str = "No knowledge context available."
        if knowledge_index:
            relevant_knowledge = []
            types = set(f["type"] for f in findings_summary)
            for t in types:
                relevant_files = knowledge_index.find_relevant_files(t)
                for rv in relevant_files:
                    structure = knowledge_index.get_file_structure(rv)
                    if structure:
                        relevant_knowledge.append(f"File: {rv}, Headings: {[h['text'] for h in structure.get('headings', [])]}")
            
            if relevant_knowledge:
                relevant_knowledge_str = "\n".join(relevant_knowledge)

        user_prompt = (
            f"Source File: {rel_path}\n\n"
            f"Code Content:\n{code_content[:5000]}\n\n"
            f"Initial Findings:\n{json.dumps(findings_summary, indent=2)}\n\n"
            f"Relevant Knowledge Context:\n{relevant_knowledge_str}\n\n"
            "Synthesize these into a list of high-fidelity Code Facts. If no valid findings are present, return an empty list []."
        )

        try:
            response = await self.prober.llm.ainvoke([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ])
            
            raw_fact_data = response.content if hasattr(response, 'content') else str(response)
            
            # Parse JSON from response
            facts = []
            if isinstance(raw_fact_data, str):
                if "```json" in raw_fact_data:
                    json_match = re.search(r"```json\n(.*?)\n```", raw_fact_data, re.DOTALL)
                    if json_match:
                        facts = json.loads(json_match.group(1))
                else:
                    try:
                        facts = json.loads(raw_fact_data)
                    except json.JSONDecodeError:
                        # Try to find any JSON-like structure
                        json_match = re.search(r"\[.*\]|\{.*\}", raw_fact_data, re.DOTALL)
                        if json_match:
                            try:
                                facts = json.loads(json_match.group(0))
                            except json.JSONDecodeError:
                                return []
                        else:
                            return []
            elif isinstance(raw_fact_data, list):
                facts = raw_fact_data
            
            # If the LLM wrapped the list in a dictionary like {"code_facts": [...]}
            if isinstance(facts, dict) and "code_facts" in facts:
                facts = facts["code_facts"]

            print(f"        [DEBUG] LLM Raw Response: {raw_fact_data}")
            print(f"        [DEBUG] Parsed Facts: {facts}")

            if not isinstance(facts, list):
                return []



            # Validation and cleanup
            valid_facts = []
            required_keys = ("id", "type", "description", "attack_surface", "data_flow_path", "location", "confidence")
            for f in facts:
                if isinstance(f, dict) and all(k in f for k in required_keys):
                    valid_facts.append(f)
                else:
                    print(f"        [DEBUG] Fact missing keys! Found: {list(f.keys()) if isinstance(f, dict) else type(f)}")
            
            return valid_facts

            
        except Exception as e:
            audit_logger.log_event("agentic_codebase_scanner", "synthesis_llm_error", error=str(e))
            return []
