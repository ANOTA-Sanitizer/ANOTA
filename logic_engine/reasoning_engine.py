import json
import logging
import asyncio
import os
from typing import List, Dict, Any, Optional
from logic_engine.agent_config import AgentConfig
from logic_engine.blackboard import blackboard
from logic_engine.utils.logger import audit_logger
from langchain_core.messages import HumanMessage, SystemMessage
from logic_engine.utils.semantic_reader import SemanticReader

class ReasoningEngine:
    def __init__(self, vault_path: Optional[str] = None):
        self.llm = AgentConfig.get_llm(model_type="reasoning")
        self.logger = logging.getLogger("ReasoningEngine")
        self.vault_path = vault_path
        self.reader = SemanticReader() if vault_path else None

    async def generate_hypotheses(self, facts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyzes recent facts to generate new, structured hypotheses.
        """
        if not facts:
            return []

        system_prompt = (
            "You are a specialized security reasoning engine. Your task is to analyze observed facts "
            "and generate structured hypotheses about potential business logic flaws, security vulnerabilities, "
            "or unexpected system behaviors. "
            "\n\n"
            "CRITICAL REQUIREMENT: Every hypothesis must follow a 'Chain-of-Traceability' (Source $\\rightarrow$ Transformation $\\rightarrow$ Sink). "
            "Even at the hypothesis stage, you must propose a plausible logical path for how an attack could succeed. "
            "\n\n"
            "Output must be a JSON list of objects, where each object represents a hypothesis with these keys: "
            "'id' (unique slug), 'description' (clear explanation), 'type' (e.g., CSRF, IDOR, Privilege Escalation, Logic Flaw), "
            "'confidence' (0.0 to 1.0), 'supporting_evidence' (list of fact IDs or descriptions), and 'traceability_path' (a proposed logical flow)."
        )
        
        user_prompt = f"Analyze the following observed facts and generate hypotheses:\n{json.dumps(facts, indent=2)}"

import json
import logging
import asyncio
import os
from typing import List, Dict, Any, Optional
from logic_engine.agent_config import AgentConfig
from logic_engine.blackboard import blackboard
from logic_engine.utils.logger import audit_logger
from langchain_core.messages import HumanMessage, SystemMessage
from logic_engine.utils.semantic_reader import SemanticReader

class ReasoningEngine:
    def __init__(self, vault_path: Optional[str] = None):
        self.llm = AgentConfig.get_llm(model_type="reasoning")
        self.logger = logging.getLogger("ReasoningEngine")
        self.vault_path = vault_path
        self.reader = SemanticReader() if vault_path else None

    async def generate_hypotheses(self, facts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyzes recent facts to generate new, structured hypotheses.
        """
        if not facts:
            return []

        system_prompt = (
            "You are a specialized security reasoning engine. Your task is to analyze observed facts "
            "and generate structured hypotheses about potential business logic flaws, security vulnerabilities, "
            "or unexpected system behaviors. "
            "\n\n"
            "CRITICAL REQUIREMENT: Every hypothesis must follow a 'Chain-of-Traceability' (Source $\\rightarrow$ Transformation $\\rightarrow$ Sink). "
            "Even at the hypothesis stage, you must propose a plausible logical path for how an attack could succeed. "
            "\n\n"
            "Output must be a JSON list of objects, where each object represents a hypothesis with these keys: "
            "'id' (unique slug), 'description' (clear explanation), 'type' (e.g., CSRF, IDOR, Privilege Escalation, Logic Flaw), "
            "'confidence' (0.0 to 1.0), 'supporting_evidence' (list of fact IDs or descriptions), and 'traceability_path' (a proposed logical flow)."
        )
        
        user_prompt = f"Analyze the following observed facts and generate hypotheses:\n{json.dumps(facts, indent=2)}"

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            # Log the LLM call for transparency
            audit_logger.log_llm_call(
                agent_id="reasoning_engine",
                component="generate_hypotheses",
                prompt=user_prompt,
                response=str(response.content) if hasattr(response, 'content') else str(response)
            )
            
            # The response is expected to be a JSON string due to format="json"
            hypotheses = json.loads(response.content)
            
            if isinstance(hypotheses, dict) and "hypotheses" in hypotheses:
                hypotheses = hypotheses["hypotheses"]

            if not isinstance(hypotheses, list):
                self.logger.error(f"LLM did not return a list of hypotheses. Returned type: {type(hypotheses)}, content: {hypotheses}")
                return []


            for hyp in hypotheses:
                blackboard.add_hypothesis(hyp)
            
            audit_logger.log_event("reasoning_engine", "hypotheses_generated", input_data={"count": len(hypotheses)})
            return hypotheses
        except Exception as e:
            self.logger.error(f"Error generating hypotheses: {e}")
            audit_logger.log_event("reasoning_engine", "error", error=str(e))
            return []

    async def evaluate_hypothesis(self, hypothesis_id: str, context_facts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluates a specific hypothesis against new context and facts.
        """
        # Find hypothesis in blackboard
        all_hypotheses = blackboard.get_all()["hypotheses"]
        target_hyp = next((h for h in all_hypotheses if h["content"].get("id") == hypothesis_id), None)
        
        if not target_hyp:
            return {"error": f"Hypothesis {hypothesis_id} not found."}

        hypothesis_content = target_hyp["content"]

        system_prompt = (
            "You are an expert security validator. Evaluate a hypothesis against provided facts. "
            "Determine if the hypothesis is supported, refuted, or remains inconclusive. "
            "\n\n"
            "CRITICAL REQUIREMENT: Your evaluation must validate the proposed 'Chain-of-Traceability'. "
            "Verify if the observed facts actually support the proposed path from Source to Sink. "
            "\n\n"
            "Output must be a JSON object with these keys: "
            "'status' ('supported', 'refuted', 'inconclusive'), 'confidence' (0.0 to 1.0), "
            "'reasoning' (concise explanation of the validation results), and 'new_findings' (list of new facts discovered if any)."
        )

        user_prompt = (
            f"Hypothesis to evaluate: {json.dumps(hypothesis_content)}\n\n"
            f"Contextual facts to use: {json.dumps(context_facts, indent=2)}"
        )

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            # Log the LLM call for transparency
            audit_logger.log_llm_call(
                agent_id="reasoning_engine",
                component="evaluate_hypothesis",
                prompt=user_prompt,
                response=str(response.content) if hasattr(response, 'content') else str(response)
            )

            result = json.loads(response.content)
            
            # If supported, add as a verified finding
            if result.get("status") == "supported":
                finding = {
                    "hypothesis_id": hypothesis_id,
                    "description": hypothesis_content["description"],
                    "type": hypothesis_content["type"],
                    "evidence": result.get("reasoning")
                }
                blackboard.add_verified_finding(finding)

            # Add new findings to blackboard
            for new_fact in result.get("new_findings", []):
                blackboard.add_fact(new_fact)

            audit_logger.log_event("reasoning_engine", "hypothesis_evaluated", input_data={"id": hypothesis_id, "status": result.get("status")})
            return result
        except Exception as e:
            self.logger.error(f"Error evaluating hypothesis: {e}")
            audit_logger.log_event("reasoning_engine", "error", error=str(e))
            return {"error": str(e)}

    async def correlate(self, execution_result: Dict[str, Any], observation: Dict[str, Any], knowledge_map: Optional[Any] = None) -> Dict[str, Any]:
        """
        Correlates an execution result with observed telemetry using a 
        Search-Verify-Summarize loop with the structural index.
        """
        system_prompt = (
            "You are an expert security reasoning engine. Your task is to correlate a payload execution "
            "result with the observed system telemetry to determine if a business logic vulnerability "
            "or security flaw was successfully triggered. "
            "\n\n"
            "You are also provided with context extracted from an Obsidian vault. "
            "Use this knowledge to verify if the observed behavior aligns with established security constraints and business logic requirements. "
            "\n\n"
            "CRITICAL REQUIREMENT: Every finding must implement a 'Chain-of-Traceability' (Source $\\rightarrow$ Transformation $\\rightarrow$ Sink). "
            "Your reasoning and evidence chain must explicitly link the initial triggering input, the path through the application, and the final vulnerable operation."
            "\n\n"
            "Output must be a JSON object with these keys: "
            "'status' ('vulnerable', 'suspicious', 'inconclusive', 'no_impact'), "
            "'confidence' (0.0 to 1.0), "
            "'location' (object with 'file' and 'line_range', if identifiable), "
            "'reasoning' (concise explanation of the correlation), and "
            "'evidence_chain' (list of strings describing the logical link), and "
            "'new_findings' (list of new facts/observations discovered during analysis)."
        )

        # Start with the primary inputs
        context_accumulator = [
            f"Execution Result: {json.dumps(execution_result, indent=2)}",
            f"Observed Telemetry: {json.dumps(observation, indent=2)}"
        ]


        # 1. Search: Identify candidate headings via StructuralIndex
        candidates = []
        if knowledge_map:
            keywords = []
            for key in ['type', 'description', 'status']:
                val = execution_result.get(key) or observation.get(key)
                if val and isinstance(val, str):
                    keywords.append(val)
            
            seen_candidates = set()
            for kw in keywords:
                relevant_files = knowledge_map.find_relevant_files(kw)
                for rel_path in relevant_files:
                    structure = knowledge_map.get_file_structure(rel_path)
                    if not structure:
                        continue
                    for h in structure.get("headings", []):
                        cand_id = f"{rel_path}|{h['text']}"
                        if cand_id not in seen_candidates:
                            candidates.append({
                                "id": cand_id,
                                "rel_path": rel_path,
                                "heading": h["text"]
                            })
                            seen_candidates.add(cand_id)

        # 2. Verify: Iterative Search-Verify-Summarize loop
        if self.reader and candidates:
            max_iterations = 3
            for iteration in range(max_iterations):
                if not candidates:
                    break
                
                # Prepare the prompt for the decision maker
                candidate_list_str = "\n".join([f"- [{c['id']}] {c['rel_path']} -> {c['heading']}" for c in candidates])
                
                decision_prompt = (
                    "You are a strategic investigator. Your goal is to verify a potential vulnerability "
                    "by surgically reading relevant parts of a knowledge vault.\n\n"
                    "Current Context Summary:\n" + "\n".join(context_accumulator[-5:]) + "\n\n"
                    "Available Candidate Headings to Investigate:\n" + candidate_list_str + "\n\n"
                    "Which of these candidates should be investigated next to confirm or refute the vulnerability? "
                    "Pick the top 2 most promising candidates. "
                    "If no further investigation is required, respond ONLY with 'DONE'."
                )

                try:
                    response = await self.llm.ainvoke([
                        SystemMessage(content="You are a concise investigator. Respond with IDs or 'DONE'."),
                        HumanMessage(content=decision_prompt)
                    ])
                    
                    # Log the LLM call for transparency
                    audit_logger.log_llm_call(
                        agent_id="reasoning_engine",
                        component="decision_maker",
                        prompt=decision_prompt,
                        response=str(response.content) if hasattr(response, 'content') else str(response)
                    )
                    
                    decision = response.content.strip()
                    if decision.upper() == "DONE":
                        break
                    
                    # Extract IDs from decision
                    selected_ids = []
                    for cand in candidates:
                        if cand['id'] in decision:
                            selected_ids.append(cand['id'])
                    
                    if not selected_ids:
                        # If no valid IDs found, we might have reached a dead end or LLM failed
                        break
                    
                    # 3. Summarize: Read the selected headings and add to context
                    for sid in selected_ids:
                        cand = next(c for c in candidates if c['id'] == sid)
                        full_path = os.path.join(self.vault_path, cand['rel_path'])
                        content = self.reader.read_by_heading(full_path, cand['heading'])
                        
                        if content:
                            context_accumulator.append(f"### Content from {cand['rel_path']} (Heading: {cand['heading']})\n{content}")
                        
                        # Remove from candidates
                        candidates = [c for c in candidates if c['id'] != sid]

                except Exception as e:
                    self.logger.error(f"Error in search-verify loop: {e}")
                    break

        # 4. Final Correlation
        user_prompt = "### Accumulated Context\n" + "\n\n".join(context_accumulator)

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            # Log the LLM call for transparency
            audit_logger.log_llm_call(
                agent_id="reasoning_engine",
                component="final_correlation",
                prompt=user_prompt,
                response=str(response.content) if hasattr(response, 'content') else str(response)
            )

            result = json.loads(response.content)
            
            # If there are new findings, add them to the blackboard
            for new_fact in result.get("new_findings", []):
                blackboard.add_fact(new_fact)
            
            audit_logger.log_event("reasoning_engine", "correlation_performed", input_data={"status": result.get("status")})
            return result
        except Exception as e:
            self.logger.error(f"Error during correlation: {e}")
            audit_logger.log_event("reasoning_engine", "error", error=str(e))
            return {"status": "error", "confidence": 0.0, "reasoning": str(e), "new_findings": []}

    async def evaluate_hypothesis(self, hypothesis_id: str, context_facts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluates a specific hypothesis against new context and facts.
        """
        # Find hypothesis in blackboard
        all_hypotheses = blackboard.get_all()["hypotheses"]
        target_hyp = next((h for h in all_hypotheses if h["content"].get("id") == hypothesis_id), None)
        
        if not target_hyp:
            return {"error": f"Hypothesis {hypothesis_id} not found."}

        hypothesis_content = target_hyp["content"]

        system_prompt = (
            "You are an expert security validator. Evaluate a hypothesis against provided facts. "
            "Determine if the hypothesis is supported, refuted, or remains inconclusive. "
            "\n\n"
            "CRITICAL REQUIREMENT: Your evaluation must validate the proposed 'Chain-of-Traceability'. "
            "Verify if the observed facts actually support the proposed path from Source to Sink. "
            "\n\n"
            "Output must be a JSON object with these keys: "
            "'status' ('supported', 'refuted', 'inconclusive'), 'confidence' (0.0 to 1.0), "
            "'reasoning' (concise explanation of the validation results), and 'new_findings' (list of new facts discovered if any)."
        )

        user_prompt = (
            f"Hypothesis to evaluate: {json.dumps(hypothesis_content)}\n\n"
            f"Contextual facts to use: {json.dumps(context_facts, indent=2)}"
        )

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            result = json.loads(response.content)
            
            # If supported, add as a verified finding
            if result.get("status") == "supported":
                finding = {
                    "hypothesis_id": hypothesis_id,
                    "description": hypothesis_content["description"],
                    "type": hypothesis_content["type"],
                    "evidence": result.get("reasoning")
                }
                blackboard.add_verified_finding(finding)

            # Add new findings to blackboard
            for new_fact in result.get("new_findings", []):
                blackboard.add_fact(new_fact)

            audit_logger.log_event("reasoning_engine", "hypothesis_evaluated", input_data={"id": hypothesis_id, "status": result.get("status")})
            return result
        except Exception as e:
            self.logger.error(f"Error evaluating hypothesis: {e}")
            audit_logger.log_event("reasoning_engine", "error", error=str(e))
            return {"error": str(e)}

    async def correlate(self, execution_result: Dict[str, Any], observation: Dict[str, Any], knowledge_map: Optional[Any] = None) -> Dict[str, Any]:
        """
        Correlates an execution result with observed telemetry using a 
        Search-Verify-Summarize loop with the structural index.
        """
        system_prompt = (
            "You are an expert security reasoning engine. Your task is to correlate a payload execution "
            "result with the observed system telemetry to determine if a business logic vulnerability "
            "or security flaw was successfully triggered. "
            "\n\n"
            "You are also provided with context extracted from an Obsidian vault. "
            "Use this knowledge to verify if the observed behavior aligns with established security constraints and business logic requirements. "
            "\n\n"
            "CRITICAL REQUIREMENT: Every finding must implement a 'Chain-of-Traceability' (Source $\\rightarrow$ Transformation $\\rightarrow$ Sink). "
            "Your reasoning and evidence chain must explicitly link the initial triggering input, the path through the application, and the final vulnerable operation."
            "\n\n"
            "Output must be a JSON object with these keys: "
            "'status' ('vulnerable', 'suspicious', 'inconclusive', 'no_impact'), "
            "'confidence' (0.0 to 1.0), "
            "'location' (object with 'file' and 'line_range', if identifiable), "
            "'reasoning' (concise explanation of the correlation), and "
            "'evidence_chain' (list of strings describing the logical link), and "
            "'new_findings' (list of new facts/observations discovered during analysis)."
        )

        # Start with the primary inputs
        context_accumulator = [
            f"Execution Result: {json.dumps(execution_result, indent=2)}",
            f"Observed Telemetry: {json.dumps(observation, indent=2)}"
        ]


        # 1. Search: Identify candidate headings via StructuralIndex
        candidates = []
        if knowledge_map:
            keywords = []
            for key in ['type', 'description', 'status']:
                val = execution_result.get(key) or observation.get(key)
                if val and isinstance(val, str):
                    keywords.append(val)
            
            seen_candidates = set()
            for kw in keywords:
                relevant_files = knowledge_map.find_relevant_files(kw)
                for rel_path in relevant_files:
                    structure = knowledge_map.get_file_structure(rel_path)
                    if not structure:
                        continue
                    for h in structure.get("headings", []):
                        cand_id = f"{rel_path}|{h['text']}"
                        if cand_id not in seen_candidates:
                            candidates.append({
                                "id": cand_id,
                                "rel_path": rel_path,
                                "heading": h["text"]
                            })
                            seen_candidates.add(cand_id)

        # 2. Verify: Iterative Search-Verify-Summarize loop
        if self.reader and candidates:
            max_iterations = 3
            for iteration in range(max_iterations):
                if not candidates:
                    break
                
                # Prepare the prompt for the decision maker
                candidate_list_str = "\n".join([f"- [{c['id']}] {c['rel_path']} -> {c['heading']}" for c in candidates])
                
                decision_prompt = (
                    "You are a strategic investigator. Your goal is to verify a potential vulnerability "
                    "by surgically reading relevant parts of a knowledge vault.\n\n"
                    "Current Context Summary:\n" + "\n".join(context_accumulator[-5:]) + "\n\n"
                    "Available Candidate Headings to Investigate:\n" + candidate_list_str + "\n\n"
                    "Which of these candidates should be investigated next to confirm or refute the vulnerability? "
                    "Pick the top 2 most promising candidates. "
                    "If no further investigation is required, respond ONLY with 'DONE'."
                )

                try:
                    response = await self.llm.ainvoke([
                        SystemMessage(content="You are a concise investigator. Respond with IDs or 'DONE'."),
                        HumanMessage(content=decision_prompt)
                    ])
                    
                    decision = response.content.strip()
                    if decision.upper() == "DONE":
                        break
                    
                    # Extract IDs from decision
                    selected_ids = []
                    for cand in candidates:
                        if cand['id'] in decision:
                            selected_ids.append(cand['id'])
                    
                    if not selected_ids:
                        # If no valid IDs found, we might have reached a dead end or LLM failed
                        break
                    
                    # 3. Summarize: Read the selected headings and add to context
                    for sid in selected_ids:
                        cand = next(c for c in candidates if c['id'] == sid)
                        full_path = os.path.join(self.vault_path, cand['rel_path'])
                        content = self.reader.read_by_heading(full_path, cand['heading'])
                        
                        if content:
                            context_accumulator.append(f"### Content from {cand['rel_path']} (Heading: {cand['heading']})\n{content}")
                        
                        # Remove from candidates
                        candidates = [c for c in candidates if c['id'] != sid]

                except Exception as e:
                    self.logger.error(f"Error in search-verify loop: {e}")
                    break

        # 4. Final Correlation
        user_prompt = "### Accumulated Context\n" + "\n\n".join(context_accumulator)

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            result = json.loads(response.content)
            
            # If there are new findings, add them to the blackboard
            for new_fact in result.get("new_findings", []):
                blackboard.add_fact(new_fact)
            
            audit_logger.log_event("reasoning_engine", "correlation_performed", input_data={"status": result.get("status")})
            return result
        except Exception as e:
            self.logger.error(f"Error during correlation: {e}")
            audit_logger.log_event("reasoning_engine", "error", error=str(e))
            return {"status": "error", "confidence": 0.0, "reasoning": str(e), "new_findings": []}


# Global instance
reasoning_engine = ReasoningEngine()
