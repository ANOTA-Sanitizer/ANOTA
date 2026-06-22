import os
import json
import re
from typing import List, Dict, Any, Optional
from logic_engine.interaction_scanner import InteractionScanner
from logic_engine.utils.logger import audit_logger

class AgenticInteractionScanner(InteractionScanner):
    """
    Advanced scanner that uses an LLM to synthesize runtime interaction logs into high-fidelity Interaction Facts.
    """

    async def _analyze_log_entry(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Uses an LLM to synthesize a log entry into a structured Interaction Fact.
        """
        system_prompt = (
            "You are a specialized security analyst specializing in runtime behavioral analysis. "
            "Your task is to analyze an interaction log entry and synthesize it into a high-fidelity 'Interaction Fact'. "
            "\n\n"
            "An Interaction Fact must be a single, verifiable technical observation about observed behavior. "
            "\n\n"
            "Output must be a JSON object with these keys: "
            "- 'id': A unique, slug-style identifier (e.g., 'fact_unauth_access_api_user_php')."
            "- 'type': The category (e.g., 'unauthorized_access', 'sensitive_data_exposure', 'command_injection_attempt', 'injection_attempt', 'auth_bypass')."
            "- 'description': A technical, precise explanation of the observed behavior."
            "- 'trigger': A structured object describing the action that triggered the behavior: { 'method': '...', 'endpoint': '...', 'payload': '...' }."
            "- 'observed_behavior': A structured object describing the response/outcome: { 'status': '...', 'response_body_contains': '...', 'timing': '...' }."
            "- 'evidence_chain': A concise list of string observations (e.g., ['Request: POST /api/user with payload {admin:true}', 'Response: 500 Internal Server Error', 'Observation: Stack trace leaked database credentials'])."
            "- 'confidence': A score from 0.0 to 1.0."
            "- 'knowledge_context': A summary of relevant security rules or business logic from the knowledge vault that applies to this finding."
        )

        user_prompt = (
            f"Log Entry:\n{json.dumps(log_entry, indent=2)}\n\n"
            "Synthesize this log entry into a single high-fidelity Interaction Fact. If the entry is benign or does not represent a security-relevant event, return null."
        )

        try:
            response = await self.prober.llm.ainvoke([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ])
            
            raw_fact_data = response.content if hasattr(response, 'content') else str(response)
            
            # Parse JSON from response
            fact = None
            if isinstance(raw_fact_data, str):
                if "```json" in raw_fact_data:
                    json_match = re.search(r"```json\n(.*?)\n```", raw_fact_data, re.DOTALL)
                    if json_match:
                        fact = json.loads(json_match.group(1))
                else:
                    try:
                        fact = json.loads(raw_fact_data)
                    except json.JSONDecodeError:
                        # Try to find any JSON-like structure
                        json_match = re.search(r"\{.*\}", raw_fact_data, re.DOTALL)
                        if json_match:
                            try:
                                fact = json.loads(json_match.group(0))
                            except json.JSONDecodeError:
                                return None
                        else:
                            return None
            elif isinstance(raw_fact_data, dict):
                fact = raw_fact_data
            
            if fact and all(k in fact for k in ("id", "type", "description", "trigger", "observed_behavior", "evidence_chain", "confidence")):
                return fact
                
        except Exception as e:
            audit_logger.log_event("agentic_interaction_scanner", "synthesis_llm_error", error=str(e))
            
        return None
