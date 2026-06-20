import json
import logging
import asyncio
from typing import List, Dict, Any
from logic_engine.agent_config import AgentConfig
from logic_engine.blackboard import blackboard
from logic_engine.utils.logger import audit_logger
from langchain_core.messages import HumanMessage, SystemMessage

class ReasoningEngine:
    def __init__(self):
        self.llm = AgentConfig.get_llm(model_type="reasoning")
        self.logger = logging.getLogger("ReasoningEngine")

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
            "Output must be a JSON list of objects, where each object represents a hypothesis with these keys: "
            "'id' (unique slug), 'description' (clear explanation), 'type' (e.g., CSRF, IDOR, Privilege Escalation, Logic Flaw), "
            "'confidence' (0.0 to 1.0), and 'supporting_evidence' (list of fact IDs or descriptions)."
        )
        
        user_prompt = f"Analyze the following observed facts and generate hypotheses:\n{json.dumps(facts, indent=2)}"

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            # The response is expected to be a JSON string due to format="json"
            hypotheses = json.loads(response.content)
            
            if not isinstance(hypotheses, list):
                self.logger.error("LLM did not return a list of hypotheses.")
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
            "Output must be a JSON object with these keys: "
            "'status' ('supported', 'refuted', 'inconclusive'), 'confidence' (0.0 to 1.0), "
            "'reasoning' (concise explanation), and 'new_findings' (list of new facts discovered if any)."
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

# Global instance
reasoning_engine = ReasoningEngine()
