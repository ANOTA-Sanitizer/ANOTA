import json
import logging
from typing import Any, Dict, List, Optional
from langchain_core.messages import HumanMessage, SystemMessage
from logic_engine.agent_config import AgentConfig

logger = logging.getLogger(__name__)

class PayloadGenerator:
    """
    Uses an LLM to generate effective security payloads based on vulnerability type and target context.
    """

    def __init__(self, model_type: str = "reasoning"):
        self.llm = AgentConfig.get_llm(model_type=model_type)

    async def generate_payload(self, vulnerability_type: str, target_context: Dict[str, Any]) -> str:
        """
        Generates a payload for a given vulnerability type and target context.
        
        Args:
            vulnerability_type: The type of vulnerability (e.g., 'sql_injection', 'xss').
            target_context: Context about the target (e.g., {'file': 'login.php', 'line': 42, 'parameter': 'id'}).
            
        Returns:
            A string containing the payload.
        """
        system_prompt = (
            "You are a specialized security payload generation agent. Your task is to generate a single, "
            "highly effective payload for a specific vulnerability type and target context. "
            "\n\n"
            "The payload must be optimized for the given context to maximize the chance of triggering "
            "the vulnerability. "
            "\n\n"
            "Output MUST be ONLY the raw payload string. No explanations, no markdown, no quotes."
        )

        user_prompt = (
            f"Vulnerability Type: {vulnerability_type}\n"
            f"Target Context: {json.dumps(target_context, indent=2)}\n\n"
            "Generate the payload:"
        )

        try:
            response = await self.llm.ainvoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            payload = response.content.strip()
            
            # If the LLM returned a JSON object instead of a raw string, extract the payload
            try:
                payload_json = json.loads(payload)
                if isinstance(payload_json, dict) and "payload" in payload_json:
                    payload = payload_json["payload"]
                elif isinstance(payload_json, dict) and "content" in payload_json:
                    payload = payload_json["content"]
            except json.JSONDecodeError:
                pass

            # Remove potential markdown wrapping if the LLM ignores the instruction
            if payload.startswith("```"):
                # Find the first newline after the opening ```
                lines = payload.splitlines()
                if len(lines) > 1:
                    payload = "\n".join(lines[1:-1])
            
            # Clean up any remaining quotes that might have been added
            if (payload.startswith("'") and payload.endswith("'")) or (payload.startswith('"') and payload.endswith('"')):
                payload = payload[1:-1]
                
            return payload
            
        except Exception as e:
            logger.error(f"Error generating payload: {e}")
            return ""
