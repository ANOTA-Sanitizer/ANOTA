import unittest
import json
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from logic_engine.reasoning_engine import ReasoningEngine
from logic_engine.blackboard import blackboard

class TestReasoningEngine(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Clear blackboard before each test
        blackboard.state = {
            "facts": [],
            "hypotheses": [],
            "verified_findings": [],
            "current_context": {}
        }
        # Patch AgentConfig.get_llm to return a mock LLM
        self.patcher = patch('logic_engine.agent_config.AgentConfig.get_llm')
        self.mock_get_llm = self.patcher.start()
        self.mock_llm = AsyncMock()
        self.mock_get_llm.return_value = self.mock_llm
        
        self.engine = ReasoningEngine()

    async def asyncTearDown(self):
        self.patcher.stop()

    async def test_generate_hypotheses_success(self):
        facts = [{"type": "syscall", "syscall": "open", "path": "/etc/passwd"}]
        
        # Mock LLM response
        hypotheses_output = [
            {
                "id": "unauthorized-file-access",
                "description": "Potential unauthorized file access to sensitive system files.",
                "type": "Privilege Escalation",
                "confidence": 0.8,
                "supporting_evidence": ["Access to /etc/passwd"]
            }
        ]
        self.mock_llm.ainvoke.return_value = MagicMock(content=json.dumps(hypotheses_output))

        results = await self.engine.generate_hypotheses(facts)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "unauthorized-file-access")
        
        # Verify hypothesis was added to blackboard
        all_hypotheses = blackboard.get_all()["hypotheses"]
        self.assertEqual(len(all_hypotheses), 1)
        self.assertEqual(all_hypotheses[0]["content"]["id"], "unauthorized-file-access")

    async def test_evaluate_hypothesis_supported(self):
        # Set up a hypothesis in the blackboard
        hyp_id = "test-hypo"
        hyp_content = {
            "id": hyp_id,
            "description": "Test hypothesis",
            "type": "TestType",
            "confidence": 0.5,
            "supporting_evidence": []
        }
        blackboard.add_hypothesis(hyp_content)

        # Mock LLM response for evaluation
        eval_output = {
            "status": "supported",
            "confidence": 0.9,
            "reasoning": "Facts clearly support the hypothesis.",
            "new_findings": [{"type": "new_fact", "data": "something"}]
        }
        self.mock_llm.ainvoke.return_value = MagicMock(content=json.dumps(eval_output))

        # Facts used for evaluation
        context_facts = [{"type": "observed", "data": "evidence"}]

        result = await self.engine.evaluate_hypothesis(hyp_id, context_facts)

        self.assertEqual(result["status"], "supported")
        
        # Verify finding was added to blackboard
        findings = blackboard.get_all()["verified_findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["content"]["hypothesis_id"], hyp_id)

        # Verify new fact was added to blackboard
        facts = blackboard.get_all()["facts"]
        self.assertEqual(len(facts), 1)
        self.assertEqual(facts[0]["content"]["type"], "new_fact")

    async def test_evaluate_hypothesis_not_found(self):
        result = await self.engine.evaluate_hypothesis("non-existent", [])
        self.assertIn("error", result)

if __name__ == "__main__":
    unittest.main()
