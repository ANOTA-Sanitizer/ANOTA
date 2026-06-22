import asyncio
import json
import os
from unittest.mock import MagicMock, AsyncMock
from logic_engine.reasoning_engine import ReasoningEngine

async def test_correlate_success():
    # 1. Setup
    # Using a dummy path
    vault_path = "/tmp/mock_vault"
    
    # Mock SemanticReader
    mock_reader = MagicMock()
    # Mock the read_by_heading to return specific content
    mock_reader.read_by_heading.return_value = "Always check for single quotes and UNION based attacks."
    
    # Initialize ReasoningEngine with mock reader
    engine = ReasoningEngine(vault_path=vault_path)
    engine.reader = mock_reader
    # Mock the LLM
    engine.llm = MagicMock()

    # 2. Mock KnowledgeMap (StructuralIndex)
    mock_knowledge_map = MagicMock()
    mock_knowledge_map.find_relevant_files.return_value = ["security/sqli.md"]
    mock_knowledge_map.get_file_structure.return_value = {
        "headings": [{"text": "SQL Injection Patterns"}]
    }

    # 3. Inputs
    execution_result = {
        "type": "SQL Injection",
        "description": "SQLi in login.php"
    }
    observation = {
        "status": "vulnerable",
        "details": "database error leaked"
    }

    # 4. Mock LLM Responses
    # First call: Decision Maker
    decision_response = MagicMock()
    decision_response.content = "security/sqli.md|SQL Injection Patterns"

    # Second call: Final Correlation
    final_response = MagicMock()
    final_response.content = json.dumps({
        "status": "vulnerable",
        "confidence": 0.9,
        "reasoning": "The observed database error aligns with known SQL Injection patterns in the vault.",
        "new_findings": ["SQLi pattern confirmed via error leakage"]
    })

    # ainvoke is an async method, so we need to make sure it returns awaitable objects.
    from unittest.mock import AsyncMock
    engine.llm.ainvoke = AsyncMock(side_effect=[decision_response, final_response])

    # 5. Execution
    print("[*] Running correlation test...")
    result = await engine.correlate(execution_result, observation, mock_knowledge_map)

    # 6. Assertions
    print(f"[*] Result: {json.dumps(result, indent=2)}")
    assert result["status"] == "vulnerable"
    assert result["confidence"] == 0.9
    assert "sql injection patterns" in result["reasoning"].lower()
    assert "SQLi pattern confirmed" in result["new_findings"][0]
    
    # Verify reader was called correctly
    mock_reader.read_by_heading.assert_called_once_with(
        os.path.join(vault_path, "security/sqli.md"),
        "SQL Injection Patterns"
    )
    print("[SUCCESS] Correlation engine test passed!")

if __name__ == "__main__":
    asyncio.run(test_correlate_success())
