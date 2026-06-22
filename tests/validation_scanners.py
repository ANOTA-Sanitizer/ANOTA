import os
import json
import asyncio
from logic_engine.blackboard import blackboard

async def test_blackboard_schema():
    print("[*] Starting Blackboard Schema Validation...")
    blackboard.clear()
    
    # 1. Test Simple Fact
    print("[*] Testing simple string fact...")
    blackboard.add_fact("simple fact")
    
    # 2. Test Key-Value Fact
    print("[*] Testing key-value fact...")
    blackboard.add_fact("test_key", "test_value")
    
    # 3. Test Structured Code Fact (The new part)
    print("[*] Testing structured code fact...")
    code_fact = {
        "id": "fact_sqli_vulnerabilities_api_user_php",
        "type": "vulnerability",
        "description": "SQL injection in user profile update",
        "evidence_chain": ["Source: $_POST['id']", "Sink: mysqli_query"],
        "location": "user.php:45",
        "confidence": 0.9
    }
    blackboard.add_fact(code_fact)
    
    # 4. Test Verified Finding (Structured)
    print("[*] Testing structured verified finding...")
    finding = {
        "description": "Confirmed SQLi on user.php",
        "type": "SQLi",
        "severity": "CRITICAL"
    }
    blackboard.add_verified_finding(finding)
    
    # Verification
    state = blackboard.get_all()
    
    print("\n--- Blackboard State ---")
    print(json.dumps(state, indent=2))
    
    # Assertions
    assert len(state["facts"]) == 3
    assert state["facts"][0]["content"] == "simple fact"
    assert state["facts"][1]["key"] == "test_key"
    assert state["facts"][2]["id"] == "fact_sqli_vulnerabilities_api_user_php"
    assert state["facts"][2]["type"] == "vulnerability"
    
    assert len(state["verified_findings"]) == 1
    assert state["verified_findings"][0]["description"] == "Confirmed SQLi on user.php"
    
    print("\n[+] Blackboard Schema Validation PASSED!")

if __name__ == "__main__":
    asyncio.run(test_blackboard_schema())
