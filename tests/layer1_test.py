import sys
import os
import json

# Add parent directory to path so we can import logic_engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from logic_engine.utils.logger import audit_logger
from logic_engine.blackboard import blackboard
from logic_engine.knowledge_scanner import knowledge_scanner

def test_logger():
    print("Testing Logger...")
    path = audit_logger.log_event("test_agent", "test_action", input_data={"hello": "world"}, output_data={"status": "ok"})
    if os.path.exists(path):
        print(f"  [PASS] Log created at {path}")
        with open(path, 'r') as f:
            data = json.load(f)
            if data["agent_id"] == "test_agent" and data["input"]["hello"] == "world":
                print("  [PASS] Log content verified")
            else:
                print("  [FAIL] Log content mismatch")
    else:
        print("  [FAIL] Log file not created")

def test_blackboard():
    print("Testing Blackboard...")
    blackboard.add_fact("test fact")
    blackboard.add_hypothesis("test hypothesis")
    blackboard.update_context("test_key", "test_value")
    
    state = blackboard.get_all()
    if any(f["content"] == "test fact" for f in state["facts"]):
        print("  [PASS] Fact added")
    else:
        print("  [FAIL] Fact not found")
        
    if any(h["content"] == "test hypothesis" for h in state["hypotheses"]):
        print("  [PASS] Hypothesis added")
    else:
        print("  [FAIL] Hypothesis not found")

    if state["current_context"].get("test_key") == "test_value":
        print("  [PASS] Context updated")
    else:
        print("  [FAIL] Context mismatch")

def test_scanner():
    print("Testing KnowledgeScanner...")
    # Use the file we know exists
    vault_path = "../Qbrain/obsidian_vault"
    scanner = knowledge_scanner
    scanner.vault_path = os.path.abspath(vault_path)
    
    knowledge_map = scanner.scan_vault()
    
    # Check if prerequisites.md is in the map
    found = False
    for rel_path in knowledge_map.keys():
        if "rules/prerequisites.md" in rel_path:
            found = True
            print(f"  [PASS] Found {rel_path} in scan")
            break
    
    if not found:
        print("  [FAIL] Could not find prerequisites.md in scan")
        return

    # Test wiki-link extraction from prerequisites.md
    prereqs = knowledge_map["rules/prerequisites.md"]
    links = prereqs["links"]
    
    # Based on the file content, we expect [[files/config_config_inc_php|config/config.inc.php]]
    # The target should be 'files/config_config_inc_php'
    found_link = any(l["target"] == "files/config_config_inc_php" for l in links)
    if found_link:
        print("  [PASS] Wiki-links correctly extracted")
    else:
        print("  [FAIL] Wiki-links not correctly extracted. Found: ", links)

    # Test heading extraction
    headings = prereqs["headings"]
    found_heading = any(h["text"] == "1. Discovered Setup & Installer Scripts" for h in headings)
    if found_heading:
        print("  [PASS] Headings correctly extracted")
    else:
        print("  [FAIL] Headings not correctly extracted")

    # Test content extraction by heading
    # We'll try to extract the content under "1. Discovered Setup & Installer Scripts"
    # Note: in the file it is "## 1. Discovered Setup & Installer Scripts"
    content = scanner.get_content_by_heading(os.path.abspath(os.path.join(vault_path, "rules/prerequisites.md")), "1. Discovered Setup & Installer Scripts")
    if content:
        print("  [PASS] Content extracted by heading")
        if "These files contain database schema definitions" in content:
            print("  [PASS] Content content verified")
        else:
            print("  [FAIL] Content mismatch")
    else:
        print("  [FAIL] Could not extract content by heading")

if __name__ == "__main__":
    test_logger()
    print("-" * 20)
    test_blackboard()
    print("-" * 20)
    test_scanner()
