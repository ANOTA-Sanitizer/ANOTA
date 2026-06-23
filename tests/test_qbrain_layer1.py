import pytest
from logic_engine.knowledge_scanner import KnowledgeScanner
import os
import asyncio

@pytest.mark.asyncio
async def test_qbrain_scan():
    # Path to the real obsidian vault
    vault_path = os.path.abspath("../Qbrain/obsidian_vault")
    print(f"Scanning vault: {vault_path}")
    
    if not os.path.exists(vault_path):
        print(f"Error: Vault path {vault_path} does not exist.")
        return
    
    scanner = KnowledgeScanner(vault_path=vault_path)
    knowledge_map = await scanner.scan_vault()
    
    print(f"Successfully scanned {len(knowledge_map)} files.")
    
    # Print a few examples to verify
    count = 0
    for rel_path, data in knowledge_map.items():
        if count >= 5:
            break
        print(f"\nFile: {rel_path}")
        print(f"  Links: {data['links']}")
        print(f"  Headings: {data['headings']}")
        count += 1

    if not knowledge_map:
        print("Error: No files were scanned.")
    else:
        print("\nLayer 1 scan of Qbrain/obsidian_vault successful.")

