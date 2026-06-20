from logic_engine.knowledge_scanner import KnowledgeScanner
import os

def test_dvwa_scan():
    # Path to the dvwa vault
    dvwa_vault = os.path.abspath("Vault/dvwa")
    print(f"Scanning vault: {dvwa_vault}")
    
    scanner = KnowledgeScanner(vault_path=dvwa_vault)
    knowledge_map = scanner.scan_vault()
    
    print(f"Successfully scanned {len(knowledge_map)} files.")
    
    for rel_path, data in list(knowledge_map.items())[:5]:
        print(f"\nFile: {rel_path}")
        print(f"  Links: {data['links']}")
        print(f"  Headings: {data['headings']}")

    if not knowledge_map:
        print("Error: No files were scanned.")
    else:
        print("\nLayer 1 scan of Vault/dvwa successful.")

if __name__ == "__main__":
    test_dvwa_scan()
