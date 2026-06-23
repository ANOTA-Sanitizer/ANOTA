import os
import re
import asyncio
import logging
from typing import List, Dict, Any, Optional
from logic_engine.utils.semantic_reader import SemanticReader
from logic_engine.utils.logger import logger
from logic_engine.utils.agentic_prober import AgenticProber

class TraceAgent:
    """
    Agent responsible for resolving 'leads' discovered during scanning.
    It follows function calls and file includes to uncover deeper vulnerabilities.
    """

    MAX_TRACE_DEPTH = 3

    def __init__(self, repo_path: str, reader: SemanticReader, prober: AgenticProber, blackboard: Any):
        self.repo_path = os.path.abspath(repo_path)
        self.reader = reader
        self.prober = prober
        self.blackboard = blackboard

    async def resolve_leads(self, leads: List[Dict[str, Any]], repo_path: str) -> List[Dict[str, Any]]:
        """
        Resolves a list of leads and returns new findings.
        """
        new_findings = []
        
        for lead in leads:
            logger.info(f"    [>] Tracing lead: {lead['type']} -> {lead['pivot_target']}")
            
            if lead['type'] == 'LEAD_FUNCTION_CALL':
                findings = await self._trace_function_call(lead, depth=1)
                new_findings.extend(findings)
            elif lead['type'] == 'LEAD_FILE_INCLUDE':
                findings = await self._trace_file_include(lead, depth=1)
                new_findings.extend(findings)
            
        return new_findings

    async def _trace_function_call(self, lead: Dict[str, Any], depth: int) -> List[Dict[str, Any]]:
        """
        Finds the definition of a function and probes it.
        """
        if depth > self.MAX_TRACE_DEPTH:
            logger.warning(f"        [!] Max trace depth reached for {lead['pivot_target']}")
            return []

        symbol = lead['pivot_target']
        start_file = lead.get('file')
        
        # 1. Find where the symbol is defined
        definition_file = await self._find_symbol_definition(symbol, start_file)
        
        if not definition_file:
            logger.warning(f"        [!] Could not find definition for symbol: {symbol}")
            return []

        logger.info(f"        [+] Found definition of {symbol} in {definition_file}")
        
        # 2. Probe the definition for vulnerabilities
        full_path = os.path.join(self.repo_path, definition_file)
        if not os.path.exists(full_path):
            return []

        probe_results = await self.prober.probe_file_for_vulnerabilities(
            file_path=full_path,
            target_areas=["vulnerability", "sink", "source", "sanitizer"],
            rel_path=definition_file
        )

        new_findings = []
        for finding in probe_results.get("findings", []):
            finding["type"] = f"traced_{finding['type']}"
            finding["depth"] = depth
            new_findings.append(finding)
            self.blackboard.add_fact("code_facts", finding)

        # 3. Recursively trace new leads found during probing
        for new_lead in probe_results.get("leads", []):
            new_lead["depth"] = depth + 1
            self.blackboard.add_fact("leads", new_lead)
            if new_lead["type"] == 'LEAD_FUNCTION_CALL':
                recursive_findings = await self._trace_function_call(new_lead, depth=depth+1)
                new_findings.extend(recursive_findings)
            elif new_lead["type"] == 'LEAD_FILE_INCLUDE':
                recursive_findings = await self._trace_file_include(new_lead, depth=depth+1)
                new_findings.extend(recursive_findings)

        return new_findings

    async def _trace_file_include(self, lead: Dict[str, Any], depth: int) -> List[Dict[str, Any]]:
        """
        Follows a file include lead.
        """
        if depth > self.MAX_TRACE_DEPTH:
            return []

        target_file = lead['pivot_target']
        
        # 1. Locate the file
        actual_path = self._resolve_file_path(target_file, lead.get('file'))
        
        if not actual_path or not os.path.exists(actual_path):
            logger.warning(f"        [!] Could not find included file: {target_file}")
            return []

        rel_path = os.path.relpath(actual_path, self.repo_path)
        logger.info(f"        [+] Traced include to: {rel_path}")

        # 2. Probe the included file
        probe_results = await self.prober.probe_file_for_vulnerabilities(
            file_path=actual_path,
            target_areas=["vulnerability", "sink", "source", "sanitizer"],
            rel_path=rel_path
        )

        new_findings = []
        for finding in probe_results.get("findings", []):
            finding["type"] = f"traced_{finding['type']}"
            finding["depth"] = depth
            new_findings.append(finding)
            self.blackboard.add_fact("code_facts", finding)

        # 3. Recursively trace new leads found during probing
        for new_lead in probe_results.get("leads", []):
            new_lead["depth"] = depth + 1
            self.blackboard.add_fact("leads", new_lead)
            if new_lead["type"] == 'LEAD_FUNCTION_CALL':
                recursive_findings = await self._trace_function_call(new_lead, depth=depth+1)
                new_findings.extend(recursive_findings)
            elif new_lead["type"] == 'LEAD_FILE_INCLUDE':
                recursive_findings = await self._trace_file_include(new_lead, depth=depth+1)
                new_findings.extend(recursive_findings)

        return new_findings

    def _resolve_file_path(self, target_file: str, current_file: Optional[str]) -> Optional[str]:
        if not current_file:
            return os.path.join(self.repo_path, target_file)
        
        # Try relative to current file
        current_dir = os.path.dirname(os.path.join(self.repo_path, current_file))
        potential_path = os.path.join(current_dir, target_file)
        if os.path.exists(potential_path):
            return potential_path
            
        # Try relative to project root
        potential_path = os.path.join(self.repo_path, target_file)
        if os.path.exists(potential_path):
            return potential_path
            
        return None

    async def _find_symbol_definition(self, symbol: str, start_file: Optional[str]) -> Optional[str]:
        """
        Searches the codebase for a function/class definition.
        """
        # In a real implementation, we'd use a more sophisticated approach (like ctags or LSP)
        # For now, we'll do a simple grep-like search across all relevant files.
        
        # Pre-defined patterns for common languages
        patterns = [
            re.compile(rf"function\s+{re.escape(symbol)}\s*\("),
            re.compile(rf"def\s+{re.escape(symbol)}\s*\("),
            re.compile(rf"class\s+{re.escape(symbol)}\s*"),
        ]

        # If we have a start_file, we might want to search there first or around it
        # But for simplicity, we search the whole project.
        
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                if not file.endswith(('.php', '.py', '.js', '.go', '.java')):
                    continue
                
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            for pattern in patterns:
                                if pattern.search(line):
                                    return os.path.relpath(file_path, self.repo_path)
                except Exception:
                    continue
                    
        return None

    async def _extract_symbol_definition(self, file_path: str, symbol: str) -> str:
        """
        Extracts the body of the symbol definition.
        """
        # This is very simplified. A real implementation would use the SemanticReader's 
        # read_by_symbol if it was more robust.
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start_index = -1
            for i, line in enumerate(lines):
                if symbol in line: # Very naive
                    start_index = i
                    break
            
            if start_index == -1:
                return ""

            # Just return a few lines for now
            return "".join(lines[start_index:start_index+20])
        except Exception:
            return ""
