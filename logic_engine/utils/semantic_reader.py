import os
import re
from typing import Optional, List, Dict, Any

class SemanticReader:
    """
    Provides targeted reading capabilities for both code and markdown files
    to support agentic scanning without reading entire files.
    """

    def __init__(self):
        # Heading pattern for Markdown
        self.heading_pattern = re.compile(r"^(#{1,6})\s+(.*)$", re.MULTILINE)
        
        # Improved code block patterns for Python and PHP
        self.code_block_patterns = [
            (re.compile(r"def\s+(\w+)\s*\("), "python_func"),          # Python function
            (re.compile(r"class\s+(\w+)\s*[:\(]"), "python_class"),     # Python class
            (re.compile(r"function\s+(\w+)\s*\("), "php_js_func"),     # PHP/JS function
            (re.compile(r"class\s+(\w+)\s*\{"), "php_js_class"),        # PHP/JS class
        ]

    def read_snippet(self, file_path: str, start_line: int, end_line: int) -> str:
        """Reads a specific line range from a file."""
        if not os.path.exists(file_path):
            return ""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Adjusting to 1-indexed line numbers
                start = max(0, start_line - 1)
                end = min(len(lines), end_line)
                return "".join(lines[start:end]).strip()
        except Exception:
            return ""

    def read_by_heading(self, file_path: str, heading_text: str) -> Optional[str]:
        """Extracts content following a specific heading in a Markdown file."""
        if not os.path.exists(file_path):
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            start_index = -1
            end_index = len(lines)
            current_level = 0

            for i, line in enumerate(lines):
                match = self.heading_pattern.match(line)
                if match:
                    level = len(match.group(1))
                    text = match.group(2).strip()
                    if text == heading_text:
                        start_index = i + 1
                        current_level = level
                        break
            
            if start_index == -1:
                return None

            for i in range(start_index, len(lines)):
                match = self.heading_pattern.match(lines[i])
                if match:
                    new_level = len(match.group(1))
                    if new_level <= current_level:
                        end_index = i
                        break
            
            return "".join(lines[start_index:end_index]).strip()
        except Exception:
            return None

    def read_by_symbol(self, file_path: str, symbol_name: str) -> Optional[str]:
        """
        Attempts to extract a code block (function or class) by name.
        """
        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            start_index = -1
            end_index = len(lines)
            
            # Find the start of the symbol
            for i, line in enumerate(lines):
                for pattern, _ in self.code_block_patterns:
                    match = pattern.search(line)
                    if match and match.group(1) == symbol_name:
                        start_index = i
                        break
                if start_index != -1:
                    break

            if start_index == -1:
                return None

            # Heuristic end detection:
            extension = os.path.splitext(file_path)[1]
            
            if extension in ['.py']:
                # Find next line with less indentation
                first_line_indent = len(lines[start_index]) - len(lines[start_index].lstrip())
                for i in range(start_index + 1, len(lines)):
                    if lines[i].strip(): # Skip empty lines
                        current_indent = len(lines[i]) - len(lines[i].lstrip())
                        if current_indent <= first_line_indent:
                            end_index = i
                            break
            elif extension in ['.php', '.js']:
                # Find matching closing brace
                brace_count = 0
                found_first_brace = False
                for i in range(start_index, len(lines)):
                    if '{' in lines[i]:
                        brace_count += lines[i].count('{')
                        found_first_brace = True
                    if '}' in lines[i]:
                        brace_count -= lines[i].count('}')
                    
                    if found_first_brace and brace_count <= 0:
                        end_index = i + 1
                        break
            
            return "".join(lines[start_index:end_index]).strip()

        except Exception:
            return None
