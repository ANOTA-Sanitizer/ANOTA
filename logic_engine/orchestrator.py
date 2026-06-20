from typing import TypedDict, Annotated, List, Dict, Any, Optional
from langgraph.graph import StateGraph, END
from logic_engine.blackboard import Blackboard
from logic_engine.knowledge_scanner import KnowledgeScanner
from logic_engine.observer import Observer
from logic_engine.reasoning_engine import ReasoningEngine
from logic_engine.codebase_scanner import CodebaseScanner
import os

class AgentState(TypedDict):
    task: str
    trace_id: str
    original_trace_id: str
    target_script: Optional[str]
    target_queue: List[str]
    completed_targets: List[str]
    context: Dict[str, Any]
    blm: Dict[str, Any]
    attack_hypothesis: Dict[str, Any]
    execution_result: Dict[str, Any]
    verdict: Dict[str, Any]
    repro_script: str
    findings: List[Dict[str, Any]]
    next_action: str

class AgentOrchestrator:
    def __init__(self, project_name: str, repo_path: str = None, knowledge_base_path: str = None):
        self.project_name = project_name
        self.repo_path = repo_path or os.getcwd()
        self.knowledge_base_path = knowledge_base_path or "../Qbrain/obsidian_vault"
        
        self.blackboard = Blackboard(os.path.join(self.repo_path, "logic_engine/blackboard.json"))
        self.scanner = KnowledgeScanner(self.knowledge_base_path)
        self.codebase_scanner = CodebaseScanner(self.repo_path, os.path.join(self.knowledge_base_path, "rules"))
        self.observer = Observer()
        self.reasoner = ReasoningEngine()
        
        self.app = self._build_graph()

    def _static_discovery_node(self, state: AgentState) -> AgentState:
        print("[*] Running Static Discovery...")
        target_path = self.memory.codebase.root_path
        rules_path = os.path.join(self.knowledge_base_path, "rules")

        scan_results = self.codebase_scanner.scan()

        # Populate Blackboard
        self.blackboard.add_fact("discovered_entrypoints", scan_results["entrypoints"])
        self.blackboard.add_fact("technical_context", scan_results["technical_context"])
        self.blackboard.add_fact("attack_surface", scan_results["attack_surface"])

        # Update State
        state["context"]["discovered_entrypoints"] = scan_results["entrypoints"]
        state["context"]["technical_context"] = scan_results["technical_context"]
        state["context"]["attack_surface"] = scan_results["attack_surface"]

        return state

    def _dynamic_execution_node(self, state: AgentState) -> AgentState:
        print("[*] Running Dynamic Execution...")
        # Placeholder for Phase 3/4: Observation & Reasoning
        # In a real implementation, this would trigger payloads, 
        # observe telemetry via self.observer, and reason via self.reasoner.
        return state

    def _build_graph(self) -> Any:
        workflow = StateGraph(AgentState)

        workflow.add_node("static_discovery", self._static_discovery_node)
        workflow.add_node("dynamic_execution", self._dynamic_execution_node)

        workflow.set_entry_point("static_discovery")
        workflow.add_edge("static_discovery", "dynamic_execution")
        workflow.add_edge("dynamic_execution", END)

        return workflow.compile()

    # Mocking attributes expected by mac_dast_pipeline.py
    @property
    def executor(self):
        class MockExecutor:
            def __init__(self):
                self.php_runner = None
        return MockExecutor()

    @property
    def memory(self):
        class MockMemory:
            def __init__(self, repo_path):
                self.repo_path = repo_path
                self.codebase = type('obj', (object,), {'root_path': self.repo_path, 'run_command': lambda self, cmd, kwargs: {}, '_run_command': lambda self, cmd, kwargs: {"projects": [{"name": "dvwa", "root_path": "/home/kali/Desktop/mac-blm-dast/eval/dvwa"}]}})()
        return MockMemory(self.repo_path)
