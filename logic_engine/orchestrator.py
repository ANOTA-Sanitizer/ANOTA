import json
from datetime import datetime
from typing import TypedDict, Annotated, List, Dict, Any, Optional
from langgraph.graph import StateGraph, END
from logic_engine.blackboard import blackboard
from logic_engine.agentic_knowledge_scanner import AgenticKnowledgeScanner
from logic_engine.observer import Observer
from logic_engine.reasoning_engine import ReasoningEngine
from logic_engine.agentic_codebase_scanner import AgenticCodebaseScanner
from logic_engine.executor import Executor
import os
import asyncio

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
    challenges: List[Dict[str, Any]]
    current_challenge_index: int
    observation: Dict[str, Any]
    next_action: str

class MockMemory:
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.codebase = type('obj', (object,), {
            'root_path': self.repo_path, 
            'run_command': lambda self, cmd, kwargs: {}, 
            '_run_command': lambda self, cmd, kwargs: {"projects": [{"name": "dvwa", "root_path": "/home/kali/Desktop/mac-blm-dast/eval/dvwa"}]}
        })()

class AgentOrchestrator:
    def __init__(self, project_name: str, repo_path: str = None, project_root: str = None, knowledge_base_path: str = None):
        self.project_name = project_name
        self.repo_path = repo_path or os.getcwd()
        self.project_root = project_root or os.getcwd()
        self.knowledge_base_path = knowledge_base_path or "../Qbrain/obsidian_vault"
        
        self.blackboard = blackboard
        self.scanner = AgenticKnowledgeScanner(self.knowledge_base_path)
        self.codebase_scanner = AgenticCodebaseScanner(self.repo_path, self.knowledge_base_path, self.blackboard)
        self.observer = Observer()
        self.reasoner = ReasoningEngine(self.knowledge_base_path)
        self.executor = Executor()
        self.memory = MockMemory(self.repo_path)
        
        self.observer.start_listening()
        
        self.app = self._build_graph()

    async def _static_discovery_node(self, state: AgentState) -> AgentState:
        print("[*] Running Static Discovery...")
        target_path = self.memory.codebase.root_path
        
        # 1. Build a structural index of the vault first
        print("[*] Building initial vault structural index...")
        knowledge_map = await self.scanner.scan_vault()

        # 2. Scan Codebase with the structural index
        # This will find entrypoints and potentially enrich findings IF the index has AKUs.
        # But the index doesn't have AKUs yet.
        print("[*] Scanning Codebase...")
        scan_results = await self.codebase_scanner.scan(knowledge_index=knowledge_map)
        
        # 3. Now enrich the vault with AKUs for the discovered entrypoints
        print("[*] Starting Agentic Knowledge Scan to enrich vault...")
        knowledge_map = await self.scanner.scan_relevant_vault(scan_results["entrypoints"])

        # 4. Perform Agentic Codebase Scanning (Probe-and-Synthesize)
        print("[*] Performing Agentic Codebase Scanning (Probe-and-Synthesize)...")
        code_facts = await self.codebase_scanner.scan_and_synthesize(knowledge_index=knowledge_map)

        # Populate Blackboard
        self.blackboard.add_fact("discovered_entrypoints", scan_results["entrypoints"])
        self.blackboard.add_fact("technical_context", scan_results["technical_context"])
        self.blackboard.add_fact("attack_surface", scan_results["attack_surface"])
        self.blackboard.add_fact("knowledge_map", knowledge_map)
        self.blackboard.add_fact("code_facts", code_facts)

        # Update State
        state["context"]["discovered_entrypoints"] = scan_results["entrypoints"]
        state["context"]["technical_context"] = scan_results["technical_context"]
        state["context"]["attack_surface"] = scan_results["attack_surface"] + code_facts
        state["context"]["knowledge_map"] = knowledge_map
        state["findings"] = code_facts


        return state

    def _challenge_generation_node(self, state: AgentState) -> AgentState:
        print("[*] Generating Challenges...")
        attack_surface = state["context"].get("attack_surface", [])
        challenges = []

        for idx, finding in enumerate(attack_surface):
            challenge = {
                "id": f"CHALLENGE_{idx:03d}",
                "type": finding["type"],
                "target": f"{finding['file']}:{finding['line_range'][0]}",
                "description": f"Validate potential {finding['type']} vulnerability at {finding['file']}:{finding['line_range'][0]}",
                "status": "pending",
                "evidence": finding
            }
            challenges.append(challenge)

        state["challenges"] = challenges
        state["current_challenge_index"] = 0
        self.blackboard.add_fact("active_challenges", challenges)
        print(f"    [+] Generated {len(challenges)} challenges")
        
        return state

    def _requester_node(self, state: AgentState) -> AgentState:
        print("[*] Requester: Selecting next challenge...")
        idx = state.get("current_challenge_index", 0)
        challenges = state.get("challenges", [])

        if idx < len(challenges):
            challenge = challenges[idx]
            print(f"    [>] Next challenge: {challenge['id']} - {challenge['description']}")
            state["next_action"] = f"execute_{challenge['id']}"
            self.blackboard.add_fact("active_challenge", challenge)
            return state
        else:
            print("    [-] No more challenges left.")
            state["next_action"] = "complete"
            self.blackboard.add_fact("active_challenge", None)
            return state

    async def _executor_node(self, state: AgentState) -> AgentState:
        print("[*] Executor: Running payload...")
        idx = state.get("current_challenge_index", 0)
        challenges = state.get("challenges", [])

        if idx < len(challenges):
            challenge = challenges[idx]
            print(f"    [>] Executing payload for {challenge['id']} on {challenge['target']}")
            
            # Record start time to ensure we get the telemetry from THIS execution
            start_time = datetime.now()
            
            result = await self.executor.run_payload(challenge, self.codebase_scanner)
            
            # Check if the Observer captured anything in the blackboard during this run
            observation_entry = self.blackboard.get_latest_fact_entry("last_observation")
            if observation_entry:
                # If observation has a timestamp, check if it's recent
                obs_timestamp_str = observation_entry.get("timestamp")
                if obs_timestamp_str:
                    try:
                        obs_time = datetime.fromisoformat(obs_timestamp_str)
                        if obs_time > start_time:
                            observation = observation_entry.get("value") or observation_entry.get("content")
                            result["telemetry"] = observation
                            print("    [+] Merged telemetry from Observer.")
                    except Exception as e:
                        print(f"    [!] Failed to parse observation timestamp: {e}")
            
            state["execution_result"] = result
            self.blackboard.add_fact("last_execution_result", result)
        else:
            state["execution_result"] = {"status": "none"}

        return state

    def _observer_node(self, state: AgentState) -> AgentState:
        print("[*] Observer: Analyzing telemetry...")
        observation = self.blackboard.get_latest_fact("last_observation")
        if not observation:
            observation = {"telemetry": "No telemetry captured", "status": "empty"}
        
        print(f"    [>] Captured: {observation}")
        state["observation"] = observation
        return state

    async def _reasoning_node(self, state: AgentState) -> AgentState:
        print("[*] Reasoning Engine: Evaluating findings...")
        execution_result = state.get("execution_result", {})
        observation = state.get("observation", {})
        knowledge_map = state.get("context", {}).get("knowledge_map")
        
        print(f"    [>] Correlating Execution Result: {json.dumps(execution_result)}")
        print(f"    [>] with Observation: {json.dumps(observation)}")
        
        verdict = await self.reasoner.correlate(execution_result, observation, knowledge_map)
        
        print(f"    [>] Verdict: {json.dumps(verdict)}")
        state["verdict"] = verdict
        self.blackboard.add_fact("last_verdict", verdict)
        
        # Mark challenge as completed
        idx = state.get("current_challenge_index", 0)
        challenges = state.get("challenges", [])
        if idx < len(challenges):
            completed = state.get("completed_targets", [])
            completed.append(challenges[idx]["id"])
            state["completed_targets"] = completed
        
        # Increment index for next challenge
        state["current_challenge_index"] = idx + 1
        return state

    def _should_continue(self, state: AgentState) -> str:
        idx = state.get("current_challenge_index", 0)
        challenges = state.get("challenges", [])
        if idx < len(challenges):
            return "continue"
        return "end"

    def _build_graph(self) -> Any:
        workflow = StateGraph(AgentState)

        workflow.add_node("static_discovery", self._static_discovery_node)
        workflow.add_node("challenge_generation", self._challenge_generation_node)
        workflow.add_node("requester", self._requester_node)
        workflow.add_node("executor", self._executor_node)
        workflow.add_node("observer", self._observer_node)
        workflow.add_node("reasoning", self._reasoning_node)

        workflow.set_entry_point("static_discovery")
        workflow.add_edge("static_discovery", "challenge_generation")
        workflow.add_edge("challenge_generation", "requester")
        workflow.add_edge("requester", "executor")
        workflow.add_edge("executor", "observer")
        workflow.add_edge("observer", "reasoning")
        
        workflow.add_conditional_edges(
            "reasoning",
            self._should_continue,
            {
                "continue": "requester",
                "end": END
            }
        )

        return workflow.compile()

