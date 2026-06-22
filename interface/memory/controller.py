import json
import os
from threading import Lock

class MemoryController:
    """
    Manages the 4-tier memory consolidation pipeline for MAC-DAST agents.
    
    1. Working: Current LLM context window (handled by iii-engine/LangGraph).
    2. Episodic: Execution traces and state transitions (from BLM SQLite).
    3. Semantic: Knowledge graph of the codebase (from codebase-memory-mcp).
    4. Procedural: Reusable attack patterns and security rules (JSON/Vector).
    """
    def __init__(self, blm_db, codebase_client, projector=None):
        self.blm_db = blm_db
        self.codebase = codebase_client
        self.projector = projector

    def consolidate(self, decay_rate=None):
        """
        Background task to promote repeated Episodic patterns into Semantic memory.
        Also applies confidence decay to stale hypotheses.
        """
        from logic_engine.agent_config import AgentConfig
        decay_rate = decay_rate or AgentConfig.CONFIDENCE_DECAY
        
        # 1. Promote repeated transitions to Semantic knowledge
        self._promote_frequent_transitions()
        
        # 2. Apply exponential decay to confidence scores
        self._apply_confidence_decay(decay_rate)

    def _promote_frequent_transitions(self):
        """
        Identifies transitions observed multiple times across different traces
        and flags them as 'hardened' business logic rules.
        """
        cursor = self.blm_db.conn.cursor()
        # Find transitions observed across > 3 traces
        cursor.execute("""
            SELECT action_identifier, count(DISTINCT trace_id) as freq
            FROM transitions
            GROUP BY action_identifier
            HAVING freq >= 3
        """)
        frequent = cursor.fetchall()
        for action, freq in frequent:
            # Upsert into Semantic tier (using static_hints for now)
            self.blm_db.save_static_hint(
                "logic_rule", 
                action, 
                {"status": "hardened", "observation_count": freq}
            )

    def _apply_confidence_decay(self, decay_rate=0.9):
        """
        Decays confidence scores for observations and BLM edges over time.
        Confidence = Confidence * decay_rate for entries not accessed in the last 24h.
        """
        cursor = self.blm_db.conn.cursor()
        
        # Decay transitions not accessed in the last hour (for testing/demo purposes, 
        # real system would use 24h)
        cursor.execute("""
            UPDATE transitions 
            SET confidence_score = confidence_score * ? 
            WHERE last_accessed < datetime('now', '-1 hour')
        """, (decay_rate,))
        
        cursor.execute("""
            UPDATE observations 
            SET confidence_score = confidence_score * ? 
            WHERE last_accessed < datetime('now', '-1 hour')
        """, (decay_rate,))
        
        self.blm_db.conn.commit()

    def hybrid_search(self, query, k=None):
        """
        Performs Hybrid Search (BM25 + Vector) and unifies via Reciprocal Rank Fusion (RRF).
        """
        from logic_engine.agent_config import AgentConfig
        k = k or AgentConfig.RRF_K
        
        bm25_results = self._search_bm25(query)
        vector_results = self._search_vector(query)
        
        # RRF Algorithm: Score(d) = sum(1 / (k + rank(d)))
        scores = {}
        
        for rank, trace_id in enumerate(bm25_results, 1):
            scores[trace_id] = scores.get(trace_id, 0) + (1.0 / (k + rank))
            
        for rank, trace_id in enumerate(vector_results, 1):
            scores[trace_id] = scores.get(trace_id, 0) + (1.0 / (k + rank))
            
        # Sort by RRF score descending
        sorted_ids = sorted(scores.keys(), key=lambda x: scores[x], reverse=True)
        return sorted_ids

    def _search_bm25(self, query):
        """
        Full-text search using SQLite FTS5.
        """
        cursor = self.blm_db.conn.cursor()
        cursor.execute("""
            SELECT trace_id FROM observations_fts 
            WHERE content_summary MATCH ? 
            ORDER BY rank
        """, (query,))
        return [row[0] for row in cursor.fetchall()]

    def _search_vector(self, query):
        """
        Semantic search using Ollama embeddings and cosine similarity.
        """
        import numpy as np
        from logic_engine.agent_config import AgentConfig
        import struct
        
        # 1. Get query embedding
        query_vec = np.array(AgentConfig.get_embedding(query))
        
        # 2. Fetch all embeddings from DB
        cursor = self.blm_db.conn.cursor()
        cursor.execute("SELECT trace_id, embedding FROM vector_embeddings")
        rows = cursor.fetchall()
        
        results = []
        for trace_id, blob in rows:
            # Convert blob back to float array
            # Assuming float32, length depends on model (BGE-M3 is 1024)
            vec = np.frombuffer(blob, dtype=np.float32)
            
            # Compute cosine similarity
            similarity = np.dot(query_vec, vec) / (np.linalg.norm(query_vec) * np.linalg.norm(vec))
            results.append((trace_id, similarity))
            
        # Sort by similarity descending
        results.sort(key=lambda x: x[1], reverse=True)
        return [x[0] for x in results]

    async def add_vector_index_agentic(self, trace_id, text):
        """
        Agentic memory indexing: Summarizes large traces before embedding.
        Prevents information loss from blind truncation.
        """
        import numpy as np
        from logic_engine.agent_config import AgentConfig
        
        # 1. Logic-Aware Compression
        # If text is small, use it directly. If large, use Agent to compress.
        if len(text) > 4000:
            summarized_text = await self._compress_logic(text)
        else:
            summarized_text = text

        # 2. Generate and store embedding
        embedding = AgentConfig.get_embedding(summarized_text)
        blob = np.array(embedding, dtype=np.float32).tobytes()
        
        cursor = self.blm_db.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO vector_embeddings (trace_id, embedding)
            VALUES (?, ?)
        """, (trace_id, blob))
        self.blm_db.conn.commit()

    async def _compress_logic(self, raw_trace):
        """
        Uses the reasoning LLM to transform a raw trace into a dense logical narrative.
        Implements a recursive 'Reassessment' strategy for massive traces (>12k chars).
        """
        from logic_engine.agent_config import AgentConfig
        llm = AgentConfig.get_llm("reasoning")
        
        limit = 12000
        if len(raw_trace) > limit:
            print(f" [!] WARNING: Trace size ({len(raw_trace)} chars) exceeds single-pass limit ({limit}). Initiating tiered logic reassessment...")
            
            # 1. Chunked Reassessment
            chunks = [raw_trace[i:i + limit] for i in range(0, len(raw_trace), limit)]
            chunk_summaries = []
            
            for idx, chunk in enumerate(chunks):
                print(f" [*] Processing chunk {idx+1}/{len(chunks)} for logic extraction...")
                prompt = f"""
Summarize the logic flow of this TRACE SEGMENT ({idx+1}/{len(chunks)}).
Focus ONLY on state changes, function calls, and security checks.

TRACE SEGMENT:
{chunk}

SEGMENT LOGIC SUMMARY:
"""
                response = await llm.ainvoke(prompt)
                chunk_summaries.append(response.content)
            
            # 2. Global Synthesis
            print(f" [*] Synthesizing final global narrative from {len(chunk_summaries)} segments...")
            final_prompt = f"""
You are the MAC-DAST Global Logic Synthesizer.
Combine the following logic segments into a single, high-signal narrative of the business logic flow.

SEGMENTS:
{chr(10).join(chunk_summaries)}

GLOBAL LOGIC NARRATIVE:
"""
            final_response = await llm.ainvoke(final_prompt)
            return final_response.content

        # Normal single-pass compression
        prompt = f"""
You are the MAC-DAST Memory Compressor.
Transform the following raw execution trace into a dense, high-signal narrative of the business logic flow.
Focus on:
1. Initial State
2. Key functional line coverage (security checks, logic gates)
3. State Transitions (changes in session, cookies, or DB)
4. Final Outcome (Success, Error, or Redirect)

RAW TRACE:
{raw_trace}

COMPRESSED NARRATIVE:
"""
        response = await llm.ainvoke(prompt)
        return response.content

    def add_vector_index(self, trace_id, text):
        """
        Legacy blind truncation (deprecated for project tasks).
        """
        import numpy as np
        from logic_engine.agent_config import AgentConfig
        
        truncated_text = text[:4000]
        embedding = AgentConfig.get_embedding(truncated_text)
        blob = np.array(embedding, dtype=np.float32).tobytes()
        
        cursor = self.blm_db.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO vector_embeddings (trace_id, embedding)
            VALUES (?, ?)
        """, (trace_id, blob))
        self.blm_db.conn.commit()

    def mark_accessed(self, trace_id):
        """
        Resets the decay curve for a specific trace.
        """
        cursor = self.blm_db.conn.cursor()
        cursor.execute("""
            UPDATE transitions SET last_accessed = CURRENT_TIMESTAMP WHERE trace_id = ?
        """, (trace_id,))
        cursor.execute("""
            UPDATE observations SET last_accessed = CURRENT_TIMESTAMP WHERE trace_id = ?
        """, (trace_id,))
        self.blm_db.conn.commit()

    async def get_context_for_trace(self, trace_id):
        """
        Consolidates Episodic and Semantic memory for a specific execution trace.
        Filters codebase metadata to reduce LLM noise and prevents hallucinations.
        """
        # 1. Fetch Episodic Memory (What happened?)
        observation = self.get_observation(trace_id)

        # 2. Fetch Semantic Memory (What is the code structure?)
        from logic_engine.agents.php_profiler import PHPProfiler
        from logic_engine.agents.summarizer import CodeSummarizerAgent
        php_prof = PHPProfiler()
        summarizer = CodeSummarizerAgent(self)

        # Get root path for jail/resolution
        root = getattr(self.codebase, 'root_path', os.getcwd())

        # Files hit in trace (ensure absolute)
        raw_coverage = observation.get("coverage", {})
        if isinstance(raw_coverage, dict) and "coverage" in raw_coverage:
             # Unwrap if nested (from parser)
             raw_coverage = raw_coverage["coverage"]

        trace_files = {os.path.abspath(os.path.join(root, f)) for f in raw_coverage.keys()}
        print(f" [MEMORY] Trace files hit: {len(trace_files)}")
        files_to_inspect = set(trace_files)

        # Add ONLY relevant static dependencies from the DB
        cursor = self.blm_db.conn.cursor()
        cursor.execute("SELECT value FROM static_hints WHERE type = 'code_dependency'")
        dependencies = []
        for row in cursor.fetchall():
            dep = json.loads(row[0])
            # Resolve relative paths to absolute for comparison
            abs_from = os.path.abspath(os.path.join(root, dep["from"]))
            abs_to = os.path.abspath(os.path.join(root, dep["to"]))

            if abs_from in trace_files:
                dependencies.append(dep)
                files_to_inspect.add(abs_to)

        print(f" [MEMORY] Total files to inspect (including deps): {len(files_to_inspect)}")
        structural_context = []

        for file_path in files_to_inspect:
            # Determine role: PRIMARY vs DEPENDENCY
            rel_file = os.path.relpath(file_path, root)
            role = "PRIMARY_CONTROLLER" if any(rel_file == ep for ep in raw_coverage.keys()) else "DEPENDENCY"
            
            # A. Get high-value code summary using the LLM subagent
            if file_path.endswith(".php"):
                full_path = os.path.abspath(os.path.join(root, file_path))
                if os.path.exists(full_path) and full_path.startswith(os.path.abspath(root)):
                    clean_code = await summarizer.summarize(full_path)
                    structural_context.append({
                        "type": "code_summary", 
                        "file": rel_file,
                        "role": role,
                        "content": clean_code
                    })
            
            # B. Get filtered graph hints (Focus on importance/connectivity)
            hints = self.codebase.search(name_pattern=f".*{file_path}.*", search_type="graph")
            if isinstance(hints, list):
                for h in hints:
                    # Filter: Only keep nodes with high centrality or that are entry points
                    if h.get("in_degree", 0) > 1 or h.get("is_entry_point"):
                        structural_context.append({
                            "type": "graph_hint",
                            "name": h.get("name"),
                            "label": h.get("label"),
                            "importance": h.get("in_degree"),
                            "file": h.get("file_path")
                        })
            
        return {
            "episodic": observation,
            "semantic": structural_context,
            "dependencies": dependencies
        }

    def get_observation(self, trace_id):
        import json
        cursor = self.blm_db.conn.cursor()
        cursor.execute("SELECT * FROM observations WHERE trace_id = ?", (trace_id,))
        row = cursor.fetchone()
        if not row:
            print(f" [MEMORY] Trace ID not found in DB: {trace_id}")
            return {}
            
        print(f" [MEMORY] Retrieved trace {trace_id}, coverage_len: {len(row[4])}")
        return {
            "trace_id": row[1],
            "timestamp": row[2],
            "source": row[3],
            "coverage": json.loads(row[4]),
            "state": json.loads(row[5]),
            "events": json.loads(row[6])
        }
