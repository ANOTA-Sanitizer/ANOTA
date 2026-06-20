import os
from langchain_ollama import ChatOllama

class AgentConfig:
    """
    Central configuration for MAC-DAST agents and Ollama connection.
    """
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://10.0.2.2:11434")
    
    # Models
    REASONING_MODEL = "qwen2.5-coder:7b"  # 1M context, great for orchestration
    CODER_MODEL = "qwen2.5-coder:7b"        # Specialized for code and uprobe traces
    EMBED_MODEL = "bge-m3:latest"
    
    # Logic Parameters
    RRF_K = 60
    CONFIDENCE_DECAY = 0.9

    @classmethod
    def get_embedding(cls, text):
        import requests
        response = requests.post(
            f"{cls.OLLAMA_BASE_URL}/api/embeddings",
            json={
                "model": cls.EMBED_MODEL,
                "prompt": text
            }
        )
        response.raise_for_status()
        return response.json()["embedding"]

    @classmethod
    def get_llm(cls, model_type="reasoning"):
        model_name = cls.REASONING_MODEL if model_type == "reasoning" else cls.CODER_MODEL
        return ChatOllama(
            base_url=cls.OLLAMA_BASE_URL,
            model=model_name,
            temperature=0,
            format="json" # Enforce JSON for structured tool use
        )
