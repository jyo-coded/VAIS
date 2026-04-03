"""
agents/llm_client.py
────────────────────
Lightweight REST client for communicating with the local Ollama instance.
Bypasses heavy LangChain dependencies for speed and stability.
"""

from __future__ import annotations
import json
import logging
import requests
from typing import Optional
from config import OLLAMA_BASE_URL, OLLAMA_MODEL

log = logging.getLogger(__name__)

class OllamaClient:
    """Wrapper for Ollama /api/generate REST API."""
    
    def __init__(self, base_url: str = OLLAMA_BASE_URL, model: str = OLLAMA_MODEL):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = 60  # seconds

    def generate(self, prompt: str, system: Optional[str] = None, json_format: bool = False) -> str:
        """
        Produce a generation based on prompt.
        If json_format is True, restricts model output to JSON.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        
        if system:
            payload["system"] = system
            
        if json_format:
            payload["format"] = "json"

        endpoint = f"{self.base_url}/api/generate"
        
        try:
            resp = requests.post(endpoint, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
        except requests.exceptions.RequestException as e:
            log.error(f"Ollama generation failed: {e}")
            raise

    def generate_stream(self, prompt: str, system: Optional[str] = None):
        """
        Produce a streamed generation via generator yielding word chunks.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": True,
        }
        
        if system:
            payload["system"] = system

        endpoint = f"{self.base_url}/api/generate"
        
        try:
            with requests.post(endpoint, json=payload, stream=True, timeout=self.timeout) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if line:
                        data = json.loads(line)
                        yield data.get("response", "")
        except Exception as e:
            log.error(f"Ollama stream failed: {e}")
            yield f"\n[Ollama error: {e}]"
        except requests.exceptions.RequestException as e:
            log.error(f"Ollama generation failed: {e}")
            raise RuntimeError(f"Ollama communication error: {e}")

    def is_alive(self) -> bool:
        """Ping the model list to ensure it's up and accessible."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = [m.get("name") for m in resp.json().get("models", [])]
                if self.model in models or f"{self.model}:latest" in models or any(self.model in m for m in models):
                    return True
                log.warning(f"Model {self.model} not found in Ollama tags: {models}")
                return False
            return False
        except requests.exceptions.RequestException:
            return False
