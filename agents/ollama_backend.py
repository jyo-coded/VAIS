"""
agents/ollama_backend.py
────────────────────────
Custom Google ADK backend that routes LLM requests to local Ollama via raw HTTP REST.
Implements the required ADK interface bypassing standard cloud dependencies.
"""

from __future__ import annotations
import json
import logging
import requests
from typing import Any, AsyncGenerator

from google.adk.models import BaseLlm
from config import OLLAMA_BASE_URL, OLLAMA_MODEL

log = logging.getLogger(__name__)

class OllamaBackend(BaseLlm):
    """Custom BaseLlm routing ADK calls synchronously and asynchronously directly to Ollama."""
    
    # Define explicitly for Pydantic if BaseLlm inherits from it
    model_name: str = OLLAMA_MODEL
    base_url: str = OLLAMA_BASE_URL
    timeout: int = 120

    def generate(self, prompt: str, system_instruction: str | None = None, **kwargs: Any) -> str:
        """Synchronous generation."""
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
        }
        if system_instruction:
            payload["system"] = system_instruction
            
        endpoint = f"{self.base_url.rstrip('/')}/api/generate"
        try:
            resp = requests.post(endpoint, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json().get("response", "").strip()
        except Exception as e:
            log.error(f"Ollama generation failed: {e}")
            return f"Error connecting to Ollama: {e}"

    async def generate_async(self, prompt: str, system_instruction: str | None = None, **kwargs: Any) -> str:
        """Asynchronous generation."""
        import aiohttp
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
        }
        if system_instruction:
            payload["system"] = system_instruction
            
        endpoint = f"{self.base_url.rstrip('/')}/api/generate"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(endpoint, json=payload, timeout=self.timeout) as resp:
                    resp.raise_for_status()
                    data = await resp.json()
                    return data.get("response", "").strip()
        except Exception as e:
            log.error(f"Ollama async generation failed: {e}")
            return f"Error connecting to Ollama: {e}"

    # Minimal Duck Typing for ADK runners expectations
    def __call__(self, *args, **kwargs):
        if "prompt" in kwargs:
            return self.generate(kwargs["prompt"], kwargs.get("system_instruction"))
        elif len(args) > 0:
            return self.generate(args[0])
        return ""
