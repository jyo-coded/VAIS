"""
agents/base_agent.py
────────────────────
VAIS Agent base class.
- Uses google.adk.Agent for multi-agent orchestration (ADK preserved as requested).
- Also holds a direct OllamaClient for fast parallel generation.
- Pipeline messages are short status lines; only Yamabiko uses the LLM for patch suggestions.
"""
from __future__ import annotations
import time
import logging
from typing import Literal, Optional

log = logging.getLogger(__name__)


class BaseVAISAgent:
    """
    VAIS Agent — wraps google.adk.Agent for orchestration metadata,
    and uses OllamaClient directly for fast generation.
    """

    def __init__(
        self,
        name: str,
        species: str,
        description: str,
        emoji: str,
        colour_hex: str,
        system_instruction: str,
    ):
        self.name = name
        self.species = species
        self.description = description
        self.emoji = emoji
        self.colour_hex = colour_hex
        self.system_instruction = system_instruction
        self.shared_messages: list[dict] = []

        # Try registering with google.adk (orchestration metadata only — NOT used for generation)
        try:
            from google.adk import Agent
            self.adk_agent = Agent(
                name=name,
                model="gemini-2.0-flash",   # ADK metadata model; actual generation goes via OllamaClient
                instructions=system_instruction,
            )
        except Exception as e:
            log.debug(f"[{name}] ADK agent registration skipped: {e}")
            self.adk_agent = None

    # ── LLM Generation via OllamaClient (bypasses ADK for speed) ────────────

    def _get_client(self):
        from agents.llm_client import OllamaClient
        return OllamaClient()

    async def generate_async(self, prompt: str, max_tokens: int = 400) -> Optional[str]:
        """
        Non-blocking generation. Tries Ollama first; falls back gracefully.
        Returns None if Ollama is down — callers should use rule-based text instead.
        """
        import asyncio, functools
        client = self._get_client()
        try:
            loop = asyncio.get_event_loop()
            result: str = await asyncio.wait_for(
                loop.run_in_executor(None, functools.partial(client.generate, prompt, self.system_instruction)),
                timeout=60,
            )
            return result.strip() if result else None
        except Exception as e:
            log.warning(f"[{self.name}] Ollama generate failed: {e}")
            return None

    # ── Message Factory ──────────────────────────────────────────────────────

    def send_message(
        self,
        text: str,
        message_type: Literal["info", "warning", "critical", "patch_request", "status"] = "info",
        vuln_id: Optional[str] = None,
        patch_diff: Optional[str] = None,
    ) -> dict:
        msg: dict = {
            "agent_name": self.name,
            "species": self.species,
            "emoji": self.emoji,
            "colour": self.colour_hex,
            "text": text,
            "timestamp": time.time(),
            "message_type": message_type,
        }
        if vuln_id:
            msg["vuln_id"] = vuln_id
        if patch_diff:
            msg["patch_diff"] = patch_diff
        self.shared_messages.append(msg)
        return msg
