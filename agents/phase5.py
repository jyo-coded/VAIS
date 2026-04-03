"""
agents/phase5.py
────────────────
Phase 5 Entry Point: ADK Agentic Patching execution taking Phase 4 Results.
Yields asynchronous streams to the frontend dashboard.
"""
from __future__ import annotations
import logging
from typing import AsyncGenerator

from ml.phase4 import Phase4Result
from agents.orchestrator import VaisAdkOrchestrator

log = logging.getLogger(__name__)

class Phase5Result:
    """Encapsulates the messages from the agents directly to the UI layer."""
    def __init__(self):
        self.messages = []
        self.patch_confirmations_pending = []
        
    def add_message(self, msg: dict):
        self.messages.append(msg)
        if msg.get("message_type") == "patch_request":
            self.patch_confirmations_pending.append(msg)

async def run_phase5_async(phase4_result: Phase4Result) -> AsyncGenerator[dict, None]:
    """
    Initializes the ADK Pipeline and begins iterating via an Asynchronous Generator.
    This serves as the core pipeline runner directly feeding the Frontend Stream.
    """
    log.info("Starting Phase 5: Multi-Agent ADK Routing.")
    
    orchestrator = VaisAdkOrchestrator()
    phase5_result = Phase5Result()
    
    # Asynchronously iterate over each ADK agent's execution phase
    async for message in orchestrator.run_pipeline_async(phase4_result):
        phase5_result.add_message(message)
        yield message
        
    log.info(f"Phase 5 complete. Pending patch confirmations: {len(phase5_result.patch_confirmations_pending)}")

# For testing outside event loops:
def run_phase5_sync(phase4_result: Phase4Result) -> Phase5Result:
    import asyncio

    result = Phase5Result()

    async def _gather():
        async for msg in run_phase5_async(phase4_result):
            result.add_message(msg)

    try:
        asyncio.run(_gather())
    except RuntimeError:
        # Already inside an event loop (e.g. Jupyter) — use nest_asyncio
        import nest_asyncio
        nest_asyncio.apply()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_gather())

    return result
