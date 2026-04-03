"""
backend/server.py
─────────────────
FastAPI and python-socketio integration mapping VAIS Phase 5 ADK agents
back into a live React frontend.
"""
from __future__ import annotations
import os
import sys
import asyncio
from pathlib import Path

# Fix python path for VAIS core imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import socketio
import uvicorn

from core.phase1 import run_phase1
from rules.engine import run_phase2
from ml.phase3 import run_phase3
from ml.phase4 import run_phase4
from agents.phase5 import run_phase5_async

# Create SocketIO async server bridging to ASGI
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")

# Create FastAPI app
app = FastAPI(title="VAIS 2.0 Web Interface")

# Wrap SocketIO around FastAPI
socket_app = socketio.ASGIApp(sio, app)

@sio.event
async def connect(sid, environ):
    print(f"[{sid}] WebClient Connected.")

@sio.event
async def disconnect(sid):
    print(f"[{sid}] WebClient Disconnected.")

@sio.event
async def trigger_scan(sid, data):
    """
    Receives request to trigger scanning and streams Agent ADK outputs continuously.
    """
    target_dir = data.get("directory", "tests/samples/")
    await sio.emit("agent_stream", {
        "agent_name": "System",
        "species": "Core Engine",
        "emoji": "⚙️",
        "colour": "#333333",
        "text": f"Starting comprehensive VAIS analysis on {target_dir}...",
        "message_type": "info"
    }, to=sid)

    # Yield back to event loop
    await asyncio.sleep(0.1)

    try:
        # Phase 1-4 execute synchronously normally, 
        # but socket.io is Async ASGI, so wrap them in executors to not block socket pings
        loop = asyncio.get_event_loop()
        p1 = await loop.run_in_executor(None, run_phase1, target_dir, None, False)
        p2 = await loop.run_in_executor(None, run_phase2, p1, None, False)
        p3 = await loop.run_in_executor(None, run_phase3, p2, None, False)
        p4 = await loop.run_in_executor(None, run_phase4, p3, None, False)
        
        # Phase 5 handles Agent routing async!
        async for msg in run_phase5_async(p4):
            await sio.emit("agent_stream", msg, to=sid)
        
        await sio.emit("scan_complete", {"status": "success"}, to=sid)
        
    except Exception as e:
        await sio.emit("agent_stream", {
            "agent_name": "Exception",
            "species": "Error",
            "emoji": "❌",
            "colour": "#FF0000",
            "text": str(e),
            "message_type": "critical"
        }, to=sid)
        await sio.emit("scan_complete", {"status": "error"}, to=sid)

# Serve the compiled React Frontend cleanly dynamically targeting dist
dist_path = project_root / "frontend" / "dist"

@app.get("/")
async def serve_spa():
    index_file = dist_path / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"error": "Frontend dist not found. Did you run 'npm run build'?"}

# Mount static build folder for JS / CSS assets
if dist_path.exists():
    app.mount("/", StaticFiles(directory=str(dist_path)), name="static")

if __name__ == "__main__":
    port = 5000
    print(f"Starting VAIS API & Interface at http://localhost:{port}")
    uvicorn.run("backend.server:socket_app", host="0.0.0.0", port=port, reload=True, reload_dirs=["backend", "agents"])
