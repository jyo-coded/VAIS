"""
backend/app.py — VAIS 2.0 Backend
Flask + SocketIO multi-agent pipeline.
"""
import os, sys, threading, base64, asyncio, traceback
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.phase1 import run_phase1
from rules.engine import run_phase2
from ml.phase3 import run_phase3
from ml.phase4 import run_phase4
from agents.phase5 import run_phase5_async
from agents.llm_client import OllamaClient
from config import OLLAMA_BASE_URL, OLLAMA_MODEL, GEMINI_API_KEY, GEMINI_MODEL

app = Flask(__name__, static_folder="../frontend/dist", static_url_path="")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

SCAN_CACHE: dict   = {}   # file_path → scan result
PATCH_HISTORY: list = []
UPLOAD_DIR = PROJECT_ROOT / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

IGNORED = {".git",".venv","venv","node_modules","dist","build","__pycache__",".pytest_cache",".mypy_cache","uploads"}
SRC_EXT  = {".c",".cpp",".cc",".h",".hpp",".py",".go",".java",".js",".ts",".jsx",".tsx"}

# ── Gemini chatbox client ──────────────────────────────────────────────────────
def _gemini_chat_stream(user_text: str, context: str = "", agent_identity: str = "VAIS Assistant"):
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        system = (
            f"You are {agent_identity}, an expert cybersecurity AI embedded in the VAIS 2.0 "
            "Vulnerability Analysis & Intelligence System. You know about:\n"
            "- Tanuki (Recon agent): maps attack surface, entry points\n"
            "- Tsushima (Memory Safety): detects buffer overflows, UAF, double-free\n"
            "- Iriomote (Taint Flow): traces untrusted data from source to sink\n"
            "- Raijū (ML Risk Scoring): CodeBERT + GNN + XGBoost ensemble\n"
            "- Yamabiko (Patch Strategy): generates and applies security patches\n"
            "- CWE IDs, CERT-C, OWASP Top 10, CVSS scoring\n"
            "Answer concisely and helpfully. If a question is about an agent's function, "
            "explain what that agent does in the VAIS pipeline. Keep sentences short and punchy.\n"
            + (f"Recent scan context:\n{context}\n" if context else "")
        )
        response = model.generate_content(f"{system}\n\nUser: {user_text}", stream=True)
        for chunk in response:
            if chunk.text:
                yield chunk.text
    except Exception as e:
        # Fallback to Ollama
        try:
            client = OllamaClient()
            if client.is_alive():
                yield from client.generate_stream(
                    f"You are {agent_identity}. {user_text}",
                    system="Expert cybersecurity assistant for the VAIS vulnerability analysis platform."
                )
                return
        except Exception:
            pass
        yield (
            f"I'm {agent_identity}. I can answer questions about the scan results, agents (Tanuki, Tsushima, "
            "Iriomote, Raijū, Yamabiko), vulnerability types, and remediation strategies. "
            "The AI model is currently offline — please check your Gemini API key or start Ollama."
        )

# ── Utility ───────────────────────────────────────────────────────────────────
def build_file_tree(directory: str) -> list:
    tree = []
    try:
        for e in sorted(os.scandir(directory), key=lambda x: (not x.is_dir(), x.name)):
            if e.name in IGNORED or e.name.startswith("."):
                continue
            node = {"name": e.name, "path": os.path.relpath(e.path, str(PROJECT_ROOT)), "type": "directory" if e.is_dir() else "file"}
            if e.is_dir():
                node["children"] = build_file_tree(e.path)
                if not node["children"]: continue
            else:
                if Path(e.name).suffix.lower() not in SRC_EXT: continue
                cached = SCAN_CACHE.get(node["path"], {"status":"unscanned","findings":{"critical":0,"high":0}})
                node["status"]   = cached["status"]
                node["findings"] = cached["findings"]
            tree.append(node)
    except Exception as exc:
        print(f"tree error {directory}: {exc}")
    return tree

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/api/files")
def get_files():
    return jsonify(build_file_tree(str(PROJECT_ROOT)))

@app.route("/api/samples")
def get_samples():
    lang_map = {".c":"C",".cpp":"C++",".go":"Go",".java":"Java",".py":"Python"}
    desc_map = {
        "vulnerable.c":    "Buffer overflows, format strings, strcpy misuse",
        "vulnerable.cpp":  "Memory leaks, UAF, double-free, integer overflow",
        "vulnerable.go":   "Race conditions, unchecked errors, unsafe pointers",
        "vulnerable.java": "SQL injection, XXE, hardcoded secrets, weak crypto",
        "vulnerable.py":   "eval injection, pickle deserialization, path traversal",
    }
    out = []
    sd = PROJECT_ROOT / "tests" / "samples"
    if sd.exists():
        for f in sorted(sd.iterdir()):
            if f.suffix.lower() in SRC_EXT:
                out.append({
                    "name": f.name,
                    "path": str(f.relative_to(PROJECT_ROOT)),
                    "language": lang_map.get(f.suffix.lower(), f.suffix[1:].upper()),
                    "description": desc_map.get(f.name, "Demo vulnerable file"),
                    "size_bytes": f.stat().st_size,
                })
    return jsonify(out)

@app.route("/api/plots")
def get_plots():
    plots = {}
    # Phase 4 saves plots to vapt_output/phase4/plots/
    plots_dir = PROJECT_ROOT / "vapt_output" / "phase4" / "plots"
    for name in ["confusion_matrix","roc_curve","pr_curve","feature_importance"]:
        p = plots_dir / f"{name}.png"
        if p.exists():
            with open(p,"rb") as f:
                plots[name] = base64.b64encode(f.read()).decode()
        else:
            plots[name] = ""
    return jsonify(plots)

@app.route("/api/system/status")
def get_system_status():
    ollama = OllamaClient()
    reachable = ollama.is_alive()
    return jsonify({
        "backend": "connected",
        "ollama": {"reachable": reachable, "model": OLLAMA_MODEL, "base_url": OLLAMA_BASE_URL, "mode": "ollama" if reachable else "fallback"},
    })

@app.route("/api/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400
    f = request.files["file"]
    dest = UPLOAD_DIR / Path(f.filename).name
    f.save(str(dest))
    return jsonify({"path": str(dest.relative_to(PROJECT_ROOT))})

@app.route("/api/patches")
def get_patches():
    return jsonify(PATCH_HISTORY)

# ── Scan Pipeline ──────────────────────────────────────────────────────────────
def _emit(sid: str, event: str, data: dict):
    socketio.emit(event, data, room=sid)

def run_scan_pipeline(sid: str, file_path: str, lang: str):
    def status(text: str, agent="System", colour="#E85D04"):
        _emit(sid, "agent_message", {
            "agent_name": agent, "species": "Orchestrator",
            "colour": colour, "text": text, "message_type": "status",
        })

    try:
        resolved = PROJECT_ROOT / file_path
        if not resolved.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        SCAN_CACHE[file_path] = {"status": "scanning", "findings": {"critical":0,"high":0}}
        ollama_up = OllamaClient().is_alive()

        status(
            f"Pipeline started for {file_path}. "
            + ("Ollama online — AI analysis enabled." if ollama_up else "Ollama offline — rule-based mode."),
            "System", "#E85D04"
        )

        # Read source code to stream to UI
        try:
            source_code = resolved.read_text(encoding="utf-8", errors="replace")
        except Exception:
            source_code = ""

        if source_code:
            _emit(sid, "source_code", {"path": file_path, "code": source_code[:8000]})

        # ── Phase 1 ──
        status("Tanuki: Parsing AST and mapping call graph...", "Tanuki", "#E85D04")
        p1 = run_phase1(file_path, lang_override=lang, verbose=False)

        # ── Phase 2 ──
        status("Tsushima: Running security rule engine...", "Tsushima", "#3B82F6")
        p2 = run_phase2(p1, verbose=False)
        n_candidates = len(p2.collection) if hasattr(p2, "collection") else 0
        status(f"Tsushima: {n_candidates} candidate vulnerabilities found.", "Tsushima", "#3B82F6")

        # ── Phase 3 ──
        status("Iriomote: Extracting ML features and tracing taint paths...", "Iriomote", "#10B981")
        p3 = run_phase3(p2, p1, verbose=False)

        # ── Phase 4 ──
        status("Raijū: Running ML ensemble (XGBoost + CodeBERT + GNN)...", "Raijū", "#8B5CF6")
        p4 = run_phase4(p3, output_dir=str(PROJECT_ROOT/"vapt_output"/"phase4"), verbose=False, with_evaluation=True)
        n_scored = len(p4.scored_vulns)
        n_high   = sum(1 for v in p4.scored_vulns if v.is_high_risk)
        status(f"Raijū: {n_scored} findings scored. {n_high} high-risk confirmed.", "Raijū", "#8B5CF6")

        # ── Phase 5 (Agents stream) ──
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def stream():
            async for msg in run_phase5_async(p4):
                _emit(sid, "agent_message", msg)

        loop.run_until_complete(stream())

        # ── Finalise ──
        crit = len([v for v in p4.scored_vulns if str(getattr(v,"severity","")).upper()=="CRITICAL"])
        high = len([v for v in p4.scored_vulns if str(getattr(v,"severity","")).upper()=="HIGH"])
        st   = "vuln" if (crit+high) > 0 else "clean"
        results = [v.to_dict() for v in p4.scored_vulns]

        SCAN_CACHE[file_path] = {"status": st, "findings": {"critical":crit,"high":high}, "full_results": results}
        _emit(sid, "scan_complete", {"file_path": file_path, "status": st, "findings": {"critical":crit,"high":high}, "results": results})

    except Exception as exc:
        traceback.print_exc()
        _emit(sid, "agent_message", {
            "agent_name": "System", "species": "Error", "colour": "#f87171",
            "text": f"Pipeline error: {exc}", "message_type": "critical",
        })

# ── Socket Events ─────────────────────────────────────────────────────────────
@socketio.on("trigger_scan")
def handle_scan(data):
    sid = request.sid
    threading.Thread(
        target=run_scan_pipeline,
        args=(sid, data.get("path",""), data.get("lang","auto")),
        daemon=True
    ).start()

@socketio.on("confirm_patch")
def handle_patch(data):
    vid = data.get("vuln_id")
    approved = data.get("approved", False)
    status = "applied" if approved else "skipped"
    if approved:
        PATCH_HISTORY.append({"vuln_id": vid, "status": status})
    emit("patch_status", {"vuln_id": vid, "status": status})
    emit("agent_message", {
        "agent_name": "Yamabiko", "species": "Mountain Echo Spirit",
        "colour": "#F59E0B",
        "text": f"Patch for {vid} {'applied ✓' if approved else 'skipped —'} recorded.",
        "message_type": "info",
    })

@socketio.on("user_message")
def handle_user_message(data):
    sid   = request.sid
    text  = data.get("text","").strip()
    if not text:
        return

    # Build context from recent scan
    ctx_parts = []
    for path, cached in list(SCAN_CACHE.items())[-1:]:
        if "full_results" in cached:
            top = cached["full_results"][:3]
            ctx_parts.append(f"Recent scan of {path}: " + "; ".join(
                f"{v['vuln_id']} {v['severity']} {v['title']}" for v in top
            ))
    context = "\n".join(ctx_parts)

    def respond():
        import os
        text_lower = text.lower()
        reply_agent = "VAIS Assistant"
        reply_colour = "#F0C05D"
        reply_species = "Chatbox AI"

        if "iriomote" in text_lower:
            reply_agent = "Iriomote"
            reply_colour = "#10B981"
            reply_species = "TAINT FLOW"
        elif "tanuki" in text_lower:
            reply_agent = "Tanuki"
            reply_colour = "#E85D04"
            reply_species = "RECON"
        elif "tsushima" in text_lower:
            reply_agent = "Tsushima"
            reply_colour = "#3B82F6"
            reply_species = "MEMORY SAFETY"
        elif "raiju" in text_lower or "raijū" in text_lower:
            reply_agent = "Raijū"
            reply_colour = "#8B5CF6"
            reply_species = "ML RISK SCORING"
        elif "yamabiko" in text_lower:
            reply_agent = "Yamabiko"
            reply_colour = "#F59E0B"
            reply_species = "PATCH STRATEGY"

        msg_id = os.urandom(4).hex()
        
        socketio.emit("agent_message", {
            "id": msg_id,
            "agent_name": reply_agent,
            "species": reply_species,
            "colour": reply_colour,
            "text": "Thinking...",
            "message_type": "info",
        }, room=sid)

        full_reply = ""
        for chunk in _gemini_chat_stream(text, context, reply_agent):
            full_reply += chunk
            socketio.emit("agent_message_update", {
                "id": msg_id,
                "text": full_reply
            }, room=sid)

    threading.Thread(target=respond, daemon=True).start()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=False,
                 allow_unsafe_werkzeug=True, use_reloader=False)
