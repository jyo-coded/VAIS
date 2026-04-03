"""
core/taint_analyzer.py
──────────────────────
Provides Taint Analysis mapping sources to sinks using NetworkX.
Exposes TaintAnalyzer to assess reachability for Phase 2 VulnObjects.
"""

from __future__ import annotations
import networkx as nx
from dataclasses import dataclass, field
from rules.vuln_object import VulnObject
import logging

log = logging.getLogger(__name__)

# Module-level dictionaries tracking sources/sinks
SOURCE_FUNCTIONS = {
    "argv": "Command line argument injection vector",
    "stdin": "Standard input stream",
    "getenv": "Environment variable injection",
    "recv": "Network socket receiver",
    "read": "File or descriptor reader",
    "fgets": "Stream string reader",
    "scanf": "Formatted input reader"
}

SINK_FUNCTIONS = {
    "strcpy": "CWE-120: Buffer Copy without Checking Size",
    "gets": "CWE-242: Use of Inherently Dangerous Function",
    "sprintf": "CWE-120: Buffer Copy without Checking Size",
    "system": "CWE-78: OS Command Injection",
    "printf": "CWE-134: Use of Externally-Controlled Format String",
    "memcpy": "CWE-120: Buffer Copy without Checking Size",
    "exec": "CWE-78: OS Command Injection",
    "popen": "CWE-78: OS Command Injection"
}

@dataclass
class TaintResult:
    vuln_id: str
    taint_confirmed: bool = False
    source_name: str = ""
    sink_name: str = ""
    taint_path: list[str] = field(default_factory=list)
    human_readable_path: str = ""

class TaintAnalyzer:
    """
    Evaluates execution routes from tainted sources ending in sensitive sinks 
    within the AST CallGraph context.
    """
    
    def analyze(self, nx_graph: nx.DiGraph, vulns: list[VulnObject]) -> list[TaintResult]:
        """
        Cross-validates Phase 2 VulnObjects against NetworkX shortest_paths.
        """
        results = []
        for vuln in vulns:
            # We look for a path from any SOURCE_FUNCTION in the call graph 
            # to the function containing the vulnerability.
            # Additionally, check if the vulnerability itself triggers a SINK function.
            target_func = vuln.function_name
            
            taint_result = TaintResult(vuln_id=vuln.vuln_id)
            
            # Since NetworkX graph nodes are function names:
            best_path = None
            detected_source = None
            
            for source in SOURCE_FUNCTIONS:
                if source in nx_graph and target_func in nx_graph:
                    try:
                        if nx.has_path(nx_graph, source, target_func):
                            path = nx.shortest_path(nx_graph, source, target_func)
                            if best_path is None or len(path) < len(best_path):
                                best_path = path
                                detected_source = source
                    except nx.NetworkXError:
                        continue
                        
            if best_path:
                taint_result.taint_confirmed = True
                taint_result.source_name = detected_source
                taint_result.taint_path = best_path
                
                # Check for sink
                for sink in SINK_FUNCTIONS:
                    if target_func == sink or (sink in nx_graph and nx.has_path(nx_graph, target_func, sink)):
                        taint_result.sink_name = sink
                        # Map full path out
                        try:
                            down_path = nx.shortest_path(nx_graph, target_func, sink)
                            # avoid duplicating target_func
                            if len(down_path) > 1:
                                best_path = best_path + down_path[1:]
                            break
                        except nx.NetworkXError:
                            pass
                
                taint_result.taint_path = best_path
                taint_result.human_readable_path = " → ".join(best_path)
                
                # Mutate VulnObject securely
                vuln.taint_confirmed = True
                vuln.taint_path = taint_result.human_readable_path
                vuln.add_agent_note(f"Taint Confirmed: {taint_result.human_readable_path}")
            
            results.append(taint_result)
            
        return results
