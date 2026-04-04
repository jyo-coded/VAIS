import { useEffect, useRef, useState, type CSSProperties } from 'react';
import { io, Socket } from 'socket.io-client';
import { ScanConsole } from './components/ScanConsole';
import { AgentTerminal, isUser } from './components/AgentTerminal';
import type { AgentMessage, AnyMessage } from './components/AgentTerminal';
import { MLAnalytics } from './components/MLAnalytics';
import { Documentation } from './components/Documentation';
import { AgentGlossary } from './components/AgentGlossary';
import { routeIntent } from './lib/IntentRouter';

type FileNode = {
  name: string; path: string; type: 'directory' | 'file';
  status?: 'unscanned' | 'scanning' | 'vuln' | 'clean';
  findings?: { critical: number; high: number };
  children?: FileNode[];
};

export type Finding = {
  vuln_id: string; cwe: string; rule_name: string; source_file: string; language: string;
  function_name: string; line_start: number; line_end: number; title: string; description: string;
  code_snippet: string; severity: string; confidence: number; taint_confirmed: boolean;
  taint_path?: string; standards_citation?: string; exploit_prob?: number; risk_score?: number;
  composite_risk: number; patch_strategy?: string; patch_applied?: boolean; status: string;
  agent_notes: string[]; ml_severity?: string;
};

export type PatchRecord = {
  id: string;
  vuln_id: string;
  rule_name: string;
  file_path: string;
  timestamp: string;
  strategy: string;
};

type PlotsResponse = Record<string, string>;

type SystemStatus = {
  backend: string;
  ollama: { reachable: boolean; model: string; base_url: string; mode: string };
};


type NavPage = 'console' | 'glossary' | 'analytics' | 'docs';

const NAV_LINKS: { id: NavPage; label: string }[] = [
  { id: 'console',   label: 'Console' },
  { id: 'glossary',  label: 'Agent Glossary' },
  { id: 'analytics', label: 'Analytics' },
  { id: 'docs',      label: 'Documentation' },
];

const initialStatus: SystemStatus = {
  backend: 'connecting',
  ollama: { reachable: false, model: 'qwen2.5-coder:7b', base_url: 'http://localhost:11434', mode: 'fallback' },
};

export default function App() {
  const [page, setPage] = useState<NavPage>('console');
  const [files, setFiles] = useState<FileNode[]>([]);
  const [messages, setMessages] = useState<AnyMessage[]>([]);
  const [scanningPath, setScanningPath] = useState<string | null>(null);
  const [activeAgent, setActiveAgent] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [plots, setPlots] = useState<PlotsResponse>({});
  const [status, setStatus] = useState<SystemStatus>(initialStatus);
  const [sourceCode, setSourceCode] = useState<{ path: string; code: string } | null>(null);
  const [patchHistory, setPatchHistory] = useState<PatchRecord[]>([]);

  const socketRef = useRef<Socket | null>(null);

  // Theme switching via IntersectionObserver
  useEffect(() => {
    if (page !== 'console') return;
    const hero = document.getElementById('section-hero');
    const agents = document.getElementById('section-agents');
    const insights = document.getElementById('section-insights');

    const obs = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (!e.isIntersecting) return;
        if (e.target.id === 'section-hero')    document.body.style.background = 'radial-gradient(ellipse at top, rgba(232,93,4,0.13), transparent 50%), #030101';
        if (e.target.id === 'section-agents')  document.body.style.background = 'radial-gradient(ellipse at 40% 0%, rgba(240,192,93,0.09), transparent 50%), #030101';
        if (e.target.id === 'section-insights') document.body.style.background = 'radial-gradient(ellipse at top, rgba(26,200,80,0.09), transparent 50%), #030101';
      });
    }, { threshold: 0.35 });

    if (hero) obs.observe(hero);
    if (agents) obs.observe(agents);
    if (insights) obs.observe(insights);

    return () => obs.disconnect();
  }, [page]);

  useEffect(() => {
    const loadFiles = async () => {
      try { setFiles((await (await fetch('/api/files')).json()) as FileNode[]); } catch {}
    };
    const loadPlots = async () => {
      try { setPlots((await (await fetch('/api/plots')).json()) as PlotsResponse); } catch {}
    };
    const loadStatus = async () => {
      try {
        const d = (await (await fetch('/api/system/status')).json()) as SystemStatus;
        setStatus(d);
      } catch { setStatus(prev => ({ ...prev, backend: 'unavailable' })); }
    };

    loadFiles(); loadPlots(); loadStatus();
    const statusInterval = setInterval(loadStatus, 15000);

    socketRef.current = io('/', { path: '/socket.io', transports: ['websocket', 'polling'] });

    socketRef.current.on('connect', () => setStatus(p => ({ ...p, backend: 'connected' })));
    socketRef.current.on('disconnect', () => setStatus(p => ({ ...p, backend: 'disconnected' })));

    socketRef.current.on('agent_message', (msg: AgentMessage) => {
      const knownAgents = ['Tanuki','Tsushima','Iriomote','Raiju','Raijū','Yamabiko'];
      if (knownAgents.includes(msg.agent_name)) setActiveAgent(msg.agent_name);
      else if (msg.message_type === 'status' && msg.agent_name !== 'System') setActiveAgent(msg.agent_name);
      setMessages(prev => [...prev, msg]);
    });

    socketRef.current.on('agent_message_update', (data: { id: string; text: string }) => {
      setMessages(prev => prev.map(m => (!isUser(m) && m.id === data.id) ? { ...m, text: data.text } : m));
    });

    socketRef.current.on('source_code', (data: { path: string; code: string }) => {
      setSourceCode(data);
    });

    socketRef.current.on('scan_results', (data: { findings: Finding[] }) => {
      setFindings(data.findings);
    });

    socketRef.current.on('scan_complete', (data: { results?: Finding[] }) => {
      setScanningPath(null);
      setActiveAgent(null);
      if (data.results) setFindings(data.results);
      loadFiles();
      // Refresh plots after scan
      setTimeout(() => loadPlots(), 1000);
    });

    socketRef.current.on('patch_status', (data: { vuln_id?: string; status?: string }) => {
      const text = `Patch for ${data.vuln_id ?? 'item'}: ${data.status ?? 'updated'}`;
      setMessages(prev => [...prev, { agent_name: 'Yamabiko', species: 'Patch Strategy', colour: '#F59E0B', text, message_type: 'info' }]);
    });

    return () => {
      clearInterval(statusInterval);
      socketRef.current?.disconnect();
    };
  }, []);

  const triggerScan = (path: string, lang: string) => {
    setScanningPath(path);
    setFindings([]);
    setSourceCode(null);
    setMessages([{
      agent_name: 'System', species: 'Orchestrator', colour: '#E85D04',
      text: `Initialising VAIS pipeline for: ${path}`,
      message_type: 'status',
    }]);
    socketRef.current?.emit('trigger_scan', { path, lang });

    setPage('console');
  };

  const confirmPatch = (vulnId: string, approved: boolean) => {
    socketRef.current?.emit('confirm_patch', { vuln_id: vulnId, approved });

    if (approved) {
      const finding = findings.find(f => f.vuln_id === vulnId);
      if (finding) {
        setPatchHistory(prev => [
          {
            id: Math.random().toString(36).substr(2, 9),
            vuln_id: vulnId,
            rule_name: finding.rule_name,
            file_path: finding.source_file,
            timestamp: new Date().toLocaleTimeString(),
            strategy: finding.patch_strategy || 'Automated Remediation'
          },
          ...prev
        ]);
      }
    }

    // Remove the patch from local state so it stops showing in CodeViewer immediately
    setMessages(prev => prev.map(m => (!isUser(m) && m.vuln_id === vulnId && m.message_type === 'patch_request') ? { ...m, patch_diff: undefined } : m));
  };

  const buildSystemPrompt = () => {
    const filename = sourceCode?.path?.split('/').pop() || 'None';
    const lang = findings[0]?.language || 'Unknown';
    const top5 = findings
      .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
      .slice(0, 5)
      .map(f => ({ vuln_id: f.vuln_id, cwe: f.cwe, function: f.function_name, line: f.line_start, rule: f.rule_name, risk_score: f.risk_score }));
    
    const taintIds = findings.filter(f => f.taint_confirmed).map(f => f.vuln_id);
    const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
    const highs = findings.filter(f => f.severity === 'HIGH').length;

    return `You are VAIS — the Vulnerability Assessment Intelligence System. You are a precision security AI embedded in a professional SAST platform.
    
    Orchestrate five specialist agents:
    - Tanuki (Recon): Speaks like a recon specialist — precise, lists entry points.
    - Tsushima (Memory): Speaks with urgency about memory safety (buffer overflows, UAF). Names line and function.
    - Iriomote (Taint): Analytical about data flow — traces tainted input source to sink.
    - Raijū (ML): Authrotity on ML scores — explains features and probabilities.
    - Yamabiko (Patch): Patch engineer — proposes exact code fixes.

    CURRENT SCAN STATE:
    File: ${filename}
    Language: ${lang}
    Findings: ${findings.length} (Critical: ${criticals}, High: ${highs})
    Top Results: ${JSON.stringify(top5)}
    Taint Confirmed: ${taintIds.join(', ')}
    
    Always respond AS the requested agent if mentioned. Detect user intent for line numbers or CWEs and answer with absolute technical precision. Cap responses at 150 words. Be direct.`;
  };

  const handleUserMessage = async (rawText: string) => {
    const { enrichedText, suggestedAgent } = routeIntent(rawText, findings);
    
    const userMsg: AnyMessage = { type: 'user', text: rawText };
    setMessages(prev => [...prev, userMsg]);

    const assistantId = Math.random().toString(36).substr(2, 9);
    const agentMsg: AgentMessage = {
      id: assistantId,
      agent_name: suggestedAgent,
      species: suggestedAgent === 'VAIS' ? 'SECURITY INTELLIGENCE' : suggestedAgent.toUpperCase(),
      colour: suggestedAgent === 'Tanuki' ? '#E85D04' : suggestedAgent === 'Tsushima' ? '#3B82F6' : suggestedAgent === 'Iriomote' ? '#10B981' : suggestedAgent === 'Raijū' ? '#8B5CF6' : suggestedAgent === 'Yamabiko' ? '#F59E0B' : '#FFB050',
      text: '',
      message_type: 'info'
    };
    
    setMessages(prev => [...prev, agentMsg]);
    setActiveAgent(suggestedAgent);

    // Build Chat History (Last 6 messages)
    const history = messages
      .slice(-6)
      .map(m => ({
        role: isUser(m) ? 'user' : 'assistant',
        content: m.text
      }));

    try {
      const response = await fetch('http://localhost:11434/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'qwen2.5-coder:7b',
          stream: true,
          messages: [
            { role: 'system', content: buildSystemPrompt() },
            ...history,
            { role: 'user', content: enrichedText }
          ]
        })
      });

      if (!response.body) return;
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let accumulatedText = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n').filter(l => l.trim());
        
        for (const line of lines) {
          try {
            const json = JSON.parse(line);
            if (json.message?.content) {
              accumulatedText += json.message.content;
              setMessages(prev => prev.map(m => 
                (isUser(m) || m.id !== assistantId) ? m : { ...m, text: accumulatedText }
              ));
            }
          } catch (e) {
            console.error('Error parsing Ollama chunk:', e);
          }
        }
      }
    } catch (err) {
      console.error('Ollama communication error:', err);
      // Fallback or error indicator
      setMessages(prev => prev.map(m => 
        (isUser(m) || m.id !== assistantId) ? m : { ...m, text: 'Ollama not reachable or model not loaded. Please ensure qwen2.5-coder:7b is running at localhost:11434.' }
      ));
    }
  };

  const handleNavClick = (id: NavPage) => {
    setPage(id);
    window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior });
    document.body.style.background = '';
  };

  return (
    <>
      {/* ── NAVBAR ── */}
      <header style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 50,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 32px', height: 64,
        background: 'rgba(3,1,1,0.85)', backdropFilter: 'blur(16px)',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
      }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 32 }}>
          <button
            onClick={() => handleNavClick('console')}
            style={{
              border: 'none', cursor: 'pointer', padding: 0,
              fontSize: 22, fontWeight: 900,
              background: 'linear-gradient(120deg, #FFB050, #E85D04)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
              backgroundClip: 'text', fontFamily: 'Inter, sans-serif',
            } as CSSProperties}
          >
            VAIS
          </button>

          {/* Nav links */}
          <nav style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            {NAV_LINKS.map(link => (
              <button
                key={link.id}
                onClick={() => handleNavClick(link.id)}
                className={`nav-link${(page === link.id && link.id !== 'glossary') ? ' active' : ''}`}
                style={{
                  background: 'none', border: 'none', cursor: 'pointer',
                  padding: '6px 12px', borderRadius: 6,
                  fontFamily: 'Inter, sans-serif',
                }}
              >
                {link.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Right: status + sys btn */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, fontSize: 12, fontWeight: 600 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: status.backend === 'connected' ? '#4ade80' : 'rgba(255,255,255,0.35)' }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: status.backend === 'connected' ? '#4ade80' : '#52525b' }} />
              API
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: status.ollama.reachable ? '#4ade80' : '#fbbf24' }}>
              <div style={{ width: 6, height: 6, borderRadius: '50%', background: status.ollama.reachable ? '#4ade80' : '#fbbf24' }} />
              LLM
            </div>
          </div>
          <button
            style={{
              background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 20, color: 'white', fontSize: 12, fontWeight: 600,
              padding: '8px 16px', cursor: 'pointer', fontFamily: 'Inter, sans-serif',
            }}
          >
            System Status
          </button>
        </div>
      </header>

      {/* ── PAGES ── */}
      <div style={{ paddingTop: 0 }}>
        {page === 'console' && (
          <>
            <ScanConsole files={files} onScan={triggerScan} scanningPath={scanningPath} status={status} />
            <AgentTerminal
              messages={messages as AnyMessage[]}
              activeAgent={activeAgent}
              onConfirmPatch={confirmPatch}
              onUserMessage={handleUserMessage}
              sourceCode={sourceCode}
              findings={findings}
            />
            <MLAnalytics findings={findings} plots={plots} />
          </>
        )}

        {page === 'glossary' && <AgentGlossary onClose={() => setPage('console')} />}

        {page === 'analytics' && (
          <div style={{ paddingTop: 64 }}>
            <MLAnalytics findings={findings} plots={plots} />
          </div>
        )}

        {page === 'docs' && <Documentation findings={findings} patchHistory={patchHistory} />}
      </div>
    </>
  );
}
