import { useEffect, useRef, useState, Fragment } from 'react';
import { Bot, Send, Terminal, Code2, CheckCircle2, Zap } from 'lucide-react';
import { AgentSidebar } from './AgentSidebar';
import { AGENT_ICONS } from './AgentIcons';
import { hexToRgb } from './AgentSidebar';

export type AgentMessage = {
  id?: string;
  agent_name: string;
  species: string;
  emoji?: string;
  colour: string;
  text: string;
  message_type: string;
  vuln_id?: string;
  patch_diff?: string;
};

type UserMessage = { type: 'user'; text: string; id?: string };
export type AnyMessage = AgentMessage | UserMessage;

export function isUser(m: AnyMessage): m is UserMessage {
  return (m as UserMessage).type === 'user';
}

export type Finding = {
  vuln_id: string; cwe: string; rule_name: string; source_file: string; language: string;
  function_name: string; line_start: number; line_end: number; title: string; description: string;
  code_snippet: string; severity: string; confidence: number; taint_confirmed: boolean;
  taint_path?: string; standards_citation?: string; exploit_prob?: number; risk_score?: number;
  composite_risk: number; patch_strategy?: string; patch_applied?: boolean; status: string;
  agent_notes: string[]; ml_severity?: string;
};

// ── Inline Annotation Component ──────────────────────────────────────────────
function LineAnnotation({ 
  finding, 
  patch, 
  onPatch 
}: { 
  finding: Finding; 
  patch?: AgentMessage; 
  onPatch: (id: string, approved: boolean) => void 
}) {
  const [expanded, setExpanded] = useState(true);
  const rgb = hexToRgb(finding.severity === 'CRITICAL' || finding.severity === 'HIGH' ? '#f87171' : '#F59E0B');

  return (
    <div style={{
      margin: '4px 8px 8px 44px',
      background: 'rgba(15, 12, 8, 0.95)',
      border: `1px solid rgba(${rgb}, 0.3)`,
      borderRadius: 8,
      overflow: 'hidden',
      boxShadow: `0 8px 24px rgba(0,0,0,0.4), 0 0 0 1px rgba(${rgb}, 0.1)`,
      animation: 'chatFadeUp 0.3s ease-out',
      zIndex: 20,
    }}>
      {/* Header */}
      <div 
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: '8px 12px',
          background: `rgba(${rgb}, 0.1)`,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          cursor: 'pointer',
          borderBottom: expanded ? `1px solid rgba(${rgb}, 0.1)` : 'none'
        }}
      >
        <Zap size={12} style={{ color: `rgb(${rgb})` }} />
        <span style={{ fontSize: 11, fontWeight: 700, color: 'white', flex: 1 }}>
          {finding.vuln_id}: {finding.rule_name} — <span style={{ color: `rgb(${rgb})` }}>Tsushima</span>
        </span>
        <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.4)', fontWeight: 600 }}>
          {finding.exploit_prob ? `Exploit Prob: ${(finding.exploit_prob * 100).toFixed(0)}%` : 'Analyzing...'}
        </div>
      </div>

      {expanded && (
        <div style={{ padding: 12 }}>
          <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.7)', lineHeight: 1.5, marginBottom: 12 }}>
            {finding.description}
            {finding.taint_path && (
              <div style={{ 
                marginTop: 8, padding: '6px 10px', background: 'rgba(255,255,255,0.03)', 
                borderRadius: 4, border: '1px solid rgba(255,255,255,0.05)',
                fontSize: 10, color: '#10B981', fontFamily: "'JetBrains Mono', monospace"
              }}>
                <strong style={{ color: 'rgba(255,255,255,0.4)', marginRight: 6 }}>TAINT PATH:</strong>
                {finding.taint_path}
              </div>
            )}
          </div>

          {/* Patch Diff View */}
          {patch && (
            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 10, fontWeight: 800, color: '#F59E0B', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.05em' }}>
                Proposed Patch (Yamabiko)
              </div>
              <div style={{
                position: 'relative',
                background: '#040404',
                borderRadius: 8,
                border: '1px solid rgba(255,255,255,0.08)',
                overflow: 'hidden',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 11,
                boxShadow: '0 4px 20px rgba(0,0,0,0.4)'
              }}>
                <div style={{ padding: '8px 0' }}>
                  {patch.patch_diff?.split('\n').filter(l => l.startsWith('-') || l.startsWith('+')).map((line, i) => (
                    <div key={i} style={{
                      padding: '2px 12px',
                      background: line.startsWith('+') ? 'rgba(74,222,128,0.1)' : 'rgba(248,113,113,0.1)',
                      color: line.startsWith('+') ? '#4ade80' : '#f87171',
                      display: 'flex',
                      gap: 8
                    }}>
                      <span style={{ opacity: 0.5, width: 12 }}>{line[0]}</span>
                      <span>{line.slice(1)}</span>
                    </div>
                  ))}
                </div>

                {/* Primary Action Buttons - Left Aligned Under Code */}
                <div style={{ 
                  display: 'flex', 
                  gap: 8, 
                  padding: '12px 12px 14px',
                  justifyContent: 'flex-start',
                }}>
                  <button
                    onClick={() => onPatch(finding.vuln_id, true)}
                    style={{
                      height: 28, 
                      padding: '0 14px',
                      borderRadius: 6,
                      background: 'rgba(16, 185, 129, 0.25)', 
                      backdropFilter: 'blur(12px)',
                      color: '#10B981',
                      fontSize: 10, 
                      fontWeight: 800, 
                      border: '1px solid rgba(16, 185, 129, 0.3)', 
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontFamily: 'Inter, sans-serif',
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      transition: 'all 0.2s ease',
                      boxShadow: '0 4px 12px rgba(0,0,0,0.3)'
                    }}
                    onMouseOver={e => {
                      e.currentTarget.style.background = 'rgba(16, 185, 129, 0.4)';
                      e.currentTarget.style.color = 'white';
                    }}
                    onMouseOut={e => {
                      e.currentTarget.style.background = 'rgba(16, 185, 129, 0.25)';
                      e.currentTarget.style.color = '#10B981';
                    }}
                  >
                    Accept
                  </button>
                  <button
                    onClick={() => onPatch(finding.vuln_id, false)}
                    style={{
                      height: 28, 
                      padding: '0 14px',
                      borderRadius: 6,
                      background: 'rgba(239, 68, 68, 0.25)', 
                      backdropFilter: 'blur(122x)',
                      color: '#EF4444',
                      fontSize: 10, 
                      fontWeight: 800, 
                      border: '1px solid rgba(239, 68, 68, 0.3)', 
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontFamily: 'Inter, sans-serif',
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      transition: 'all 0.2s ease',
                      boxShadow: '0 4px 12px rgba(0,0,0,0.3)'
                    }}
                    onMouseOver={e => {
                      e.currentTarget.style.background = 'rgba(239, 68, 68, 0.4)';
                      e.currentTarget.style.color = 'white';
                    }}
                    onMouseOut={e => {
                      e.currentTarget.style.background = 'rgba(239, 68, 68, 0.25)';
                      e.currentTarget.style.color = '#EF4444';
                    }}
                  >
                    Reject
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Code Viewer Panel ────────────────────────────────────────────────────────
function CodeViewer({
  filePath,
  code,
  findings,
  messages,
  patchedVulnIds,
  rejectedVulnIds,
  onPatch,
  onAcceptAll,
  height,
}: {
  filePath: string;
  code: string;
  findings: Finding[];
  messages: AnyMessage[];
  patchedVulnIds: Set<string>;
  rejectedVulnIds: Set<string>;
  onPatch: (id: string, approved: boolean) => void;
  onAcceptAll: () => void;
  height: number;
}) {
  const lines = code.split('\n');
  const fileName = filePath.split(/[/\\]/).pop();

  // Which line numbers are vulnerable
  const getLineFindings = (lineNum: number) =>
    findings.filter(f => lineNum >= f.line_start && lineNum <= f.line_end);

  // Get pending patch for a finding
  const getPatchMsg = (vulnId: string) =>
    messages.find(m => !isUser(m) && (m as AgentMessage).vuln_id === vulnId &&
      (m as AgentMessage).patch_diff && (m as AgentMessage).message_type === 'patch_request') as AgentMessage | undefined;

  const isPatched = (vulnId: string) => patchedVulnIds.has(vulnId);

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      width: 460, 
      flexShrink: 0,
      height: height,
      background: 'rgba(6, 6, 10, 0.97)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 12,
      overflow: 'hidden',
      boxShadow: '0 0 0 1px rgba(232,93,4,0.15), inset 0 1px 0 rgba(255,255,255,0.05)',
    }}>
      {/* Header */}
      <div style={{
        padding: '10px 14px',
        borderBottom: '1px solid rgba(255,255,255,0.07)',
        background: 'rgba(0,0,0,0.5)',
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Code2 size={14} style={{ color: '#E85D04', flexShrink: 0 }} />
          <span style={{
            fontSize: 13,
            fontWeight: 700,
            color: '#E85D04',
            fontFamily: "'JetBrains Mono', monospace",
            flex: 1,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}>{fileName}</span>
        </div>
        <div style={{ display: 'flex', gap: 16, fontSize: 11 }}>
          <span style={{ color: 'rgba(255,255,255,0.4)' }}>
            <span style={{ fontWeight: 700 }}>Lines:</span> {lines.length}
          </span>
          <span style={{ color: findings.length > 0 ? '#f87171' : 'rgba(255,255,255,0.4)' }}>
            <span style={{ fontWeight: 700 }}>Findings:</span>{' '}
            <span style={{ color: '#f87171', fontWeight: 800 }}>{findings.length}</span>
          </span>
        </div>
      </div>

      {/* Scrollable Code Area */}
      <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
        <div style={{
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontSize: 12,
          lineHeight: 1.65,
          minWidth: 'max-content',
          paddingBottom: 40,
        }}>
          {lines.map((line, idx) => {
            const lineNum = idx + 1;
            const lineFindings = getLineFindings(lineNum);
            const isPatchedLine = lineFindings.length > 0 && lineFindings.some(f => isPatched(f.vuln_id));
            const isRejectedLine = lineFindings.length > 0 && lineFindings.some(f => rejectedVulnIds.has(f.vuln_id));
            const isVuln = lineFindings.length > 0 && !isPatchedLine && !isRejectedLine;

            const rowBg = isPatchedLine ? 'rgba(16, 185, 129, 0.1)' : 
                          isRejectedLine ? 'rgba(239, 68, 68, 0.1)' :
                          isVuln ? 'rgba(248,113,113,0.05)' : 'transparent';
            
            const accentColor = isPatchedLine ? '#10B981' : isRejectedLine ? '#EF4444' : '#f87171';
            
            return (
              <Fragment key={idx}>
                <div style={{ display: 'flex', background: rowBg }}>
                  <div style={{
                    padding: '1px 10px',
                    color: accentColor,
                    textAlign: 'right',
                    borderRight: '1px solid rgba(255,255,255,0.05)',
                    minWidth: 44,
                    background: (isVuln || isPatchedLine || isRejectedLine) ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.2)',
                    fontSize: 11,
                  }}>
                    {lineNum}
                  </div>
                  <div style={{
                    padding: '1px 14px',
                    color: isPatchedLine ? '#10B981' : isRejectedLine ? '#EF4444' : isVuln ? '#fff' : 'rgba(255,255,255,0.7)',
                    whiteSpace: 'pre',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    flex: 1,
                  }}>
                    {line || ' '}
                    {isPatchedLine && <span style={{ fontSize: 9, fontWeight: 800, color: '#10B981', background: 'rgba(16, 185, 129, 0.1)', padding: '1px 6px', borderRadius: 4, letterSpacing: '0.05em' }}>✓ PATCHED</span>}
                    {isRejectedLine && <span style={{ fontSize: 9, fontWeight: 800, color: '#EF4444', background: 'rgba(239, 68, 68, 0.1)', padding: '1px 6px', borderRadius: 4, letterSpacing: '0.05em' }}>✕ REJECTED</span>}
                  </div>
                </div>

                {/* Render Annotations only on the start line of a finding range */}
                {lineFindings
                  .filter(f => f.line_start === lineNum && !isPatched(f.vuln_id) && !rejectedVulnIds.has(f.vuln_id))
                  .map(f => (
                    <LineAnnotation 
                      key={f.vuln_id} 
                      finding={f} 
                      patch={getPatchMsg(f.vuln_id)} 
                      onPatch={onPatch}
                    />
                  ))
                }
              </Fragment>
            );
          })}
        </div>
      </div>

      {findings.length > 0 && (patchedVulnIds.size + rejectedVulnIds.size) < findings.length && (
        <div style={{ 
          padding: '16px 20px', 
          borderTop: '1px solid rgba(255,255,255,0.07)', 
          background: 'rgba(0,0,0,0.6)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center'
        }}>
          <button
            onClick={onAcceptAll}
            style={{
              width: '100%', 
              height: 40, 
              borderRadius: 8,
              background: 'rgba(240,192,93,0.08)', 
              border: '1px solid rgba(240,192,93,0.25)',
              color: '#F0C05D', 
              fontSize: 13, 
              fontWeight: 700, 
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 10,
              transition: 'all 0.2s ease',
              fontFamily: 'Inter, sans-serif'
            }}
            onMouseOver={e => {
              e.currentTarget.style.background = 'rgba(240,192,93,0.15)';
              e.currentTarget.style.borderColor = 'rgba(240,192,93,0.4)';
            }}
            onMouseOut={e => {
              e.currentTarget.style.background = 'rgba(240,192,93,0.08)';
              e.currentTarget.style.borderColor = 'rgba(240,192,93,0.25)';
            }}
          >
            <CheckCircle2 size={16} />
            Approve All Patches
          </button>
        </div>
      )}
    </div>
  );
}

// ── Agent Message Bubble ──────────────────────────────────────────────────────
function AgentBubble({ msg }: { msg: AgentMessage }) {
  const Icon = AGENT_ICONS[msg.agent_name];
  const isPatch = msg.message_type === 'patch_request';
  const isStatus = msg.message_type === 'status';
  const rgb = hexToRgb(msg.colour);

  if (isStatus) {
    return (
      <div style={{
        fontSize: 11,
        fontFamily: "'JetBrains Mono', monospace",
        color: 'rgba(255,255,255,0.4)',
        padding: '3px 4px',
        display: 'flex',
        alignItems: 'center',
        gap: 8,
      }}>
        <span style={{ color: msg.colour, fontWeight: 700 }}>{msg.agent_name}:</span>
        {msg.text}
      </div>
    );
  }

  return (
    <div style={{
      borderLeft: `3px solid ${msg.colour}`,
      padding: '10px 12px',
      borderRadius: '2px 8px 8px 8px',
      background: 'rgba(255,255,255,0.03)',
      border: `1px solid rgba(${rgb},0.1)`,
      borderLeftColor: msg.colour,
      animation: 'chatFadeUp 0.25s ease',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 6 }}>
        <div style={{
          width: 22,
          height: 22,
          borderRadius: 5,
          background: `rgba(${rgb},0.2)`,
          border: `1px solid rgba(${rgb},0.3)`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}>
          {Icon ? <Icon size={13} color={msg.colour} /> : <span style={{ fontSize: 9, fontWeight: 800, color: msg.colour }}>{msg.agent_name?.[0]}</span>}
        </div>
        <span style={{ fontSize: 12, fontWeight: 700, color: msg.colour }}>{msg.agent_name}</span>
        <span style={{ fontSize: 9, color: 'rgba(255,255,255,0.25)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>• {msg.species}</span>
      </div>
      <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.85)', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
        {msg.text}
      </div>
      {isPatch && (
        <div style={{
          marginTop: 10,
          padding: '8px 10px',
          borderRadius: 6,
          background: `rgba(${rgb},0.05)`,
          border: `1px dashed rgba(${rgb},0.2)`,
          fontSize: 11,
          color: 'rgba(255,255,255,0.5)',
        }}>
          Patch ready for <strong style={{ color: msg.colour }}>{msg.vuln_id}</strong> — review in code pane →
        </div>
      )}
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────
interface AgentTerminalProps {
  messages: AnyMessage[];
  activeAgent: string | null;
  onConfirmPatch: (id: string, approved: boolean) => void;
  onUserMessage: (text: string) => void;
  sourceCode?: { path: string; code: string } | null;
  findings: Finding[];
}

export function AgentTerminal({
  messages,
  activeAgent,
  onConfirmPatch,
  onUserMessage,
  sourceCode,
  findings,
}: AgentTerminalProps) {
  const chatRef = useRef<HTMLDivElement>(null);
  const [input, setInput] = useState('');
  // Track which vuln IDs have been patched (to turn lines green)
  const [patchedVulnIds, setPatchedVulnIds] = useState<Set<string>>(new Set());
  // Track which vuln IDs have been rejected (to hide annotations)
  const [rejectedVulnIds, setRejectedVulnIds] = useState<Set<string>>(new Set());

  // Fixed height for the 3-pane area
  const PANEL_HEIGHT = 600;

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [messages]);

  const send = () => {
    const t = input.trim();
    if (!t) return;
    onUserMessage(t);
    setInput('');
  };

  const handlePatch = (vulnId: string, approved: boolean) => {
    onConfirmPatch(vulnId, approved);
    if (approved) {
      setPatchedVulnIds(prev => new Set([...prev, vulnId]));
    } else {
      setRejectedVulnIds(prev => new Set([...prev, vulnId]));
    }
  };

  const isAllPatched = findings.length > 0 && patchedVulnIds.size >= findings.length;
  const [showPatchSuccess, setShowPatchSuccess] = useState(false);

  useEffect(() => {
    if (isAllPatched) {
      setShowPatchSuccess(true);
      const timer = setTimeout(() => setShowPatchSuccess(false), 5000);
      return () => clearTimeout(timer);
    }
  }, [isAllPatched]);

  return (
    <section
      id="section-agents"
      style={{
        padding: '80px 32px 100px',
        borderTop: '1px solid rgba(255,255,255,0.05)',
        background: 'radial-gradient(ellipse at top, rgba(240,192,93,0.1), transparent 60%), #030101',
      }}
    >
      <div style={{ maxWidth: 1400, margin: '0 auto' }}>
        {/* Header - Upgraded UI (Mirroring ML Analytics in Yellow) */}
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 10,
            background: 'rgba(240,192,93,0.1)', border: '1px solid rgba(240,192,93,0.2)',
            borderRadius: 99, padding: '6px 16px', marginBottom: 20
          }}>
            <Zap size={14} style={{ color: '#F0C05D' }} />
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.2em', color: '#F0C05D', textTransform: 'uppercase' }}>Execution Swarm</span>
          </div>
          <h2 style={{
            fontSize: 'clamp(32px, 5vw, 56px)', fontWeight: 800, margin: 0,
            letterSpacing: '-0.03em', lineHeight: 1.1, color: 'white',
            textShadow: '0 0 40px rgba(255,255,255,0.1)'
          }}>
            Multi Agents<br />
            <span style={{ background: 'linear-gradient(135deg, #F0C05D, #E85D04)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
              Orchestration
            </span>
          </h2>

          {/* Success Message - Disappearing */}
          {showPatchSuccess && (
            <div style={{
              marginTop: 24,
              fontSize: 13, fontWeight: 700,
              background: 'rgba(74,222,128,0.12)',
              border: '1px solid rgba(74,222,128,0.3)',
              borderRadius: 8,
              padding: '10px 24px',
              color: '#4ade80',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 10,
              animation: 'chatFadeUp 0.4s ease-out'
            }}>
              <CheckCircle2 size={18} />
              Patch for all vulnerability applied ✓ recorded
            </div>
          )}
        </div>

        {/* 3-Pane Row */}
        <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start', height: PANEL_HEIGHT }}>

          {/* ── Pane 1: Agent Sidebar ── */}
          <AgentSidebar activeAgent={activeAgent} />

          {/* ── Pane 2: Terminal + Chatbox (center, flex-grow) ── */}
          <div style={{
            flex: 1,
            minWidth: 0,
            height: PANEL_HEIGHT,
            display: 'flex',
            flexDirection: 'column',
            background: 'rgba(6,4,1,0.95)',
            border: '1px solid rgba(255,255,255,0.07)',
            borderRadius: 12,
            overflow: 'hidden',
            boxShadow: 'inset 0 1px 0 rgba(240,192,93,0.3), 0 20px 40px rgba(0,0,0,0.5)',
          }}>
            {/* Terminal Header */}
            <div style={{
              padding: '11px 16px',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
              display: 'flex',
              alignItems: 'center',
              gap: 9,
              background: 'rgba(0,0,0,0.4)',
              flexShrink: 0,
            }}>
              <Terminal size={14} style={{ color: '#F0C05D' }} />
              <span style={{ fontSize: 14, fontWeight: 700, color: 'white', flex: 1 }}>Live Agent Terminal</span>
            </div>

            {/* Messages */}
            <div
              ref={chatRef}
              style={{
                flex: 1,
                overflowY: 'auto',
                padding: '12px 16px',
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                minHeight: 0,
              }}
            >
              {messages
                .filter(msg => isUser(msg) || (msg as AgentMessage).message_type !== 'patch_request')
                .length === 0 ? (
                <div style={{
                  flex: 1,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'rgba(255,255,255,0.2)',
                  gap: 10,
                }}>
                  <Bot size={32} style={{ opacity: 0.2 }} />
                  <span style={{ fontSize: 13 }}>Select a file to start the pipeline</span>
                </div>
              ) : (
                messages
                  .filter(msg => isUser(msg) || (msg as AgentMessage).message_type !== 'patch_request')
                  .map((msg, idx) => {
                    if (isUser(msg)) {
                      return (
                        <div key={idx} style={{ display: 'flex', justifyContent: 'flex-end' }}>
                          <div style={{
                            maxWidth: '78%',
                            padding: '9px 13px',
                            borderRadius: '10px 2px 10px 10px',
                            background: 'rgba(240,192,93,0.1)',
                            border: '1px solid rgba(240,192,93,0.2)',
                          }}>
                            <div style={{ fontSize: 9, fontWeight: 700, color: '#F0C05D', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.12em' }}>You</div>
                            <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.88)', lineHeight: 1.55 }}>{msg.text}</div>
                          </div>
                        </div>
                      );
                    }
                    return <AgentBubble key={idx} msg={msg as AgentMessage} />;
                  })
              )}
            </div>

            {/* Chatbox Input Area */}
            <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', flexShrink: 0, paddingBottom: 10 }}>
              {/* Quick Action Chips */}
              {findings.length > 0 && (
                <div style={{ display: 'flex', gap: 8, padding: '12px 16px 4px', overflowX: 'auto', WebkitOverflowScrolling: 'touch' }}>
                  {[
                    "What should I fix first?",
                    "Explain the critical finding",
                    "What does Raijū think?",
                    `Explain line ${findings[0].line_start}`
                  ].map(chip => (
                    <button
                      key={chip}
                      onClick={() => onUserMessage(chip)}
                      className="chip-btn"
                      style={{
                        padding: '5px 12px',
                        background: 'rgba(240,192,93,0.06)',
                        border: '1px solid rgba(240,192,93,0.15)',
                        borderRadius: 16,
                        color: 'rgba(240,192,93,0.8)',
                        fontSize: 10,
                        fontWeight: 700,
                        whiteSpace: 'nowrap',
                        cursor: 'pointer',
                        transition: 'all 0.2s ease',
                      }}
                    >
                      {chip}
                    </button>
                  ))}
                </div>
              )}

              <div style={{
                padding: '3px 16px 2px',
                fontSize: 9,
                color: 'rgba(255,255,255,0.2)',
                display: 'flex',
                justifyContent: 'space-between',
              }}>
                <span>Ask agents about vulnerabilities or request code patches.</span>
                <span style={{ color: '#F0C05D', fontWeight: 700 }}>Qwen2.5-Coder:7b (LOCAL)</span>
              </div>
              <div style={{
                padding: '8px 14px 12px',
                display: 'flex',
                gap: 10,
                alignItems: 'center',
                background: 'rgba(0,0,0,0.3)',
              }}>
                <div style={{
                  flex: 1,
                  display: 'flex',
                  alignItems: 'center',
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: 10,
                  padding: '2px 4px',
                }}>
                  <input
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && send()}
                    placeholder="Message VAIS Intelligence..."
                    style={{
                      flex: 1,
                      background: 'transparent',
                      border: 'none',
                      color: 'white',
                      fontSize: 13,
                      padding: '9px 12px',
                      outline: 'none',
                      fontFamily: 'Inter, sans-serif',
                    }}
                  />
                </div>
                <button
                  onClick={send}
                  style={{
                    width: 38, height: 38, borderRadius: 10,
                    background: '#F0C05D',
                    border: 'none',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    cursor: 'pointer', flexShrink: 0,
                    transition: 'transform 0.1s ease',
                  }}
                  onMouseDown={e => e.currentTarget.style.transform = 'scale(0.95)'}
                  onMouseUp={e => e.currentTarget.style.transform = 'scale(1)'}
                >
                  <Send size={18} style={{ color: 'black' }} />
                </button>
              </div>
            </div>
          </div>

          {/* ── Pane 3: Code Viewer (fixed width, strictly same height as terminal) ── */}
          {sourceCode ? (
            <CodeViewer
              filePath={sourceCode.path}
              code={sourceCode.code}
              findings={findings}
              messages={messages}
              patchedVulnIds={patchedVulnIds}
              rejectedVulnIds={rejectedVulnIds}
              onPatch={handlePatch}
              onAcceptAll={() => {
                findings.forEach(f => {
                  if (!patchedVulnIds.has(f.vuln_id) && !rejectedVulnIds.has(f.vuln_id)) {
                    handlePatch(f.vuln_id, true);
                  }
                });
              }}
              height={PANEL_HEIGHT}
            />
          ) : (
            <div style={{
              width: 420,
              height: PANEL_HEIGHT,
              flexShrink: 0,
              background: 'rgba(6,6,10,0.97)',
              border: '1px dashed rgba(255,255,255,0.06)',
              borderRadius: 12,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 10,
              color: 'rgba(255,255,255,0.18)',
            }}>
              <Code2 size={28} style={{ opacity: 0.25 }} />
              <span style={{ fontSize: 13 }}>Code view appears after scan</span>
            </div>
          )}

        </div>
      </div>
    </section>
  );
}
