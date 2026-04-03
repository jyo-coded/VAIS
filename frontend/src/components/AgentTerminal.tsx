import React, { useEffect, useRef, useState } from 'react';
import { Bot, Send, Terminal, Code2, CheckCircle2, XCircle } from 'lucide-react';
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

// ── Diff Preview ──────────────────────────────────────────────────────────────
function DiffPreview({ diff }: { diff: string }) {
  return (
    <div style={{ fontFamily: "'JetBrains Mono','Fira Code',monospace", fontSize: 12, lineHeight: 1.6, background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: 12, overflowX: 'auto', whiteSpace: 'pre', marginTop: 10 }}>
      {diff.split('\n').map((line, i) => (
        <div
          key={i}
          style={{ color: line.startsWith('+') ? '#4ade80' : line.startsWith('-') ? '#f87171' : 'rgba(255,255,255,0.4)', background: line.startsWith('+') ? 'rgba(74,222,128,0.07)' : line.startsWith('-') ? 'rgba(248,113,113,0.07)' : 'transparent', padding: '0 4px' }}
        >
          {line || ' '}
        </div>
      ))}
    </div>
  );
}

// ── Source Code Panel ─────────────────────────────────────────────────────────
function SourcePanel({ filePath, code }: { filePath: string; code: string }) {
  const lines = code.split('\n');
  return (
    <div style={{ marginBottom: 16, borderRadius: 12, overflow: 'hidden', border: '1px solid rgba(232,93,4,0.25)', background: 'rgba(0,0,0,0.5)' }}>
      <div style={{ padding: '10px 16px', borderBottom: '1px solid rgba(232,93,4,0.15)', display: 'flex', alignItems: 'center', gap: 8, background: 'rgba(232,93,4,0.06)' }}>
        <Code2 size={14} style={{ color: '#E85D04' }} />
        <span style={{ fontSize: 12, fontWeight: 700, color: '#E85D04', fontFamily: "'JetBrains Mono',monospace" }}>{filePath}</span>
        <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginLeft: 'auto' }}>{lines.length} lines</span>
      </div>
      <div style={{ maxHeight: 220, overflowY: 'auto' }}>
        <div style={{ display: 'flex', fontFamily: "'JetBrains Mono',monospace", fontSize: 12, lineHeight: 1.7 }}>
          <div style={{ padding: '8px 10px', color: 'rgba(255,255,255,0.2)', textAlign: 'right', userSelect: 'none', borderRight: '1px solid rgba(255,255,255,0.06)', minWidth: 42, background: 'rgba(0,0,0,0.3)' }}>
            {lines.map((_, i) => <div key={i}>{i + 1}</div>)}
          </div>
          <div style={{ padding: '8px 14px', color: 'rgba(255,255,255,0.75)', flex: 1, overflowX: 'auto', whiteSpace: 'pre' }}>
            {code}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Agent Message Bubble ──────────────────────────────────────────────────────
function AgentBubble({ msg, onPatch }: { msg: AgentMessage; onPatch: (id: string, approved: boolean) => void }) {
  const Icon = AGENT_ICONS[msg.agent_name];
  const isPatch  = msg.message_type === 'patch_request';
  const isStatus = msg.message_type === 'status';
  const rgb = hexToRgb(msg.colour);

  if (isStatus) {
    return (
      <div style={{ fontSize: 11, fontFamily: "'JetBrains Mono',monospace", color: 'rgba(255,255,255,0.35)', padding: '2px 4px', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color: msg.colour, fontWeight: 700 }}>{msg.agent_name}:</span>
        {msg.text}
      </div>
    );
  }

  return (
    <div style={{ borderLeft: `3px solid ${msg.colour}`, padding: '12px 14px', borderRadius: '2px 10px 10px 10px', background: 'rgba(255,255,255,0.03)', border: `1px solid rgba(${rgb},0.12)`, borderLeftColor: msg.colour, animation: 'chatFadeUp 0.3s ease' }}>
      {/* Agent header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <div style={{ width: 26, height: 26, borderRadius: 6, background: `rgba(${rgb},0.2)`, border: `1px solid rgba(${rgb},0.3)`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          {Icon ? <Icon size={15} color={msg.colour} /> : <span style={{ fontSize: 10, fontWeight: 800, color: msg.colour }}>{msg.agent_name?.[0]}</span>}
        </div>
        <span style={{ fontSize: 13, fontWeight: 700, color: msg.colour }}>{msg.agent_name}</span>
        <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.28)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>• {msg.species}</span>
      </div>

      {/* Message text */}
      <div style={{ fontSize: 14, color: 'rgba(255,255,255,0.88)', lineHeight: 1.65, whiteSpace: 'pre-wrap' }}>
        {msg.text}
      </div>

      {/* Patch block */}
      {isPatch && (
        <div style={{ marginTop: 14, padding: 14, borderRadius: 10, background: `rgba(${rgb},0.06)`, border: `1px solid rgba(${rgb},0.25)` }}>
          <div style={{ fontSize: 11, fontWeight: 800, letterSpacing: '0.12em', textTransform: 'uppercase', color: msg.colour, marginBottom: 10 }}>
            ⚠ Awaiting patch approval
          </div>
          {msg.patch_diff && <DiffPreview diff={msg.patch_diff} />}
          {msg.vuln_id && (
            <div style={{ display: 'flex', gap: 10, marginTop: 14 }}>
              <button
                onClick={() => onPatch(msg.vuln_id!, true)}
                style={{ display: 'flex', alignItems: 'center', gap: 6, height: 34, padding: '0 18px', borderRadius: 8, background: 'rgba(34,197,94,0.15)', border: '1px solid rgba(74,222,128,0.4)', color: '#4ade80', fontSize: 13, fontWeight: 700, cursor: 'pointer', fontFamily: 'Inter,sans-serif' }}
              >
                <CheckCircle2 size={14} /> Apply Patch
              </button>
              <button
                onClick={() => onPatch(msg.vuln_id!, false)}
                style={{ display: 'flex', alignItems: 'center', gap: 6, height: 34, padding: '0 18px', borderRadius: 8, background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.15)', color: 'rgba(255,255,255,0.6)', fontSize: 13, fontWeight: 700, cursor: 'pointer', fontFamily: 'Inter,sans-serif' }}
              >
                <XCircle size={14} /> Reject
              </button>
            </div>
          )}
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
}

export function AgentTerminal({ messages, activeAgent, onConfirmPatch, onUserMessage, sourceCode }: AgentTerminalProps) {
  const chatRef  = useRef<HTMLDivElement>(null);
  const [input, setInput] = useState('');

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [messages]);

  const send = () => {
    const t = input.trim();
    if (!t) return;
    onUserMessage(t);
    setInput('');
  };

  return (
    <section
      id="section-agents"
      style={{ minHeight: '100vh', paddingTop: 80, paddingBottom: 80, paddingLeft: 40, paddingRight: 40, borderTop: '1px solid rgba(255,255,255,0.05)', background: 'radial-gradient(ellipse at 40% 0%, rgba(240,192,93,0.07),transparent 50%), #030101' }}
    >
      <div style={{ maxWidth: 1300, margin: '0 auto' }}>
        {/* Section header */}
        <div style={{ textAlign: 'center', marginBottom: 48 }}>
          <p style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.25em', textTransform: 'uppercase', color: '#F0C05D', marginBottom: 12 }}>Execution Swarm</p>
          <h2 style={{ fontSize: 'clamp(28px,4vw,48px)', fontWeight: 800, margin: 0, letterSpacing: '-0.02em' }}>Autonomous Operations</h2>
        </div>

        <div style={{ display: 'flex', gap: 28, alignItems: 'flex-start' }}>
          {/* Agent Sidebar */}
          <AgentSidebar activeAgent={activeAgent} />

          {/* Terminal */}
          <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
            <div style={{ background: 'rgba(8,6,1,0.9)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 16, overflow: 'hidden', display: 'flex', flexDirection: 'column', boxShadow: 'inset 0 2px 1px rgba(240,192,93,0.4), 0 24px 48px rgba(0,0,0,0.5)' }}>
              {/* Header */}
              <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(0,0,0,0.3)' }}>
                <Terminal size={16} style={{ color: '#F0C05D' }} />
                <span style={{ fontSize: 15, fontWeight: 700, color: 'white', flex: 1 }}>Live Agent Terminal</span>
                {activeAgent && (
                  <div style={{ fontSize: 11, fontWeight: 700, background: 'rgba(240,192,93,0.15)', border: '1px solid rgba(240,192,93,0.35)', borderRadius: 999, padding: '3px 10px', color: '#F0C05D' }}>
                    {activeAgent} running...
                  </div>
                )}
              </div>

              {/* Messages area */}
              <div ref={chatRef} style={{ height: 520, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 10 }}>
                {messages.length === 0 ? (
                  <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'rgba(255,255,255,0.2)', gap: 12 }}>
                    <Bot size={36} style={{ opacity: 0.25 }} />
                    <span style={{ fontSize: 14 }}>Select a file above to start the pipeline</span>
                  </div>
                ) : (
                  <>
                    {/* Source code panel if we have it */}
                    {sourceCode && <SourcePanel filePath={sourceCode.path} code={sourceCode.code} />}

                    {messages.map((msg, idx) => {
                      if (isUser(msg)) {
                        return (
                          <div key={idx} style={{ display: 'flex', justifyContent: 'flex-end' }}>
                            <div style={{ maxWidth: '75%', padding: '10px 14px', borderRadius: '10px 2px 10px 10px', background: 'rgba(240,192,93,0.1)', border: '1px solid rgba(240,192,93,0.2)' }}>
                              <div style={{ fontSize: 10, fontWeight: 700, color: '#F0C05D', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.12em' }}>You</div>
                              <div style={{ fontSize: 14, color: 'rgba(255,255,255,0.9)', lineHeight: 1.6 }}>{msg.text}</div>
                            </div>
                          </div>
                        );
                      }
                      return <AgentBubble key={idx} msg={msg as AgentMessage} onPatch={onConfirmPatch} />;
                    })}
                  </>
                )}
              </div>

              {/* Chatbox input */}
              <div style={{ padding: '0 20px 4px', fontSize: 10, color: 'rgba(255,255,255,0.4)', textAlign: 'right', display: 'flex', justifyContent: 'space-between' }}>
                <span>Type to ask VAIS Assistant or a specific agent directly.</span>
                <span>Powered by Gemini 2.0 Flash</span>
              </div>
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', padding: '12px 16px', display: 'flex', gap: 10, alignItems: 'center', background: 'rgba(0,0,0,0.25)' }}>
                <input
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && send()}
                  placeholder="Ask about agents, vulnerabilities, or request a change..."
                  style={{ flex: 1, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 10, color: 'white', fontSize: 13, padding: '10px 14px', outline: 'none', fontFamily: 'Inter,sans-serif' }}
                />
                <button
                  onClick={send}
                  style={{ width: 38, height: 38, borderRadius: 10, background: 'rgba(240,192,93,0.2)', border: '1px solid rgba(240,192,93,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', flexShrink: 0 }}
                >
                  <Send size={15} style={{ color: '#F0C05D' }} />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
