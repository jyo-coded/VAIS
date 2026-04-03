import React, { useState } from 'react';
import { ChevronDown, ChevronRight, CheckCircle2, XCircle } from 'lucide-react';

type Finding = {
  vuln_id: string;
  cwe: string;
  rule_name: string;
  source_file: string;
  language: string;
  function_name: string;
  line_start: number;
  line_end: number;
  title: string;
  description: string;
  code_snippet: string;
  severity: string;
  confidence: number;
  taint_confirmed: boolean;
  taint_path?: string;
  standards_citation?: string;
  exploit_prob?: number;
  risk_score?: number;
  composite_risk: number;
  patch_strategy?: string;
  patch_applied?: boolean;
  status: string;
  agent_notes: string[];
  ml_severity?: string;
};

type PlotsResponse = Record<string, string>;

interface MLAnalyticsProps {
  findings: Finding[];
  plots: PlotsResponse;
}

const SEV_STYLE: Record<string, string> = {
  CRITICAL: 'sev-critical', HIGH: 'sev-high', MEDIUM: 'sev-medium', LOW: 'sev-low',
};

export function MLAnalytics({ findings, plots }: MLAnalyticsProps) {
  const [tab, setTab] = useState('overview');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  const counts = {
    critical: findings.filter(f => f.severity === 'CRITICAL').length,
    high:     findings.filter(f => f.severity === 'HIGH').length,
    medium:   findings.filter(f => f.severity === 'MEDIUM').length,
    low:      findings.filter(f => f.severity === 'LOW').length,
  };

  const TABS = [
    { id: 'overview', label: 'Overview' },
    { id: 'findings', label: 'Findings' },
    { id: 'mlanalysis', label: 'ML Analytics' },
    { id: 'standards', label: 'Standards' },
  ];

  return (
    <section
      id="section-insights"
      style={{
        minHeight: '100vh',
        paddingTop: 80, paddingBottom: 80,
        paddingLeft: 40, paddingRight: 40,
        borderTop: '1px solid rgba(255,255,255,0.05)',
        background: 'radial-gradient(ellipse at top, rgba(26,200,80,0.08), transparent 55%), #030101',
      }}
    >
      <div style={{ maxWidth: 1300, margin: '0 auto' }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 48 }}>
          <p className="section-kicker" style={{ color: '#1AC850' }}>Results Compilation</p>
          <h2 style={{ fontSize: 'clamp(28px, 4vw, 48px)', fontWeight: 800, margin: 0, letterSpacing: '-0.02em' }}>
            Vulnerability Findings &amp; ML Analysis
          </h2>
        </div>

        <div className="glass-card-green" style={{ overflow: 'hidden' }}>
          {/* Tabs */}
          <div style={{ padding: '0 24px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', gap: 4, overflowX: 'auto' }}>
            {TABS.map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`tab-btn ${tab === t.id ? 'active-green' : ''}`}
                style={{ margin: '12px 0' }}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Content */}
          <div style={{ padding: 28, background: 'rgba(1,8,3,0.4)', minHeight: 480 }}>
            {/* ── OVERVIEW ── */}
            {tab === 'overview' && (
              <div>
                {/* Risk Counts */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 28 }}>
                  {[
                    { label: 'Critical Risk', val: counts.critical,  glow: 'rgba(239,68,68,0.15)',   color: '#f87171' },
                    { label: 'High Risk',     val: counts.high,      glow: 'rgba(249,115,22,0.15)',  color: '#fb923c' },
                    { label: 'Medium Risk',   val: counts.medium,    glow: 'rgba(234,179,8,0.15)',   color: '#facc15' },
                    { label: 'Low Risk',      val: counts.low,       glow: 'rgba(26,200,80,0.12)',   color: '#4ade80' },
                  ].map(m => (
                    <div key={m.label} className="stat-card" style={{ boxShadow: `0 0 30px ${m.glow}`, border: `1px solid rgba(255,255,255,0.06)` }}>
                      <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'rgba(255,255,255,0.4)', marginBottom: 12 }}>{m.label}</div>
                      <div style={{ fontSize: 56, fontWeight: 900, color: m.color, lineHeight: 1 }}>{m.val}</div>
                    </div>
                  ))}
                </div>

                {/* Language breakdown */}
                {findings.length > 0 && (
                  <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: 20 }}>
                    <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.15em', color: '#1AC850', textTransform: 'uppercase', marginBottom: 16 }}>Language Breakdown</div>
                    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                      {Array.from(new Set(findings.map(f => f.language))).map(lang => {
                        const cnt = findings.filter(f => f.language === lang).length;
                        return (
                          <div key={lang} style={{ background: 'rgba(26,200,80,0.08)', border: '1px solid rgba(26,200,80,0.2)', borderRadius: 999, padding: '5px 14px', fontSize: 12, fontWeight: 600, color: '#4ade80' }}>
                            {lang?.toUpperCase() ?? 'UNKNOWN'} — {cnt}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {!findings.length && (
                  <div style={{ textAlign: 'center', padding: '60px 0', color: 'rgba(255,255,255,0.2)', fontSize: 15 }}>
                    Run a scan to see results here
                  </div>
                )}
              </div>
            )}

            {/* ── FINDINGS ── */}
            {tab === 'findings' && (
              <div>
                {!findings.length
                  ? <div style={{ textAlign: 'center', padding: '60px 0', color: 'rgba(255,255,255,0.2)' }}>No findings yet — select a target file above</div>
                  : (
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', color: '#1AC850' }}>
                            {['ID', 'Severity', 'CWE', 'Rule', 'Function', 'Line', 'Exploit%', 'Risk', 'Taint', ''].map(h => (
                              <th key={h} style={{ padding: '10px 12px', fontWeight: 700, fontSize: 10, letterSpacing: '0.15em', textTransform: 'uppercase', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {findings.map(f => (
                            <React.Fragment key={f.vuln_id}>
                              <tr
                                style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer' }}
                                onClick={() => setExpandedRow(expandedRow === f.vuln_id ? null : f.vuln_id)}
                              >
                                <td style={{ padding: '10px 12px', fontFamily: "'JetBrains Mono', monospace", color: '#1AC850', whiteSpace: 'nowrap' }}>{f.vuln_id}</td>
                                <td style={{ padding: '10px 12px' }}><span className={`sev-badge ${SEV_STYLE[f.severity] ?? ''}`}>{f.severity}</span></td>
                                <td style={{ padding: '10px 12px', fontFamily: "'JetBrains Mono', monospace", color: 'rgba(255,255,255,0.5)', fontSize: 11 }}>{f.cwe}</td>
                                <td style={{ padding: '10px 12px', color: 'rgba(255,255,255,0.7)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.rule_name}</td>
                                <td style={{ padding: '10px 12px', fontFamily: "'JetBrains Mono', monospace", color: 'rgba(255,255,255,0.6)', whiteSpace: 'nowrap' }}>{f.function_name}</td>
                                <td style={{ padding: '10px 12px', color: 'rgba(255,255,255,0.4)', whiteSpace: 'nowrap' }}>{f.line_start}</td>
                                <td style={{ padding: '10px 12px', color: 'rgba(255,255,255,0.7)', whiteSpace: 'nowrap' }}>
                                  {f.exploit_prob != null ? `${Math.round(f.exploit_prob * 100)}%` : '—'}
                                </td>
                                <td style={{ padding: '10px 12px', color: 'rgba(255,255,255,0.7)', whiteSpace: 'nowrap' }}>
                                  {f.composite_risk != null ? f.composite_risk.toFixed(2) : '—'}
                                </td>
                                <td style={{ padding: '10px 12px' }}>
                                  {f.taint_confirmed
                                    ? <CheckCircle2 size={15} style={{ color: '#4ade80' }} />
                                    : <XCircle size={15} style={{ color: 'rgba(255,255,255,0.2)' }} />}
                                </td>
                                <td style={{ padding: '10px 12px' }}>
                                  {expandedRow === f.vuln_id
                                    ? <ChevronDown size={14} style={{ color: 'rgba(255,255,255,0.4)' }} />
                                    : <ChevronRight size={14} style={{ color: 'rgba(255,255,255,0.4)' }} />}
                                </td>
                              </tr>

                              {/* Expanded row */}
                              {expandedRow === f.vuln_id && (
                                <tr>
                                  <td colSpan={10} style={{ padding: '4px 12px 20px', background: 'rgba(26,200,80,0.03)' }}>
                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, paddingTop: 12 }}>
                                      {/* Description + taint */}
                                      <div>
                                        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.1em', color: '#1AC850', textTransform: 'uppercase', marginBottom: 8 }}>Analysis</div>
                                        <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.75)', lineHeight: 1.65, marginBottom: 12 }}>{f.description}</div>
                                        {f.taint_path && (
                                          <div>
                                            <div style={{ fontSize: 11, fontWeight: 700, color: '#1AC850', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Taint Path</div>
                                            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: 'rgba(255,255,255,0.6)', background: 'rgba(0,0,0,0.3)', borderRadius: 8, padding: '8px 12px' }}>
                                              {f.taint_path}
                                            </div>
                                          </div>
                                        )}
                                        {f.agent_notes?.length > 0 && (
                                          <div style={{ marginTop: 12 }}>
                                            <div style={{ fontSize: 11, fontWeight: 700, color: '#1AC850', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Agent Notes</div>
                                            {f.agent_notes.map((n, i) => <div key={i} style={{ fontSize: 12, color: 'rgba(255,255,255,0.55)', marginBottom: 4 }}>• {n}</div>)}
                                          </div>
                                        )}
                                      </div>
                                      {/* Code snippet */}
                                      <div>
                                        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.1em', color: '#1AC850', textTransform: 'uppercase', marginBottom: 8 }}>Vulnerable Snippet</div>
                                        <pre style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#f87171', background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(248,113,113,0.15)', borderRadius: 8, padding: '12px', overflow: 'auto', margin: 0, lineHeight: 1.6 }}>
                                          {f.code_snippet || '// Snippet unavailable'}
                                        </pre>
                                        {f.patch_strategy && (
                                          <div style={{ marginTop: 12 }}>
                                            <div style={{ fontSize: 11, fontWeight: 700, color: '#1AC850', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Patch Strategy</div>
                                            <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.7)', lineHeight: 1.6 }}>{f.patch_strategy}</div>
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  </td>
                                </tr>
                              )}
                            </React.Fragment>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )
                }
              </div>
            )}

            {/* ── ML ANALYTICS ── */}
            {tab === 'mlanalysis' && (
              <div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 20 }}>
                  {['confusion_matrix', 'roc_curve', 'pr_curve', 'feature_importance'].map(key => (
                    <div key={key} style={{ background: 'rgba(26,200,80,0.04)', border: '1px solid rgba(26,200,80,0.15)', borderRadius: 12, overflow: 'hidden' }}>
                      <div style={{ padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: 11, fontWeight: 700, letterSpacing: '0.15em', textTransform: 'uppercase', color: '#1AC850' }}>
                        {key.replace(/_/g, ' ')}
                      </div>
                      <div style={{ height: 280, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
                        {plots[key]
                          ? <img src={`data:image/png;base64,${plots[key]}`} alt={key} style={{ maxHeight: '100%', maxWidth: '100%', objectFit: 'contain', filter: 'contrast(1.1) brightness(1.05)' }} />
                          : <span style={{ fontSize: 13, color: 'rgba(255,255,255,0.25)' }}>Graph pending — run a scan first</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── STANDARDS ── */}
            {tab === 'standards' && (
              <div>
                {/* Industry Standards Compliance Badges */}
                <div style={{ marginBottom: 28 }}>
                  <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.15em', color: '#1AC850', textTransform: 'uppercase', marginBottom: 12 }}>Industry Standard Coverage</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {['CERT-C', 'CERT-C++', 'CWE Top 25', 'OWASP Top 10', 'CVSS 3.1', 'MISRA C', 'SEI CERT', 'NIST SP 800-53'].map(std => (
                      <div key={std} style={{ background: 'rgba(26,200,80,0.1)', border: '1px solid rgba(26,200,80,0.3)', borderRadius: 999, padding: '5px 14px', fontSize: 12, fontWeight: 700, color: '#4ade80' }}>
                        {std}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Findings standards table */}
                {!findings.length
                  ? <div style={{ textAlign: 'center', padding: '48px 0', color: 'rgba(255,255,255,0.2)' }}>Standards mapping appears after a scan</div>
                  : findings.map(f => (
                    <div key={f.vuln_id} style={{ padding: '16px 20px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 10, marginBottom: 10 }}>
                      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, flexWrap: 'wrap', marginBottom: 6 }}>
                        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 700, color: '#1AC850' }}>{f.vuln_id}</span>
                        <span style={{ fontSize: 12, color: 'rgba(255,255,255,0.5)' }}>{f.cwe}</span>
                        <span className={`sev-badge ${SEV_STYLE[f.severity] ?? ''}`} style={{ marginLeft: 'auto' }}>{f.severity}</span>
                      </div>
                      {f.standards_citation && (
                        <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.7)', marginBottom: 6 }}>
                          <span style={{ color: '#1AC850', fontWeight: 600 }}>Standard: </span>{f.standards_citation}
                        </div>
                      )}
                      {f.patch_strategy && (
                        <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.6)', lineHeight: 1.6 }}>
                          <span style={{ color: '#1AC850', fontWeight: 600 }}>Mitigation: </span>{f.patch_strategy}
                        </div>
                      )}
                    </div>
                  ))
                }
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
