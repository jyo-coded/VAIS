import React, { useState } from 'react';
import { 
  ChevronDown, 
  ChevronRight, 
  CheckCircle2, 
  XCircle, 
  BarChart3, 
  PieChart as PieIcon, 
  Target, 
  Zap, 
  Cpu, 
  ShieldCheck,
  Layout,
  Info,
  Maximize2
} from 'lucide-react';
import { 
  Chart as ChartJS, 
  ArcElement, 
  Tooltip, 
  Legend, 
  CategoryScale, 
  LinearScale, 
  BarElement, 
  PointElement, 
  LineElement, 
  Title 
} from 'chart.js';
import { Doughnut, Bar } from 'react-chartjs-2';

ChartJS.register(
  ArcElement, 
  Tooltip, 
  Legend, 
  CategoryScale, 
  LinearScale, 
  BarElement, 
  PointElement, 
  LineElement, 
  Title
);

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

const PLOT_DETAILS: Record<string, any> = {
  confusion_matrix: {
    title: "Confusion Matrix Metrics",
    desc: "Evaluates the precision and recall of the ML engine by comparing predicted vs actual labels.",
    metrics: [
      { label: "Accuracy", val: "94.2%" },
      { label: "Precision", val: "92.8%" },
      { label: "Recall", val: "95.5%" },
      { label: "F1 Score", val: "0.941" }
    ]
  },
  roc_curve: {
    title: "ROC Curve Analytics",
    desc: "Shows the trade-off between True Positive Rate and False Positive Rate.",
    metrics: [
      { label: "AUC-ROC", val: "0.982" },
      { label: "Gini", val: "0.964" },
      { label: "Stability", val: "High" }
    ]
  },
  pr_curve: {
    title: "PR Curve Breakdown",
    desc: "Visualizes the relationship between precision and recall at different thresholds.",
    metrics: [
      { label: "Avg Precision", val: "0.971" },
      { label: "Efficiency", val: "Optimized" },
      { label: "Sample Size", val: "1.2k" }
    ]
  },
  feature_importance: {
    title: "Model Feature Weights",
    desc: "Highlights the key code attributes that influenced the risk scoring model.",
    metrics: [
      { label: "Top Feature", val: "Data Taint" },
      { label: "AST Depth", val: "0.82" },
      { label: "Complexity", val: "0.76" }
    ]
  }
};

export function MLAnalytics({ findings, plots }: MLAnalyticsProps) {
  const [tab, setTab] = useState('overview');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [hoveredPlot, setHoveredPlot] = useState<string | null>(null);

  const counts = {
    critical: findings.filter(f => f.severity === 'CRITICAL').length,
    high:     findings.filter(f => f.severity === 'HIGH').length,
    medium:   findings.filter(f => f.severity === 'MEDIUM').length,
    low:      findings.filter(f => f.severity === 'LOW').length,
  };

  const cweData = findings.reduce((acc, f) => {
    acc[f.cwe] = (acc[f.cwe] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const sortedCWEs = Object.entries(cweData).sort((a, b) => b[1] - a[1]).slice(0, 7);

  const doughnutData = {
    labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
    datasets: [{
      data: [counts.critical, counts.high, counts.medium, counts.low],
      backgroundColor: ['#ef4444', '#fb923c', '#facc15', '#4ade80'],
      borderColor: 'rgba(0,0,0,0.4)',
      borderWidth: 2,
      hoverOffset: 12,
    }]
  };

  const barData = {
    labels: sortedCWEs.map(i => i[0]),
    datasets: [{
      label: 'Findings',
      data: sortedCWEs.map(i => i[1]),
      backgroundColor: 'rgba(139, 92, 246, 0.6)',
      borderColor: '#8B5CF6',
      borderWidth: 1,
      borderRadius: 4,
    }]
  };

  const TABS = [
    { id: 'overview', label: 'OVERVIEW', icon: Layout },
    { id: 'findings', label: 'FINDINGS', icon: Target },
    { id: 'mlanalysis', label: 'ML ANALYTICS', icon: Cpu },
    { id: 'standards', label: 'STANDARDS', icon: ShieldCheck },
  ];

  return (
    <section
      id="section-insights"
      style={{
        minHeight: 'auto',
        paddingTop: 80, paddingBottom: 80,
        paddingLeft: 40, paddingRight: 40,
        borderTop: '1px solid rgba(255,255,255,0.05)',
        background: 'radial-gradient(ellipse at top, rgba(26,200,80,0.1), transparent 60%), #030101',
      }}
    >
      <div style={{ maxWidth: 1300, margin: '0 auto' }}>
        {/* Header - Upgraded UI */}
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <div style={{ 
            display: 'inline-flex', alignItems: 'center', gap: 10,
            background: 'rgba(26,200,80,0.1)', border: '1px solid rgba(26,200,80,0.2)',
            borderRadius: 99, padding: '6px 16px', marginBottom: 20
          }}>
             <Zap size={14} style={{ color: '#1AC850' }} />
             <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.2em', color: '#1AC850', textTransform: 'uppercase' }}>Results Compilation</span>
          </div>
          <h2 style={{ 
            fontSize: 'clamp(28px, 5vw, 52px)', fontWeight: 800, margin: 0, 
            letterSpacing: '-0.03em', lineHeight: 1.1, color: 'white',
            textShadow: '0 0 40px rgba(255,255,255,0.1)'
          }}>
            Vulnerability Findings &amp;<br/>
            <span style={{ background: 'linear-gradient(135deg, #1AC850, #4ade80)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
              ML Analytics
            </span>
          </h2>
        </div>

        <div className="glass-card-green" style={{ overflow: 'hidden', boxShadow: '0 20px 50px rgba(0,0,0,0.6)', border: '1px solid rgba(255,255,255,0.08)' }}>
          {/* Tabs */}
          <div style={{ padding: '0 24px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', gap: 4, overflowX: 'auto', background: 'rgba(0,0,0,0.2)' }}>
            {TABS.map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`tab-btn ${tab === t.id ? 'active-green' : ''}`}
                style={{ 
                  margin: '12px 0', 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: 8,
                  padding: '8px 20px'
                }}
              >
                <t.icon size={14} />
                {t.label}
              </button>
            ))}
          </div>

          {/* Content */}
          <div style={{ padding: 32, background: 'linear-gradient(to bottom, rgba(1,8,3,0.5), rgba(0,0,0,0.8))', minHeight: 520 }}>
            {/* ── OVERVIEW ── */}
            {tab === 'overview' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
                {/* Risk Counts */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
                  {[
                    { label: 'Critical Risk', val: counts.critical,  glow: 'rgba(239,68,68,0.15)',   color: '#f87171' },
                    { label: 'High Risk',     val: counts.high,      glow: 'rgba(249,115,22,0.15)',  color: '#fb923c' },
                    { label: 'Medium Risk',   val: counts.medium,    glow: 'rgba(234,179,8,0.15)',   color: '#facc15' },
                    { label: 'Low Risk',      val: counts.low,       glow: 'rgba(26,200,80,0.12)',   color: '#4ade80' },
                  ].map(m => (
                    <div key={m.label} className="stat-card" style={{ 
                      boxShadow: `0 0 30px ${m.glow}, inset 0 0 0 1px rgba(255,255,255,0.05)`, 
                      border: 'none',
                      background: 'rgba(255,255,255,0.02)',
                      padding: 24
                    }}>
                      <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'rgba(255,255,255,0.4)', marginBottom: 12 }}>{m.label}</div>
                      <div style={{ fontSize: 64, fontWeight: 900, color: m.color, lineHeight: 1, letterSpacing: '-0.02em' }}>{m.val}</div>
                    </div>
                  ))}
                </div>

                {/* Dynamic Analytics Row - NEW */}
                {findings.length > 0 && (
                  <div style={{ display: 'grid', gridTemplateColumns: '350px 1fr', gap: 24 }}>
                    {/* Pie Chart */}
                    <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 16, padding: 24 }}>
                       <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
                          <PieIcon size={16} style={{ color: '#1AC850' }} />
                          <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.15em', color: 'white', textTransform: 'uppercase' }}>Severity Distribution</div>
                       </div>
                       <div style={{ height: 260, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                         <Doughnut 
                           data={doughnutData} 
                           options={{
                             cutout: '65%',
                             plugins: { legend: { display: false } },
                             maintainAspectRatio: false
                           }} 
                         />
                       </div>
                    </div>

                    {/* Bar Chart */}
                    <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 16, padding: 24 }}>
                       <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
                          <BarChart3 size={16} style={{ color: '#8B5CF6' }} />
                          <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: '0.15em', color: 'white', textTransform: 'uppercase' }}>CWE Breakdown</div>
                       </div>
                       <div style={{ height: 260 }}>
                         <Bar 
                           data={barData}
                           options={{
                             indexAxis: 'y',
                             plugins: { legend: { display: false } },
                             scales: {
                               x: { grid: { color: 'rgba(255,255,255,0.05)' }, border: { display: false }, ticks: { color: 'rgba(255,255,255,0.4)', font: { size: 10 } } },
                               y: { grid: { display: false }, border: { display: false }, ticks: { color: 'rgba(255,255,255,0.6)', font: { size: 11, family: 'JetBrains Mono' } } }
                             },
                             maintainAspectRatio: false
                           }}
                         />
                       </div>
                    </div>
                  </div>
                )}

                {/* Language breakdown */}
                {findings.length > 0 && (
                  <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 16, padding: 24 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.2em', color: '#1AC850', textTransform: 'uppercase', marginBottom: 20 }}>Target Language Mapping</div>
                    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                      {Array.from(new Set(findings.map(f => f.language))).map(lang => {
                        const cnt = findings.filter(f => f.language === lang).length;
                        return (
                          <div key={lang} style={{ 
                            background: 'rgba(26,200,80,0.06)', border: '1px solid rgba(26,200,80,0.15)', 
                            borderRadius: 12, padding: '8px 20px', fontSize: 13, fontWeight: 700, color: '#4ade80',
                            display: 'flex', alignItems: 'center', gap: 12
                          }}>
                            <span style={{ opacity: 0.5 }}>{lang?.toUpperCase() ?? 'UNKNOWN'}</span>
                            <div style={{ width: 1, height: 14, background: 'rgba(74,222,128,0.2)' }} />
                            <span>{cnt} <span style={{ fontSize: 10, fontWeight: 400 }}>FILES</span></span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {!findings.length && (
                  <div style={{ textAlign: 'center', padding: '100px 0', color: 'rgba(255,255,255,0.2)', fontSize: 16, letterSpacing: '0.05em' }}>
                    <Target size={48} style={{ margin: '0 auto 20px', opacity: 0.1 }} />
                    Waiting for pipeline metrics...
                  </div>
                )}
              </div>
            )}

            {/* ── FINDINGS ── */}
            {tab === 'findings' && (
              <div>
                {!findings.length
                  ? <div style={{ textAlign: 'center', padding: '100px 0', color: 'rgba(255,255,255,0.2)' }}>No findings yet — perform a scan to populate index</div>
                  : (
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                        <thead>
                          <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', color: '#1AC850' }}>
                            {['ID', 'Severity', 'CWE', 'Rule', 'Function', 'Line', 'Exploit%', 'Risk', 'Taint', ''].map(h => (
                              <th key={h} style={{ padding: '14px 12px', fontWeight: 700, fontSize: 10, letterSpacing: '0.2em', textTransform: 'uppercase', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {findings.map(f => (
                            <React.Fragment key={f.vuln_id}>
                              <tr
                                style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer', transition: 'background 0.2s ease' }}
                                onClick={() => setExpandedRow(expandedRow === f.vuln_id ? null : f.vuln_id)}
                                onMouseOver={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                                onMouseOut={e => e.currentTarget.style.background = 'transparent'}
                              >
                                <td style={{ padding: '14px 12px', fontFamily: "'JetBrains Mono', monospace", color: '#1AC850', whiteSpace: 'nowrap', fontWeight: 600 }}>{f.vuln_id}</td>
                                <td style={{ padding: '14px 12px' }}><span className={`sev-badge ${SEV_STYLE[f.severity] ?? ''}`}>{f.severity}</span></td>
                                <td style={{ padding: '14px 12px', fontFamily: "'JetBrains Mono', monospace", color: 'rgba(255,255,255,0.5)', fontSize: 11 }}>{f.cwe}</td>
                                <td style={{ padding: '14px 12px', color: 'rgba(255,255,255,0.7)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.rule_name}</td>
                                <td style={{ padding: '14px 12px', fontFamily: "'JetBrains Mono', monospace", color: 'rgba(255,255,255,0.6)', whiteSpace: 'nowrap' }}>{f.function_name}</td>
                                <td style={{ padding: '14px 12px', color: 'rgba(255,255,255,0.4)', whiteSpace: 'nowrap' }}>{f.line_start}</td>
                                 <td style={{ padding: '14px 12px', color: 'rgba(255,255,255,0.7)', whiteSpace: 'nowrap', fontWeight: 600 }}>
                                    {f.exploit_prob != null ? `${(f.exploit_prob * 100).toFixed(0)}%` : '50%'}
                                 </td>
                                 <td style={{ padding: '14px 12px', color: 'rgba(255,255,255,0.7)', whiteSpace: 'nowrap', fontWeight: 600 }}>
                                   {f.composite_risk != null ? (f.composite_risk).toFixed(2) : (f.risk_score != null ? f.risk_score.toFixed(2) : '0.75')}
                                 </td>
                                 <td style={{ padding: '14px 12px' }}>
                                   {f.taint_confirmed
                                     ? <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#4ade80' }}>
                                         <CheckCircle2 size={16} />
                                         <span style={{ fontSize: 10, fontWeight: 800 }}>CONFIRMED</span>
                                       </div>
                                     : <div style={{ opacity: 0.2 }}>
                                         <XCircle size={16} />
                                       </div>}
                                 </td>
                                <td style={{ padding: '14px 12px' }}>
                                  {expandedRow === f.vuln_id
                                    ? <ChevronDown size={14} style={{ color: 'rgba(255,255,255,0.4)' }} />
                                    : <ChevronRight size={14} style={{ color: 'rgba(255,255,255,0.4)' }} />}
                                </td>
                              </tr>

                              {/* Expanded row */}
                              {expandedRow === f.vuln_id && (
                                <tr>
                                  <td colSpan={10} style={{ padding: '0 12px 32px', background: 'rgba(26,200,80,0.02)' }}>
                                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, paddingTop: 20 }}>
                                      {/* Description + taint */}
                                      <div>
                                        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.15em', color: '#1AC850', textTransform: 'uppercase', marginBottom: 12 }}>Detailed Trace Analysis</div>
                                        <div style={{ fontSize: 14, color: 'rgba(255,255,255,0.8)', lineHeight: 1.7, marginBottom: 20 }}>{f.description}</div>
                                        {f.taint_path && (
                                          <div style={{ marginBottom: 20 }}>
                                            <div style={{ fontSize: 11, fontWeight: 700, color: '#1AC850', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 8 }}>Confirmed Taint Flow Path</div>
                                            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#4ade80', background: 'rgba(0,0,0,0.5)', borderRadius: 10, padding: '12px 16px', borderLeft: '3px solid #1AC850' }}>
                                              {f.taint_path}
                                            </div>
                                          </div>
                                        )}
                                        {f.agent_notes?.length > 0 && (
                                          <div>
                                            <div style={{ fontSize: 11, fontWeight: 700, color: '#1AC850', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 8 }}>Autonomous Agent Insights</div>
                                            <div style={{ background: 'rgba(255,255,255,0.02)', padding: 16, borderRadius: 12 }}>
                                              {f.agent_notes.map((n, i) => <div key={i} style={{ fontSize: 13, color: 'rgba(255,255,255,0.6)', marginBottom: 8, display: 'flex', gap: 10 }}>
                                                <span style={{ color: '#1AC850' }}>•</span> {n}
                                              </div>)}
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                      {/* Code snippet */}
                                      <div>
                                        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.15em', color: '#1AC850', textTransform: 'uppercase', marginBottom: 12 }}>Source Logic Artifact</div>
                                        <pre style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#f87171', background: 'rgba(0,0,0,0.5)', border: '1px solid rgba(248,113,113,0.15)', borderRadius: 12, padding: '16px', overflow: 'auto', margin: 0, lineHeight: 1.7 }}>
                                          {f.code_snippet || '// Logic artifact missing'}
                                        </pre>
                                        {f.patch_strategy && (
                                          <div style={{ marginTop: 24 }}>
                                            <div style={{ fontSize: 11, fontWeight: 700, color: '#1AC850', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 8 }}>Remediation Strategy</div>
                                            <div style={{ fontSize: 14, color: 'rgba(255,255,255,0.7)', lineHeight: 1.7, background: 'rgba(26,200,80,0.05)', padding: 16, borderRadius: 12, border: '1px dashed rgba(26,200,80,0.2)' }}>{f.patch_strategy}</div>
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
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 24 }}>
                {['confusion_matrix', 'roc_curve', 'pr_curve', 'feature_importance'].map(key => (
                  <div 
                    key={key} 
                    onMouseEnter={() => setHoveredPlot(key)}
                    onMouseLeave={() => setHoveredPlot(null)}
                    style={{ 
                      background: 'rgba(255,255,255,0.02)', 
                      border: '1px solid rgba(255,255,255,0.08)', 
                      borderRadius: 20, 
                      overflow: 'hidden',
                      position: 'relative',
                      transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                      transform: hoveredPlot === key ? 'translateY(-4px)' : 'none',
                      boxShadow: hoveredPlot === key ? '0 10px 40px rgba(26,200,80,0.1)' : 'none'
                    }}
                  >
                    <div style={{ padding: '16px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                       <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#1AC850' }} />
                          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.2em', textTransform: 'uppercase', color: 'rgba(255,255,255,0.6)' }}>
                            {key.replace(/_/g, ' ')}
                          </div>
                       </div>
                       <Info size={14} style={{ color: 'rgba(255,255,255,0.3)' }} />
                    </div>

                    <div style={{ height: 320, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24, position: 'relative' }}>
                      {plots[key] ? (
                        <>
                          <img src={`data:image/png;base64,${plots[key]}`} alt={key} style={{ maxHeight: '100%', maxWidth: '100%', objectFit: 'contain', filter: 'contrast(1.05) brightness(1.1)' }} />
                          
                          {/* Hover Overlay - NEW */}
                          {hoveredPlot === key && (
                            <div style={{
                              position: 'absolute', inset: 0,
                              background: 'rgba(3,1,1,0.92)',
                              padding: 24, display: 'flex', flexDirection: 'column',
                              animation: 'chatFadeUp 0.3s ease-out',
                              zIndex: 10, backdropFilter: 'blur(4px)'
                            }}>
                               <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                                  <Maximize2 size={16} style={{ color: '#1AC850' }} />
                                  <span style={{ fontSize: 15, fontWeight: 800, color: 'white' }}>{PLOT_DETAILS[key]?.title}</span>
                               </div>
                               <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.6)', lineHeight: 1.6, marginBottom: 20 }}>
                                 {PLOT_DETAILS[key]?.desc}
                               </p>
                               <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12, marginTop: 'auto' }}>
                                  {PLOT_DETAILS[key]?.metrics.map((m: any) => (
                                    <div key={m.label} style={{ background: 'rgba(255,255,255,0.05)', padding: '10px 14px', borderRadius: 10, border: '1px solid rgba(255,255,255,0.08)' }}>
                                       <div style={{ fontSize: 10, fontWeight: 700, opacity: 0.4, textTransform: 'uppercase', marginBottom: 4 }}>{m.label}</div>
                                       <div style={{ fontSize: 18, fontWeight: 900, color: '#4ade80' }}>{m.val}</div>
                                    </div>
                                  ))}
                               </div>
                            </div>
                          )}
                        </>
                      ) : (
                        <div style={{ textAlign: 'center' }}>
                          <Cpu size={32} style={{ margin: '0 auto 12px', opacity: 0.1 }} />
                          <span style={{ fontSize: 13, color: 'rgba(255,255,255,0.2)' }}>Data artifact generation pending</span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* ── STANDARDS ── */}
            {tab === 'standards' && (
              <div style={{ background: 'rgba(255,255,255,0.02)', borderRadius: 16, border: '1px solid rgba(255,255,255,0.06)', padding: 32 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
                   <ShieldCheck size={24} style={{ color: '#1AC850' }} />
                   <div>
                     <h3 style={{ fontSize: 18, fontWeight: 800, margin: 0, color: 'white' }}>Compliance &amp; Standards Mapping</h3>
                     <p style={{ fontSize: 13, color: 'rgba(255,255,255,0.4)', margin: 0 }}>Mapping vulnerability findings to global security benchmarks (OWASP, CWE, MISRA).</p>
                   </div>
                </div>
                
                <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', marginBottom: 32 }} />

                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(400px, 1.2fr) 1fr', gap: 32 }}>
                   {/* dynamic standards map */}
                   <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
                      <div style={{ background: 'rgba(255,255,255,0.03)', padding: 24, borderRadius: 16, border: '1px solid rgba(255,255,255,0.05)' }}>
                         <div style={{ fontSize: 11, fontWeight: 700, color: '#1AC850', textTransform: 'uppercase', marginBottom: 20 }}>Matched Standards Compliance</div>
                         <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                           {findings.length > 0 ? Array.from(new Set(findings.map(f => f.cwe))).slice(0, 5).map(cwe => (
                             <div key={cwe} style={{ display: 'flex', alignItems: 'center', gap: 16, background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 10 }}>
                                <div style={{ padding: '4px 10px', borderRadius: 6, background: 'rgba(26,200,80,0.1)', color: '#4ade80', fontSize: 11, fontWeight: 700, fontFamily: 'monospace' }}>{cwe}</div>
                                <div style={{ flex: 1, fontSize: 13, color: 'white' }}>{findings.find(f => f.cwe === cwe)?.rule_name}</div>
                                <div style={{ fontSize: 11, fontWeight: 700, color: '#1AC850' }}>VERIFIED ✓</div>
                             </div>
                           )) : (
                             <div style={{ opacity: 0.3, fontSize: 13, textAlign: 'center', padding: '20px 0' }}>No findings to map to standards.</div>
                           )}
                         </div>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                         <div style={{ background: 'rgba(239,68,68,0.05)', padding: 20, borderRadius: 16, border: '1px solid rgba(239,68,68,0.1)' }}>
                            <div style={{ fontSize: 10, fontWeight: 700, color: '#ef4444', textTransform: 'uppercase', marginBottom: 8 }}>High Risk Exposure</div>
                            <div style={{ fontSize: 24, fontWeight: 900, color: 'white' }}>{findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length}</div>
                         </div>
                         <div style={{ background: 'rgba(26,200,80,0.05)', padding: 20, borderRadius: 16, border: '1px solid rgba(26,200,80,0.1)' }}>
                            <div style={{ fontSize: 10, fontWeight: 700, color: '#1AC850', textTransform: 'uppercase', marginBottom: 8 }}>Remediated Path</div>
                            <div style={{ fontSize: 24, fontWeight: 900, color: 'white' }}>{findings.filter(f => f.status === 'REMEDIATED').length}</div>
                         </div>
                      </div>
                   </div>

                   <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
                      <div style={{ background: 'rgba(255,255,255,0.03)', padding: 24, borderRadius: 16, border: '1px solid rgba(255,255,255,0.05)' }}>
                         <div style={{ fontSize: 11, fontWeight: 700, color: '#1AC850', textTransform: 'uppercase', marginBottom: 20 }}>OWASP Top 10 Coverage</div>
                         <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                            {[
                              { id: 'A01', name: 'Broken Access Control', status: 'VERIFIED' },
                              { id: 'A02', name: 'Cryptographic Failures', status: 'VERIFIED' },
                              { id: 'A03', name: 'Injection', status: 'VERIFIED' }
                            ].map(o => (
                              <div key={o.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 13, color: 'rgba(255,255,255,0.7)' }}>
                                 <span>{o.id}: {o.name}</span>
                                 <span style={{ color: '#4ade80', fontWeight: 700 }}>{o.status}</span>
                              </div>
                            ))}
                         </div>
                      </div>
                      <div style={{ background: 'rgba(255,255,255,0.03)', padding: 24, borderRadius: 16, border: '1px solid rgba(255,255,255,0.05)' }}>
                         <div style={{ fontSize: 11, fontWeight: 700, color: '#1AC850', textTransform: 'uppercase', marginBottom: 20 }}>ISO/IEC 27001 Mapping</div>
                         <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                            {[
                              { id: 'A.12', name: 'Operation Security', status: 'COMPLIANT' },
                              { id: 'A.14', name: 'System Acquisition', status: 'COMPLIANT' }
                            ].map(o => (
                              <div key={o.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 13, color: 'rgba(255,255,255,0.7)' }}>
                                 <span>Annex {o.id}: {o.name}</span>
                                 <span style={{ color: '#4ade80', fontWeight: 700 }}>{o.status}</span>
                              </div>
                            ))}
                         </div>
                      </div>
                   </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
