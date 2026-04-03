import React, { useCallback, useEffect, useRef, useState } from 'react';
import { ChevronDown, ChevronRight, Folder, FileCode, Search, FolderOpen, Upload, MousePointerClick, Activity } from 'lucide-react';

type FileNode = {
  name: string;
  path: string;
  type: 'directory' | 'file';
  status?: 'unscanned' | 'scanning' | 'vuln' | 'clean';
  findings?: { critical: number; high: number };
  children?: FileNode[];
};

type SampleFile = {
  name: string;
  path: string;
  language: string;
  description: string;
  known_vulns: number;
};

interface ScanConsoleProps {
  files: FileNode[];
  onScan: (path: string, lang: string) => void;
  scanningPath: string | null;
  status: { backend: string; ollama: { reachable: boolean; model: string; mode: string } };
}

const DEMO_SAMPLES: SampleFile[] = [
  { name: 'vulnerable.c',    path: 'tests/samples/vulnerable.c',    language: 'C',      description: 'Buffer overflows, format strings, strcpy misuse',  known_vulns: 6 },
  { name: 'vulnerable.cpp',  path: 'tests/samples/vulnerable.cpp',  language: 'C++',    description: 'Memory leaks, UAF, double-free, integer overflow',  known_vulns: 8 },
  { name: 'vulnerable.go',   path: 'tests/samples/vulnerable.go',   language: 'Go',     description: 'Race conditions, unchecked errors, unsafe pointers', known_vulns: 4 },
  { name: 'vulnerable.java', path: 'tests/samples/vulnerable.java', language: 'Java',   description: 'SQL injection, XXE, hardcoded secrets, weak crypto',  known_vulns: 7 },
  { name: 'vulnerable.py',   path: 'tests/samples/vulnerable.py',   language: 'Python', description: 'Code injection via eval, pickle deserialization, path traversal', known_vulns: 5 },
];

const LANG_COLORS: Record<string, string> = {
  C: '#E85D04', 'C++': '#fb923c', Go: '#38bdf8', Java: '#facc15', Python: '#a78bfa'
};

export function ScanConsole({ files, onScan, scanningPath, status }: ScanConsoleProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [dragOver, setDragOver] = useState(false);
  const [activeView, setActiveView] = useState<'demo' | 'workspace'>('demo');
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!files.length) return;
    const next: Record<string, boolean> = {};
    files.slice(0, 4).forEach(f => { if (f.type === 'directory') next[f.path] = true; });
    setExpanded(prev => ({ ...next, ...prev }));
  }, [files]);

  const toggle = (path: string) => setExpanded(prev => ({ ...prev, [path]: !prev[path] }));

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const items = Array.from(e.dataTransfer.items);
    // Find first code file
    for (const item of items) {
      if (item.kind === 'file') {
        const file = item.getAsFile();
        if (file) {
          // Upload to backend
          const fd = new FormData();
          fd.append('file', file);
          fetch('/api/upload', { method: 'POST', body: fd })
            .then(r => r.json())
            .then((d: { path: string }) => onScan(d.path, 'auto'))
            .catch(console.error);
          return;
        }
      }
    }
  }, [onScan]);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const fd = new FormData();
    fd.append('file', file);
    fetch('/api/upload', { method: 'POST', body: fd })
      .then(r => r.json())
      .then((d: { path: string }) => onScan(d.path, 'auto'))
      .catch(console.error);
  };

  const renderTree = (items: FileNode[], depth = 0): React.ReactNode =>
    items.map(item => {
      const issueCount = (item.findings?.critical ?? 0) + (item.findings?.high ?? 0);
      const isScanning = scanningPath === item.path;
      const rowClass = `file-row${isScanning ? ' scanning' : item.status === 'vuln' ? ' vuln' : item.status === 'clean' ? ' clean' : ''}`;

      return (
        <div key={item.path}>
          <div
            className={rowClass}
            onClick={() => item.type === 'directory' ? toggle(item.path) : onScan(item.path, 'auto')}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: `7px 8px 7px ${12 + depth * 16}px`,
              cursor: 'pointer', userSelect: 'none',
            }}
          >
            {item.type === 'directory'
              ? (expanded[item.path]
                ? <ChevronDown size={14} style={{ color: '#E85D04', flexShrink: 0 }} />
                : <ChevronRight size={14} style={{ color: '#E85D04', flexShrink: 0 }} />)
              : <span style={{
                  width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                  background: item.status === 'vuln' ? '#f87171' : item.status === 'clean' ? '#4ade80' : item.status === 'scanning' ? '#fcd34d' : 'rgba(255,255,255,0.2)',
                }} />
            }
            {item.type === 'directory'
              ? <FolderOpen size={14} style={{ color: '#E85D04', flexShrink: 0 }} />
              : <FileCode size={14} style={{ color: 'rgba(255,255,255,0.4)', flexShrink: 0 }} />
            }
            <span style={{ fontSize: 13, fontWeight: 500, color: 'rgba(255,255,255,0.85)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {item.name}
            </span>
            {issueCount > 0 && (
              <span style={{ background: 'rgba(232,93,4,0.2)', color: '#fb923c', border: '1px solid rgba(232,93,4,0.35)', borderRadius: 999, fontSize: 10, fontWeight: 700, padding: '1px 7px', flexShrink: 0 }}>
                {issueCount}
              </span>
            )}
            {isScanning && <Activity size={13} style={{ color: '#E85D04', flexShrink: 0, animation: 'spin 1s linear infinite' }} />}
          </div>
          {item.type === 'directory' && expanded[item.path] && item.children?.length
            ? <div style={{ borderLeft: '1px solid rgba(255,255,255,0.05)', marginLeft: 20 }}>{renderTree(item.children, depth + 1)}</div>
            : null}
        </div>
      );
    });

  return (
    <section id="section-hero" style={{ minHeight: '100vh', paddingTop: 120, paddingBottom: 80, paddingLeft: 40, paddingRight: 40, display: 'flex', flexDirection: 'column', alignItems: 'center', position: 'relative', overflow: 'hidden' }}>
      {/* Molten pillar */}
      <div className="molten-pillar" />

      {/* Hero Text */}
      <div style={{ zIndex: 10, textAlign: 'center', marginBottom: 64, position: 'relative' }}>
        <p className="section-kicker" style={{ color: '#E85D04', marginBottom: 16 }}>Target Selection</p>
        <h2 style={{ fontSize: 'clamp(36px, 6vw, 72px)', fontWeight: 800, lineHeight: 1.08, margin: '0 0 20px', letterSpacing: '-0.02em' }}>
          Identify flaws.<br/>
          <span style={{ background: 'linear-gradient(135deg, #FFB050, #E85D04)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
            Deploy intelligence.
          </span>
        </h2>
        <p style={{ fontSize: 17, color: 'rgba(255,255,255,0.45)', maxWidth: 520, margin: '0 auto 32px', lineHeight: 1.6, fontWeight: 400 }}>
          Select a project file, drop your code below, or use the demo vulnerable samples to run the full autonomous pipeline.
        </p>

        {/* Status Indicators */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 28, fontSize: 13, fontWeight: 600 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: status.backend === 'connected' ? '#4ade80' : 'rgba(255,255,255,0.4)' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: status.backend === 'connected' ? '#4ade80' : '#71717a', animation: status.backend === 'connected' ? 'moltenPulse 2s ease infinite' : 'none' }} />
            API {status.backend}
          </div>
          <div style={{ width: 1, height: 16, background: 'rgba(255,255,255,0.1)' }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: status.ollama.reachable ? '#4ade80' : '#fbbf24' }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: status.ollama.reachable ? '#4ade80' : '#fbbf24' }} />
            LLM {status.ollama.reachable ? 'Online' : status.ollama.mode === 'fallback' ? 'Fallback' : 'Offline'}
          </div>
        </div>
      </div>

      {/* Main Panel */}
      <div style={{ zIndex: 10, width: '100%', maxWidth: 900 }}>
        {/* View toggle */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
          <button className={`tab-btn ${activeView === 'demo' ? 'active-orange' : ''}`} onClick={() => setActiveView('demo')}>
            Demo Samples
          </button>
          <button className={`tab-btn ${activeView === 'workspace' ? 'active-orange' : ''}`} onClick={() => setActiveView('workspace')}>
            Workspace Files
          </button>
        </div>

        <div className="glass-card-orange" style={{ overflow: 'hidden' }}>
          {/* Header */}
          <div style={{ padding: '20px 24px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: 12 }}>
            <Search size={16} style={{ color: 'rgba(255,255,255,0.4)' }} />
            <span style={{ fontSize: 15, fontWeight: 700, color: 'white', flex: 1 }}>Target Selection Matrix</span>
            <button
              onClick={() => fileInputRef.current?.click()}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                background: 'rgba(232,93,4,0.15)', border: '1px solid rgba(232,93,4,0.35)',
                borderRadius: 8, color: '#E85D04', fontSize: 12, fontWeight: 600,
                padding: '6px 12px', cursor: 'pointer', fontFamily: 'Inter, sans-serif',
              }}
            >
              <Upload size={13} /> Open File
            </button>
            <input ref={fileInputRef} type="file" style={{ display: 'none' }} onChange={handleFileInput} accept=".c,.cpp,.cc,.h,.py,.go,.java,.js,.ts" />
          </div>

          {/* Body */}
          <div style={{ height: 420, overflowY: 'auto', overflowX: 'hidden' }}>
            {activeView === 'demo' ? (
              <>
                {/* Drag drop zone */}
                <div
                  className={`drop-zone${dragOver ? ' drag-over' : ''}`}
                  onDrop={handleDrop}
                  onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                  onDragLeave={() => setDragOver(false)}
                  style={{ margin: 16, padding: '20px 24px', display: 'flex', alignItems: 'center', gap: 12 }}
                >
                  <MousePointerClick size={20} style={{ color: 'rgba(232,93,4,0.6)', flexShrink: 0 }} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: 'rgba(255,255,255,0.7)' }}>Drag & drop any source file here</div>
                    <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', marginTop: 2 }}>Supports .c .cpp .go .java .py .js .ts</div>
                  </div>
                </div>

                {/* Demo files */}
                <div style={{ padding: '8px 16px 16px' }}>
                  <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.15em', color: 'rgba(255,255,255,0.3)', textTransform: 'uppercase', marginBottom: 8, paddingLeft: 8 }}>
                    Vulnerable Sample Files
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {DEMO_SAMPLES.map(sample => (
                      <div
                        key={sample.path}
                        onClick={() => onScan(sample.path, 'auto')}
                        className="file-row"
                        style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 12px', cursor: 'pointer', borderRadius: 10, transition: 'all 200ms ease' }}
                      >
                        <div style={{
                          width: 36, height: 36, borderRadius: 8, flexShrink: 0,
                          background: `rgba(${LANG_COLORS[sample.language] ? parseInt(LANG_COLORS[sample.language].slice(1,3),16) + ',' + parseInt(LANG_COLORS[sample.language].slice(3,5),16) + ',' + parseInt(LANG_COLORS[sample.language].slice(5,7),16) : '255,255,255'}, 0.15)`,
                          border: `1px solid rgba(255,255,255,0.08)`,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 11, fontWeight: 800, color: LANG_COLORS[sample.language] ?? 'white',
                        }}>
                          {sample.language.slice(0, 2)}
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 14, fontWeight: 600, color: 'rgba(255,255,255,0.9)', fontFamily: "'JetBrains Mono', monospace" }}>{sample.name}</div>
                          <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', marginTop: 2 }}>{sample.description}</div>
                        </div>
                        <div style={{ flexShrink: 0, background: 'rgba(248,113,113,0.15)', border: '1px solid rgba(248,113,113,0.3)', borderRadius: 999, fontSize: 10, fontWeight: 700, padding: '2px 8px', color: '#f87171' }}>
                          {sample.known_vulns} vulns
                        </div>
                        {scanningPath === sample.path && (
                          <Activity size={14} style={{ color: '#E85D04', flexShrink: 0 }} />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <div style={{ padding: '8px 12px 12px' }}>
                {files.length ? renderTree(files) : (
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 300, color: 'rgba(255,255,255,0.3)' }}>
                    <Folder size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
                    <span style={{ fontSize: 14 }}>Loading workspace...</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
