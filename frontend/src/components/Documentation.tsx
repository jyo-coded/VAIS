import { useState } from 'react';
import { BookOpen, Shield, Wrench, ChevronDown, ChevronRight, Activity, Clock, CheckCircle2 } from 'lucide-react';

export type PatchRecord = {
  id: string;
  vuln_id: string;
  rule_name: string;
  file_path: string;
  timestamp: string;
  strategy: string;
};

interface DocumentationProps {
  findings?: any[];
  patchHistory?: PatchRecord[];
}

const SECURE_CODING_RULES = [
  { id: 'MEM00-C', cwe: 'CWE-401', category: 'Memory', title: 'Always free dynamically allocated resources', desc: 'Every call to malloc, calloc, or realloc must have a corresponding call to free. Failure to do so causes memory leaks that can be exploited to exhaust resources.', lang: 'C / C++' },
  { id: 'MEM30-C', cwe: 'CWE-416', category: 'Memory', title: 'Do not access freed memory', desc: 'After a block of memory has been freed, do not access it again. This is a use-after-free (UAF) vulnerability and is one of the most commonly exploited memory safety issues.', lang: 'C / C++' },
  { id: 'STR31-C', cwe: 'CWE-120', category: 'Strings', title: 'Guarantee that storage for strings has sufficient space', desc: 'Buffer overflows occur when data (often strings) is written beyond the end of an allocated buffer. Use bounded functions like strncpy or strlcpy instead of strcpy.', lang: 'C / C++' },
  { id: 'ARR38-C', cwe: 'CWE-119', category: 'Arrays', title: 'Guarantee that library functions do not form invalid pointers', desc: 'Library functions that accept pointer + length arguments must be called with consistent values. Passing incorrect lengths results in out-of-bounds reads or writes.', lang: 'C / C++' },
  { id: 'ERR00-CPP', cwe: 'CWE-391', category: 'Errors', title: 'Adopt and implement a consistent and comprehensive error-handling policy', desc: 'All error conditions must be handled. Unchecked return values from security-critical functions (open, read, write, exec) are a common source of vulnerabilities.', lang: 'C++' },
  { id: 'IDS00-J', cwe: 'CWE-89', category: 'Injection', title: 'Prevent SQL injection using parameterized queries', desc: 'Never concatenate user input into SQL query strings. Use PreparedStatement with parameterized queries exclusively in Java applications.', lang: 'Java' },
  { id: 'MSC61-J', cwe: 'CWE-327', category: 'Crypto', title: 'Do not use insecure or weak cryptographic algorithms', desc: 'MD5, SHA-1, DES, and RC4 are considered broken. Use SHA-256/384/512, AES-256-GCM, and RSA-2048 or higher for all cryptographic operations.', lang: 'Java / Python' },
  { id: 'ENV33-C', cwe: 'CWE-78', category: 'System', title: 'Do not call system()', desc: 'The system() function passes a command string to the OS shell, making it susceptible to command injection. Use exec() family functions with explicit argument arrays instead.', lang: 'C / C++' },
  { id: 'PY-001', cwe: 'CWE-94', category: 'Python', title: 'Never use eval() on untrusted input', desc: 'The eval() function executes arbitrary Python code. Any user-controlled input passed to eval() results in remote code execution. Use ast.literal_eval() or explicit parsing.', lang: 'Python' },
  { id: 'GO-001', cwe: 'CWE-703', category: 'Go', title: 'Always check errors from goroutines and channels', desc: 'Ignoring error values in Go means failures pass silently. All error returns must be checked, logged, and handled appropriately to prevent undefined behavior.', lang: 'Go' },
];

const MITIGATION_MAP: Record<string, { name: string; pattern: string }> = {
  'cwe-120': { 
    name: 'Safe Pointer Arithmetic & Bounds Checking', 
    pattern: 'Replace strcpy/strcat with strncpy/strlcpy. Implement explicit null termination and verify distance between pointers before copy operations.' 
  },
  'cwe-416': { 
    name: 'Pointer Nullification (RAII)', 
    pattern: 'Immediately set pointers to NULL after free(). Use unique_ptr/shared_ptr in C++ to automate lifecycle management and prevent dangling references.' 
  },
  'cwe-415': { 
    name: 'Double Free Guard', 
    pattern: 'Implement tracking for resource ownership. Ensure only one owner is responsible for deallocation and use guards to prevent re-entry into free blocks.' 
  },
  'cwe-121': { 
    name: 'Stack Protection & Canary Analysis', 
    pattern: 'Use compiler-level stack protection (-fstack-protector). Replace gets() with fgets() and ensure buffer sizes are verified against input streams.' 
  },
  'cwe-134': { 
    name: 'Format String Sanitization', 
    pattern: 'Avoid passing user-controlled strings as the first argument to printf/sprintf. Always use static format strings and pass user data as subsequent arguments.' 
  }
};

export function Documentation({ findings = [], patchHistory = [] }: DocumentationProps) {
  const [activeTab, setActiveTab] = useState<'guidelines' | 'history' | 'techniques'>('guidelines');
  const [expandedRule, setExpandedRule] = useState<string | null>(null);

  // Dynamic filtering for guidelines
  const activeCWEs = findings.map(f => f.cwe.toUpperCase());
  const relevantGuidelines = activeCWEs.length > 0 
    ? SECURE_CODING_RULES.filter(r => 
        activeCWEs.some(cwe => cwe === r.cwe || cwe.includes(r.id.split('-')[0]))
      )
    : SECURE_CODING_RULES.slice(0, 4);

  const TABS = [
    { id: 'guidelines' as const, label: 'Secure Coding Guidelines', icon: BookOpen },
    { id: 'history' as const, label: 'Patch History', icon: Clock },
    { id: 'techniques' as const, label: 'Mitigation Techniques', icon: Wrench },
  ];

  return (
    <div style={{ minHeight: '100vh', paddingTop: 120, paddingBottom: 100, background: '#030101', paddingLeft: 40, paddingRight: 40 }}>
      <div style={{ maxWidth: 1100, margin: '0 auto', padding: '0 40px' }}>
        
        {/* Header Section */}
        <div style={{ marginBottom: 60 }}>
          <div style={{ 
            display: 'inline-flex', alignItems: 'center', gap: 10,
            background: 'rgba(232,93,4,0.1)', border: '1px solid rgba(232,93,4,0.2)',
            borderRadius: 99, padding: '6px 16px', marginBottom: 20
          }}>
             <Activity size={14} style={{ color: '#E85D04' }} />
             <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.2em', color: '#E85D04', textTransform: 'uppercase' }}>Security Knowledge Base</span>
          </div>
          <h2 style={{ 
            fontSize: 'clamp(32px, 5vw, 56px)', fontWeight: 800, margin: 0, 
            letterSpacing: '-0.03em', lineHeight: 1.1, color: 'white',
            textShadow: '0 0 40px rgba(232,93,4,0.1)'
          }}>
            Vulnerability Remediation &amp;<br/>
            <span style={{ background: 'linear-gradient(135deg, #FFB050, #E85D04)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
              Advanced Documentation
            </span>
          </h2>
          <p style={{ fontSize: 18, color: 'rgba(255,255,255,0.4)', maxWidth: 650, marginTop: 24, lineHeight: 1.6 }}>
            Comprehensive reference architecture for secure coding, interactive patch auditing, and enterprise-grade mitigation techniques.
          </p>
        </div>

        {/* Global Compliance Status / Scan Summary */}
        <div style={{ 
          background: 'rgba(255,255,255,0.02)', 
          border: '1px solid rgba(255,255,255,0.05)', 
          borderRadius: 16, 
          padding: 24, 
          marginBottom: 48,
          display: 'flex',
          alignItems: 'center',
          gap: 32,
          backdropFilter: 'blur(10px)'
        }}>
          {findings.length > 0 ? (
            <>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span style={{ fontSize: 10, fontWeight: 800, color: '#E85D04', textTransform: 'uppercase', marginBottom: 4 }}>Industry standard code extension</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase' }}>Active Audit</span>
                <span style={{ fontSize: 13, color: 'white', fontWeight: 600 }}>{findings[0].source_file.split('/').pop()}</span>
              </div>
              <div style={{ width: 1, height: 40, background: 'rgba(255,255,255,0.1)' }} />
              <div style={{ display: 'flex', gap: 24 }}>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', textTransform: 'uppercase' }}>High Risk</span>
                  <span style={{ fontSize: 16, color: '#f87171', fontWeight: 800 }}>{findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <span style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', textTransform: 'uppercase' }}>Taint Confirmed</span>
                  <span style={{ fontSize: 16, color: '#10B981', fontWeight: 800 }}>{findings.filter(f => f.taint_confirmed).length}</span>
                </div>
              </div>
            </>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: 'rgba(255,255,255,0.4)', textTransform: 'uppercase' }}>Compliance Status</span>
              <span style={{ fontSize: 13, color: 'white', fontWeight: 600 }}>CWE / CERT / OWASP Compliant</span>
            </div>
          )}
          
          <div style={{ width: 1, height: 40, background: 'rgba(255,255,255,0.1)' }} />
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
             {['CERT-C', 'CWE-TOP-25', 'OWASP-ASVS', 'MISRA-2023'].map(tag => (
               <div key={tag} style={{ 
                 padding: '4px 12px', borderRadius: 6, background: 'rgba(232,93,4,0.08)', 
                 border: '1px solid rgba(232,93,4,0.2)', color: '#FFB050',
                 fontSize: 11, fontWeight: 700
               }}>{tag}</div>
             ))}
          </div>
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12, color: '#4ade80', fontSize: 12, fontWeight: 700 }}>
             <CheckCircle2 size={16} />
             Live Sync Active
          </div>
        </div>

        {/* Dynamic Navigation */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 32 }}>
           {TABS.map(tab => (
             <button
               key={tab.id}
               onClick={() => setActiveTab(tab.id)}
               style={{
                 display: 'flex', alignItems: 'center', gap: 10,
                 padding: '12px 24px', borderRadius: 12,
                 background: activeTab === tab.id ? 'rgba(232,93,4,0.1)' : 'rgba(255,255,255,0.03)',
                 border: `1px solid ${activeTab === tab.id ? 'rgba(232,93,4,0.4)' : 'rgba(255,255,255,0.08)'}`,
                 color: activeTab === tab.id ? '#FFB050' : 'rgba(255,255,255,0.4)',
                 fontSize: 14, fontWeight: 700, cursor: 'pointer', transition: 'all 0.2s ease'
               }}
             >
               <tab.icon size={16} />
               {tab.label}
             </button>
           ))}
        </div>

        {/* Content Area */}
        <div className="glass-card-orange" style={{ padding: 40, borderRadius: 24 }}>
          
          {/* ── Guidelines ── */}
          {activeTab === 'guidelines' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ marginBottom: 12 }}>
                <h3 style={{ fontSize: 20, color: 'white', fontWeight: 700, margin: '0 0 8px' }}>Contextual Guardrails</h3>
                <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.4)' }}>Showing {relevantGuidelines.length} rules relevant to your current codebase architecture.</p>
              </div>
              {relevantGuidelines.map(rule => (
                <div key={rule.id} style={{ 
                  background: 'rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.05)', 
                  borderRadius: 16, overflow: 'hidden' 
                }}>
                  <div 
                    onClick={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)}
                    style={{ padding: '20px 24px', display: 'flex', alignItems: 'center', cursor: 'pointer' }}
                  >
                    <div style={{ width: 100, fontSize: 12, fontWeight: 800, color: '#FF9800', fontFamily: 'monospace' }}>{rule.id}</div>
                    <div style={{ flex: 1, fontSize: 16, fontWeight: 600, color: 'white' }}>{rule.title}</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                       <span style={{ fontSize: 11, background: 'rgba(255,255,255,0.05)', paddingLeft: 8, paddingRight: 8, paddingTop: 2, paddingBottom: 2, borderRadius: 4, color: 'rgba(255,255,255,0.4)' }}>{rule.lang}</span>
                       {expandedRule === rule.id ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                    </div>
                  </div>
                  {expandedRule === rule.id && (
                    <div style={{ padding: '0 24px 24px', fontSize: 15, color: 'rgba(255,255,255,0.6)', lineHeight: 1.6 }}>
                      {rule.desc}
                      <div style={{ marginTop: 20, padding: 16, background: 'rgba(232,93,4,0.05)', borderRadius: 12, border: '1px solid rgba(232,93,4,0.1)', color: '#FFB050', fontSize: 13 }}>
                        <strong style={{ display: 'block', marginBottom: 4 }}>Mitigation Advisor:</strong>
                        Apply strict input validation and boundary checks at the trust boundary of the function.
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ── Patch History ── */}
          {activeTab === 'history' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              {patchHistory.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '60px 0', color: 'rgba(255,255,255,0.2)' }}>
                  <Shield size={48} style={{ opacity: 0.1, marginBottom: 16 }} />
                  <p>No patches recorded in this session. Apply a fix in the terminal to see history.</p>
                </div>
              ) : (
                patchHistory.map((patch, idx) => (
                  <div key={patch.id} style={{ display: 'flex', gap: 24 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                       <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#E85D04', boxShadow: '0 0 10px #E85D04' }} />
                       {idx !== patchHistory.length - 1 && <div style={{ width: 2, flex: 1, background: 'linear-gradient(to bottom, #E85D04, transparent)', marginTop: 8 }} />}
                    </div>
                    <div style={{ flex: 1, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 16, padding: 20 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
                        <div style={{ fontSize: 14, fontWeight: 700, color: 'white' }}>{patch.rule_name}</div>
                        <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace' }}>{patch.timestamp}</div>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
                         <div>
                            <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', textTransform: 'uppercase', marginBottom: 4 }}>Vulnerability ID</div>
                            <div style={{ fontSize: 13, color: '#FFB050', fontWeight: 600 }}>{patch.vuln_id}</div>
                         </div>
                         <div>
                            <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', textTransform: 'uppercase', marginBottom: 4 }}>File Origin</div>
                            <div style={{ fontSize: 13, color: 'white', opacity: 0.8 }}>{patch.file_path.split('/').pop()}</div>
                         </div>
                      </div>
                      <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.05)', fontSize: 13, color: 'rgba(255,255,255,0.5)' }}>
                         <strong>Strategy:</strong> {patch.strategy}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {/* ── Mitigation Techniques ── */}
          {activeTab === 'techniques' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 20 }}>
               {findings.length > 0 ? (
                 findings.map(f => {
                   const cweKey = f.cwe.toLowerCase();
                   const tech = MITIGATION_MAP[cweKey] || { 
                     name: 'Standard Mitigation Strategy', 
                     pattern: `Apply best practices for ${f.rule_name}. Implement boundary checks and input sanitization at the function entry point.` 
                   };
                   return (
                    <div key={f.vuln_id} style={{ 
                      background: 'rgba(232,93,4,0.04)', border: '1px solid rgba(232,93,4,0.15)', 
                      borderRadius: 16, padding: 24, boxShadow: '0 10px 30px rgba(0,0,0,0.2)',
                      display: 'flex', flexDirection: 'column'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                        <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(232,93,4,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                           <Wrench size={20} style={{ color: '#E85D04' }} />
                        </div>
                        <div style={{ fontSize: 10, fontWeight: 800, color: '#E85D04', borderRadius: 4, paddingLeft: 6, paddingRight: 6, paddingTop: 2, paddingBottom: 2, background: 'rgba(232,93,4,0.1)' }}>{f.cwe}</div>
                      </div>
                      <div style={{ fontSize: 16, fontWeight: 700, color: 'white', marginBottom: 8 }}>{tech.name}</div>
                      <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.6)', lineHeight: 1.6, marginBottom: 20, flex: 1 }}>{tech.pattern}</div>
                      <div style={{ borderTop: '1px solid rgba(232,93,4,0.1)', paddingTop: 12, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                         <div style={{ fontSize: 11, color: '#E85D04', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Target: {f.vuln_id}</div>
                         <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.3)', fontWeight: 600 }}>PRIORITY: HIGH</div>
                      </div>
                    </div>
                   );
                 })
               ) : (
                <div style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '60px 0', color: 'rgba(255,255,255,0.2)' }}>
                  <Wrench size={48} style={{ opacity: 0.1, marginBottom: 16 }} />
                  <p>Techniques will be generated automatically after codebase analysis.</p>
                </div>
               )}
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
