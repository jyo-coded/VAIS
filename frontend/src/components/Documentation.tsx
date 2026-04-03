import React, { useState } from 'react';
import { BookOpen, Shield, Wrench, ChevronDown, ChevronRight } from 'lucide-react';

const SECURE_CODING_RULES = [
  { id: 'MEM00-C', category: 'Memory', title: 'Always free dynamically allocated resources', desc: 'Every call to malloc, calloc, or realloc must have a corresponding call to free. Failure to do so causes memory leaks that can be exploited to exhaust resources.', lang: 'C / C++' },
  { id: 'MEM30-C', category: 'Memory', title: 'Do not access freed memory', desc: 'After a block of memory has been freed, do not access it again. This is a use-after-free (UAF) vulnerability and is one of the most commonly exploited memory safety issues.', lang: 'C / C++' },
  { id: 'STR31-C', category: 'Strings', title: 'Guarantee that storage for strings has sufficient space', desc: 'Buffer overflows occur when data (often strings) is written beyond the end of an allocated buffer. Use bounded functions like strncpy or strlcpy instead of strcpy.', lang: 'C / C++' },
  { id: 'ARR38-C', category: 'Arrays', title: 'Guarantee that library functions do not form invalid pointers', desc: 'Library functions that accept pointer + length arguments must be called with consistent values. Passing incorrect lengths results in out-of-bounds reads or writes.', lang: 'C / C++' },
  { id: 'ERR00-CPP', category: 'Errors', title: 'Adopt and implement a consistent and comprehensive error-handling policy', desc: 'All error conditions must be handled. Unchecked return values from security-critical functions (open, read, write, exec) are a common source of vulnerabilities.', lang: 'C++' },
  { id: 'IDS00-J', category: 'Injection', title: 'Prevent SQL injection using parameterized queries', desc: 'Never concatenate user input into SQL query strings. Use PreparedStatement with parameterized queries exclusively in Java applications.', lang: 'Java' },
  { id: 'MSC61-J', category: 'Crypto', title: 'Do not use insecure or weak cryptographic algorithms', desc: 'MD5, SHA-1, DES, and RC4 are considered broken. Use SHA-256/384/512, AES-256-GCM, and RSA-2048 or higher for all cryptographic operations.', lang: 'Java / Python' },
  { id: 'ENV33-C', category: 'System', title: 'Do not call system()', desc: 'The system() function passes a command string to the OS shell, making it susceptible to command injection. Use exec() family functions with explicit argument arrays instead.', lang: 'C / C++' },
  { id: 'PY-001', category: 'Python', title: 'Never use eval() on untrusted input', desc: 'The eval() function executes arbitrary Python code. Any user-controlled input passed to eval() results in remote code execution. Use ast.literal_eval() or explicit parsing.', lang: 'Python' },
  { id: 'GO-001', category: 'Go', title: 'Always check errors from goroutines and channels', desc: 'Ignoring error values in Go means failures pass silently. All error returns must be checked, logged, and handled appropriately to prevent undefined behavior.', lang: 'Go' },
];

const MITIGATION_TECHNIQUES = [
  { name: 'Safe String Wrapper', pattern: 'Replace strcpy/strcat with bounded equivalents', rules: ['STR31-C', 'MEM30-C'] },
  { name: 'Null Pointer Guard', pattern: 'Insert NULL check before pointer dereference', rules: ['EXP34-C'] },
  { name: 'Bounds Check Insertion', pattern: 'Add array access bounds validation', rules: ['ARR38-C'] },
  { name: 'Format String Fix', pattern: 'Replace printf(user_input) with printf("%s", user_input)', rules: ['FIO30-C'] },
  { name: 'Parameterized Query', pattern: 'Replace string-concatenated SQL with PreparedStatement', rules: ['IDS00-J'] },
  { name: 'Memory Free Guard', pattern: 'Wrap free() to null pointer after freeing', rules: ['MEM00-C', 'MEM30-C'] },
  { name: 'Integer Overflow Check', pattern: 'Add explicit overflow check before arithmetic', rules: ['INT30-C'] },  
  { name: 'Subprocess Array Args', pattern: 'Replace system(cmd) with execv(path, argv)', rules: ['ENV33-C'] },
];

export function Documentation() {
  const [section, setSection] = useState<'coding' | 'patches' | 'mitigation'>('coding');
  const [expandedRule, setExpandedRule] = useState<string | null>(null);

  const SECTIONS = [
    { id: 'coding' as const, label: 'Secure Coding Guidelines', icon: BookOpen },
    { id: 'patches' as const, label: 'Patch History', icon: Shield },
    { id: 'mitigation' as const, label: 'Mitigation Techniques', icon: Wrench },
  ];

  return (
    <div style={{ minHeight: '100vh', paddingTop: 100, paddingBottom: 80, paddingLeft: 40, paddingRight: 40, background: '#030101' }}>
      <div style={{ maxWidth: 960, margin: '0 auto' }}>
        <div style={{ marginBottom: 48 }}>
          <p className="section-kicker" style={{ color: '#E85D04' }}>Knowledge Base</p>
          <h2 style={{ fontSize: 'clamp(28px, 4vw, 48px)', fontWeight: 800, margin: '0 0 12px', letterSpacing: '-0.02em' }}>Documentation</h2>
          <p style={{ fontSize: 15, color: 'rgba(255,255,255,0.4)', margin: 0 }}>
            Secure coding standards, applied patch history, and mitigation reference library.
          </p>
        </div>

        {/* Industry standards compliance banner */}
        <div style={{ background: 'linear-gradient(135deg, rgba(232,93,4,0.08), rgba(240,192,93,0.05), rgba(26,200,80,0.08))', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 14, padding: '20px 24px', marginBottom: 36, display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 20 }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'white', marginBottom: 4 }}>Industry Standard Coverage</div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.45)' }}>VAIS rules map to globally recognized security standards</div>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginLeft: 'auto' }}>
            {['CERT-C', 'CERT-C++', 'CWE Top 25', 'OWASP Top 10', 'CVSS 3.1', 'MISRA-C', 'NIST 800-53'].map(s => (
              <div key={s} style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 999, padding: '4px 12px', fontSize: 11, fontWeight: 700, color: 'rgba(255,255,255,0.6)' }}>{s}</div>
            ))}
          </div>
        </div>

        {/* Section tabs */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 28, borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: 0 }}>
          {SECTIONS.map(s => {
            const Icon = s.icon;
            return (
              <button
                key={s.id}
                onClick={() => setSection(s.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '12px 18px', borderRadius: '10px 10px 0 0',
                  background: section === s.id ? 'rgba(232,93,4,0.1)' : 'transparent',
                  border: section === s.id ? '1px solid rgba(232,93,4,0.3)' : '1px solid transparent',
                  borderBottom: section === s.id ? '1px solid rgba(1,8,3,0.4)' : '1px solid transparent',
                  color: section === s.id ? '#E85D04' : 'rgba(255,255,255,0.45)',
                  fontSize: 13, fontWeight: 600, cursor: 'pointer', fontFamily: 'Inter, sans-serif',
                  marginBottom: -1,
                }}
              >
                <Icon size={14} />
                {s.label}
              </button>
            );
          })}
        </div>

        {/* ── SECURE CODING GUIDELINES ── */}
        {section === 'coding' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {SECURE_CODING_RULES.map(rule => (
              <div key={rule.id} style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, overflow: 'hidden' }}>
                <div
                  onClick={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)}
                  style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '16px 20px', cursor: 'pointer' }}
                >
                  <div style={{ width: 80, flexShrink: 0, fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 700, color: '#E85D04' }}>{rule.id}</div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'rgba(255,255,255,0.9)' }}>{rule.title}</div>
                  </div>
                  <div style={{ flexShrink: 0, fontSize: 11, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 999, padding: '3px 10px', color: 'rgba(255,255,255,0.4)', whiteSpace: 'nowrap' }}>{rule.lang}</div>
                  {expandedRule === rule.id ? <ChevronDown size={14} style={{ color: 'rgba(255,255,255,0.4)', flexShrink: 0 }} /> : <ChevronRight size={14} style={{ color: 'rgba(255,255,255,0.4)', flexShrink: 0 }} />}
                </div>
                {expandedRule === rule.id && (
                  <div style={{ padding: '0 20px 20px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                    <div style={{ padding: '16px 0', fontSize: 14, color: 'rgba(255,255,255,0.65)', lineHeight: 1.7 }}>{rule.desc}</div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ── PATCH HISTORY ── */}
        {section === 'patches' && (
          <div style={{ textAlign: 'center', padding: '80px 0', color: 'rgba(255,255,255,0.25)' }}>
            <Shield size={40} style={{ marginBottom: 16, opacity: 0.3 }} />
            <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>No patches applied yet</div>
            <div style={{ fontSize: 13 }}>Applied patches will appear here after Yamabiko authorizations</div>
          </div>
        )}

        {/* ── MITIGATION TECHNIQUES ── */}
        {section === 'mitigation' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(420px, 1fr))', gap: 16 }}>
            {MITIGATION_TECHNIQUES.map(m => (
              <div key={m.name} style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 12, padding: '18px 20px' }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'white', marginBottom: 6 }}>{m.name}</div>
                <div style={{ fontSize: 13, color: 'rgba(255,255,255,0.55)', marginBottom: 12, lineHeight: 1.6 }}>{m.pattern}</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {m.rules.map(r => (
                    <div key={r} style={{ background: 'rgba(232,93,4,0.1)', border: '1px solid rgba(232,93,4,0.2)', borderRadius: 999, padding: '2px 9px', fontSize: 11, fontWeight: 700, color: '#E85D04', fontFamily: "'JetBrains Mono', monospace" }}>{r}</div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
