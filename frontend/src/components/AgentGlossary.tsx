import { AGENTS } from './AgentSidebar';
import { AGENT_ICONS } from './AgentIcons';
import { hexToRgb } from './AgentSidebar';

// Full-page Agent Glossary — Yellow & Black accents
export function AgentGlossary({ onClose: _onClose }: { onClose: () => void }) {
  return (
    <div style={{
      minHeight: '100vh',
      background: 'radial-gradient(ellipse at top, rgba(240,192,93,0.12), transparent 55%), #030101',
      paddingTop: 100, paddingBottom: 80,
      paddingLeft: 'clamp(24px, 5vw, 80px)',
      paddingRight: 'clamp(24px, 5vw, 80px)',
    }}>
      <div style={{ maxWidth: 1100, margin: '0 auto' }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.28em', textTransform: 'uppercase', color: '#F0C05D', marginBottom: 16 }}>
            Agent Intelligence
          </div>
          <h1 style={{ fontSize: 'clamp(36px, 5vw, 64px)', fontWeight: 900, margin: '0 0 20px', letterSpacing: '-0.03em', color: 'white' }}>
            The VAIS Swarm
          </h1>
          <p style={{ fontSize: 16, color: 'rgba(255,255,255,0.45)', maxWidth: 620, margin: '0 auto', lineHeight: 1.75 }}>
            Each agent is named after a critically endangered Japanese species — animals with
            precise ecological roles, irreplaceable in their habitat, designed to do{' '}
            <span style={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>one thing with absolute precision.</span>{' '}
            VAIS agents share this philosophy.
          </p>
        </div>

        {/* Glassmorphism Agent Cards Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 24 }}>
          {AGENTS.map((agent) => {
            const Icon = AGENT_ICONS[agent.name];
            const rgb = hexToRgb(agent.color);
            return (
              <div
                key={agent.name}
                style={{
                  background: `rgba(8,6,1,0.85)`,
                  border: `1px solid rgba(${rgb}, 0.3)`,
                  borderRadius: 20,
                  padding: 0,
                  overflow: 'hidden',
                  backdropFilter: 'blur(24px)',
                  WebkitBackdropFilter: 'blur(24px)',
                  boxShadow: `inset 0 2px 0 rgba(${rgb}, 0.4), 0 20px 40px rgba(0,0,0,0.5)`,
                  transition: 'transform 300ms ease, box-shadow 300ms ease',
                }}
                onMouseEnter={e => {
                  (e.currentTarget as HTMLDivElement).style.transform = 'translateY(-6px)';
                  (e.currentTarget as HTMLDivElement).style.boxShadow = `inset 0 2px 0 rgba(${rgb}, 0.7), 0 30px 60px rgba(0,0,0,0.6), 0 0 40px rgba(${rgb}, 0.08)`;
                }}
                onMouseLeave={e => {
                  (e.currentTarget as HTMLDivElement).style.transform = 'translateY(0)';
                  (e.currentTarget as HTMLDivElement).style.boxShadow = `inset 0 2px 0 rgba(${rgb}, 0.4), 0 20px 40px rgba(0,0,0,0.5)`;
                }}
              >
                {/* Card top accent bar */}
                <div style={{ height: 3, background: `linear-gradient(90deg, rgba(${rgb},0) 0%, rgba(${rgb},1) 40%, rgba(${rgb},0.3) 100%)` }} />

                <div style={{ padding: '28px 28px 24px' }}>
                  {/* Icon + name row */}
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16, marginBottom: 20 }}>
                    <div style={{
                      width: 64, height: 64, borderRadius: 16, flexShrink: 0,
                      background: `rgba(${rgb}, 0.15)`,
                      border: `1px solid rgba(${rgb}, 0.35)`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      boxShadow: `0 8px 24px rgba(${rgb}, 0.2)`,
                    }}>
                      <Icon size={36} color={agent.color} />
                    </div>
                    <div style={{ flex: 1, paddingTop: 4 }}>
                      <h3 style={{ fontSize: 22, fontWeight: 800, color: 'white', margin: '0 0 4px', letterSpacing: '-0.01em' }}>
                        {agent.name}
                      </h3>
                      <div style={{
                        display: 'inline-flex', alignItems: 'center', gap: 6,
                        fontSize: 10, fontWeight: 800, letterSpacing: '0.2em',
                        textTransform: 'uppercase', color: agent.color,
                        background: `rgba(${rgb}, 0.12)`,
                        border: `1px solid rgba(${rgb}, 0.3)`,
                        borderRadius: 999, padding: '3px 10px',
                      }}>
                        {agent.roleTag}
                      </div>
                    </div>
                  </div>

                  {/* Species / Conservation */}
                  <div style={{ fontSize: 12, fontStyle: 'italic', color: 'rgba(255,255,255,0.35)', marginBottom: 14, lineHeight: 1.5 }}>
                    {agent.species} — {agent.conservation}
                  </div>

                  {/* Description */}
                  <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.72)', lineHeight: 1.75, margin: '0 0 20px' }}>
                    {agent.description}
                  </p>

                  {/* Domain badge */}
                  <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <div style={{
                      fontSize: 11, fontWeight: 700,
                      background: `rgba(${rgb}, 0.12)`,
                      border: `1px solid rgba(${rgb}, 0.25)`,
                      borderRadius: 999, padding: '4px 14px',
                      color: agent.color,
                    }}>
                      {agent.domain}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Bottom note */}
        <div style={{ textAlign: 'center', marginTop: 64, padding: '32px', background: 'rgba(240,192,93,0.04)', border: '1px solid rgba(240,192,93,0.1)', borderRadius: 16 }}>
          <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.4)', margin: 0, lineHeight: 1.7 }}>
            The VAIS pipeline runs agents sequentially — Tanuki maps the terrain, Tsushima finds the weaknesses,
            Iriomote confirms exploitability, Raijū scores the risk, and Yamabiko proposes the fix.
            Each handoff preserves full context from the previous agent.
          </p>
        </div>
      </div>
    </div>
  );
}
