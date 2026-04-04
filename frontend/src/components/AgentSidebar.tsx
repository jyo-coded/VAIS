import { AGENT_ICONS } from './AgentIcons';

export const AGENTS = [
  {
    name: 'Tanuki',
    species: 'Japanese raccoon dog',
    conservation: 'Common but culturally iconic',
    color: '#E85D04',
    roleTag: 'RECON',
    domain: 'All Languages',
    description: 'Surveys the codebase topology, maps all functions, identifies entry points and external input vectors before any analysis begins.',
  },
  {
    name: 'Tsushima',
    species: 'Tsushima leopard cat',
    conservation: 'Fewer than 100 surviving',
    color: '#3B82F6',
    roleTag: 'MEMORY SAFETY',
    domain: 'C / C++',
    description: 'Detects buffer overflows, use-after-free, double-free, stack corruption, and memory leak patterns across C, C++, and all memory-unsafe languages.',
  },
  {
    name: 'Iriomote',
    species: 'Iriomote wildcat',
    conservation: 'Critically endangered, ~100 individuals',
    color: '#10B981',
    roleTag: 'TAINT FLOW',
    domain: 'All Languages',
    description: 'Traces the path of untrusted external data from source functions like argv and stdin through the call graph to dangerous sink functions. Confirms exploitability.',
  },
  {
    name: 'Raiju',
    species: 'Mythical Japanese lightning beast',
    conservation: 'Folklore — embodiment of lightning',
    color: '#8B5CF6',
    roleTag: 'ML RISK SCORING',
    domain: 'All Languages',
    description: 'Runs CodeBERT, GNN, and XGBoost ensemble models to assign a risk probability to every finding. Surfaces the highest-impact vulnerabilities first.',
  },
  {
    name: 'Yamabiko',
    species: 'Mountain echo spirit (folklore)',
    conservation: 'Japanese mountain folklore entity',
    color: '#F59E0B',
    roleTag: 'PATCH STRATEGY',
    domain: 'C / C++ / All',
    description: 'Synthesises remediation patches for confirmed vulnerabilities. Presents the diff for review and waits for explicit approval before modifying any source file.',
  },
];

interface AgentSidebarProps {
  activeAgent: string | null;
}

export function AgentSidebar({ activeAgent }: AgentSidebarProps) {
  return (
    <div style={{ width: 240, flexShrink: 0 }}>
      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.18em', color: 'rgba(255,255,255,0.3)', textTransform: 'uppercase', marginBottom: 12, paddingLeft: 4 }}>
        Agents
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {AGENTS.map((agent) => {
          const Icon = AGENT_ICONS[agent.name];
          const isActive = activeAgent === agent.name;
          return (
            <div
              key={agent.name}
              className={`agent-sidebar-card${isActive ? ' active' : ''}`}
              style={{
                minHeight: 90,
                background: isActive ? `rgba(${hexToRgb(agent.color)}, 0.18)` : `rgba(${hexToRgb(agent.color)}, 0.08)`,
                border: `1px solid rgba(${hexToRgb(agent.color)}, ${isActive ? 0.55 : 0.25})`,
                boxShadow: isActive ? `0 0 12px rgba(${hexToRgb(agent.color)}, 0.2)` : 'none',
                ...(isActive ? { color: agent.color } : {}),
              }}
            >
              {isActive && (
                <div
                  className="agent-active-badge"
                  style={{ background: `rgba(${hexToRgb(agent.color)}, 0.2)`, color: agent.color, border: `1px solid rgba(${hexToRgb(agent.color)}, 0.4)` }}
                >
                  ACTIVE
                </div>
              )}

              {/* SVG Icon Box — bigger */}
              <div style={{
                width: 48, height: 48, borderRadius: 12, flexShrink: 0,
                background: `rgba(${hexToRgb(agent.color)}, 0.2)`,
                border: `1px solid rgba(${hexToRgb(agent.color)}, 0.3)`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Icon size={28} color={agent.color} />
              </div>

              {/* Text */}
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ fontSize: 15, fontWeight: 700, color: 'white', lineHeight: 1.2 }}>{agent.name}</div>
                <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: '0.15em', textTransform: 'uppercase', color: agent.color, marginTop: 3 }}>
                  {agent.roleTag}
                </div>
                <div className="agent-desc" style={{ marginTop: 5, fontSize: 11 }}>{agent.description}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Helper: convert hex to "r, g, b" string for rgba()
export function hexToRgb(hex: string): string {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  if (!result) return '255,255,255';
  return `${parseInt(result[1], 16)}, ${parseInt(result[2], 16)}, ${parseInt(result[3], 16)}`;
}
