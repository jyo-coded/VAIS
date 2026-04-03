import React from 'react';

// Shared SVG wrapper
const SvgWrap = ({ size = 24, children }: { size?: number; children: React.ReactNode }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    {children}
  </svg>
);

// ── Tanuki (Japanese Raccoon Dog) ── Geometric raccoon face
export const TanukiIcon = ({ size = 24, color = '#E85D04' }: { size?: number; color?: string }) => (
  <SvgWrap size={size}>
    {/* Head oval */}
    <ellipse cx="12" cy="13" rx="7.5" ry="6.5" fill={color} fillOpacity="0.15" stroke={color} strokeWidth="1.2"/>
    {/* Left ear triangle */}
    <polygon points="5.5,8 3,3 8,6" fill={color} fillOpacity="0.9"/>
    {/* Right ear triangle */}
    <polygon points="18.5,8 21,3 16,6" fill={color} fillOpacity="0.9"/>
    {/* Face mask - dark band */}
    <ellipse cx="12" cy="13" rx="5" ry="3.5" fill={color} fillOpacity="0.25"/>
    {/* Left eye */}
    <circle cx="9.5" cy="11.5" r="1.4" fill={color}/>
    <circle cx="9.9" cy="11.2" r="0.5" fill="rgba(255,255,255,0.6)"/>
    {/* Right eye */}
    <circle cx="14.5" cy="11.5" r="1.4" fill={color}/>
    <circle cx="14.9" cy="11.2" r="0.5" fill="rgba(255,255,255,0.6)"/>
    {/* Snout */}
    <ellipse cx="12" cy="14.5" rx="2" ry="1.3" fill={color} fillOpacity="0.5"/>
    {/* Nose dot */}
    <circle cx="12" cy="14" r="0.6" fill={color}/>
    {/* Eye rings (mask detail) */}
    <ellipse cx="9.5" cy="11.5" rx="2.2" ry="2" fill="none" stroke={color} strokeWidth="0.8" strokeOpacity="0.5"/>
    <ellipse cx="14.5" cy="11.5" rx="2.2" ry="2" fill="none" stroke={color} strokeWidth="0.8" strokeOpacity="0.5"/>
  </SvgWrap>
);

// ── Tsushima (Leopard Cat) ── Minimalist single-stroke cat silhouette
export const TsushimaIcon = ({ size = 24, color = '#3B82F6' }: { size?: number; color?: string }) => (
  <SvgWrap size={size}>
    {/* Body silhouette */}
    <path d="M7 20 Q5 18 5 15 Q5 11 8 9 Q9 7.5 9.5 5 L10.5 5 Q10 7.5 12 8 Q14 7.5 13.5 5 L14.5 5 Q15 7.5 16 9 Q19 11 19 15 Q19 18 17 20 Z" 
      fill={color} fillOpacity="0.15" stroke={color} strokeWidth="1.2" strokeLinejoin="round"/>
    {/* Left pointed ear */}
    <path d="M9.5 5 L8.5 2 L11 4.5" fill={color} fillOpacity="0.9" stroke={color} strokeWidth="0.8" strokeLinejoin="round"/>
    {/* Right pointed ear */}
    <path d="M13.5 5 L15.5 2 L13 4.5" fill={color} fillOpacity="0.9" stroke={color} strokeWidth="0.8" strokeLinejoin="round"/>
    {/* Left eye */}
    <ellipse cx="9.8" cy="10.5" rx="1.2" ry="1.4" fill={color}/>
    <ellipse cx="10" cy="10.5" rx="0.4" ry="0.8" fill="rgba(0,0,0,0.6)"/>
    {/* Right eye */}
    <ellipse cx="14.2" cy="10.5" rx="1.2" ry="1.4" fill={color}/>
    <ellipse cx="14.4" cy="10.5" rx="0.4" ry="0.8" fill="rgba(0,0,0,0.6)"/>
    {/* Curved tail */}
    <path d="M16.5 18 Q21 15 20 10 Q19.5 8 18 9" stroke={color} strokeWidth="1.8" strokeLinecap="round" fill="none"/>
    {/* Whiskers left */}
    <line x1="5" y1="13" x2="9" y2="13.5" stroke={color} strokeWidth="0.8" strokeOpacity="0.7"/>
    <line x1="5" y1="14.5" x2="9" y2="14.5" stroke={color} strokeWidth="0.8" strokeOpacity="0.7"/>
    {/* Whiskers right */}
    <line x1="19" y1="13" x2="15" y2="13.5" stroke={color} strokeWidth="0.8" strokeOpacity="0.7"/>
    <line x1="19" y1="14.5" x2="15" y2="14.5" stroke={color} strokeWidth="0.8" strokeOpacity="0.7"/>
  </SvgWrap>
);

// ── Iriomote (Wildcat) ── Angular forward-facing cat face with whiskers
export const IriomoteIcon = ({ size = 24, color = '#10B981' }: { size?: number; color?: string }) => (
  <SvgWrap size={size}>
    {/* Head */}
    <path d="M12 4 L19 9 L19 17 L15 21 L9 21 L5 17 L5 9 Z" 
      fill={color} fillOpacity="0.12" stroke={color} strokeWidth="1.1" strokeLinejoin="round"/>
    {/* Left angular ear */}
    <path d="M7 9 L5 4 L10 7.5 Z" fill={color} fillOpacity="0.85"/>
    {/* Right angular ear */}
    <path d="M17 9 L19 4 L14 7.5 Z" fill={color} fillOpacity="0.85"/>
    {/* Left forward eye */}
    <circle cx="9.5" cy="12" r="2" fill={color} fillOpacity="0.3" stroke={color} strokeWidth="1.2"/>
    <circle cx="9.5" cy="12" r="0.9" fill={color}/>
    <circle cx="9.9" cy="11.5" r="0.35" fill="rgba(255,255,255,0.7)"/>
    {/* Right forward eye */}
    <circle cx="14.5" cy="12" r="2" fill={color} fillOpacity="0.3" stroke={color} strokeWidth="1.2"/>
    <circle cx="14.5" cy="12" r="0.9" fill={color}/>
    <circle cx="14.9" cy="11.5" r="0.35" fill="rgba(255,255,255,0.7)"/>
    {/* Nose */}
    <path d="M11 15 L12 13.5 L13 15 Z" fill={color}/>
    {/* Whisker lines */}
    <line x1="4" y1="14" x2="9" y2="14.5" stroke={color} strokeWidth="0.9" strokeOpacity="0.7"/>
    <line x1="4" y1="15.5" x2="9" y2="15.5" stroke={color} strokeWidth="0.9" strokeOpacity="0.7"/>
    <line x1="20" y1="14" x2="15" y2="14.5" stroke={color} strokeWidth="0.9" strokeOpacity="0.7"/>
    <line x1="20" y1="15.5" x2="15" y2="15.5" stroke={color} strokeWidth="0.9" strokeOpacity="0.7"/>
    {/* Mouth */}
    <path d="M10.5 15.5 Q12 17 13.5 15.5" stroke={color} strokeWidth="0.9" fill="none" strokeOpacity="0.8"/>
  </SvgWrap>
);

// ── Raijū (Lightning Wolf/Fox) ── Fox silhouette with integrated lightning bolt
export const RaijuIcon = ({ size = 24, color = '#8B5CF6' }: { size?: number; color?: string }) => (
  <SvgWrap size={size}>
    {/* Body */}
    <path d="M4 19 Q4 14 7 11 L7 7 L10 9 Q11 8 12 8 Q13 8 14 7.5 L16 10 Q18 12 18 16 Q18 19 16 20 L8 20 Z" 
      fill={color} fillOpacity="0.12" stroke={color} strokeWidth="1.1" strokeLinejoin="round"/>
    {/* Sharp pointed ear - left */}
    <path d="M7 7 L6 3 L10.5 6.5 Z" fill={color} fillOpacity="0.9"/>
    {/* Sharp pointed ear - right (fox style) */}
    <path d="M14 7.5 L15.5 3.5 L17.5 7 Z" fill={color} fillOpacity="0.9"/>
    {/* Left eye */}
    <circle cx="10" cy="12" r="1.2" fill={color}/>
    <circle cx="10.3" cy="11.7" r="0.4" fill="rgba(255,255,255,0.6)"/>
    {/* Right eye */}
    <circle cx="14" cy="12" r="1.2" fill={color}/>
    <circle cx="14.3" cy="11.7" r="0.4" fill="rgba(255,255,255,0.6)"/>
    {/* Lightning bolt integrated into body */}
    <path d="M13 9 L10.5 13.5 L12.5 13.5 L10 18 L15 12.5 L12.5 12.5 L14.5 9 Z" 
      fill={color} fillOpacity="0.9" stroke={color} strokeWidth="0.3"/>
    {/* Tail with lightning points */}
    <path d="M4 19 Q2 17 3 14 Q4 12 5 13" stroke={color} strokeWidth="1.8" strokeLinecap="round" fill="none"/>
    <path d="M3.5 13.5 L4.5 11.5 L3 11 L4.5 9" stroke={color} strokeWidth="1.2" strokeLinecap="round" fill="none"/>
  </SvgWrap>
);

// ── Yamabiko (Mountain Echo Spirit / Primate) ── Small primate with round eyes
export const YamabikoIcon = ({ size = 24, color = '#F59E0B' }: { size?: number; color?: string }) => (
  <SvgWrap size={size}>
    {/* Rounded head */}
    <circle cx="12" cy="10.5" r="6.5" fill={color} fillOpacity="0.12" stroke={color} strokeWidth="1.1"/>
    {/* Left round ear */}
    <circle cx="5.5" cy="10" r="2" fill={color} fillOpacity="0.5" stroke={color} strokeWidth="0.8"/>
    <circle cx="5.5" cy="10" r="0.9" fill={color} fillOpacity="0.3"/>
    {/* Right round ear */}
    <circle cx="18.5" cy="10" r="2" fill={color} fillOpacity="0.5" stroke={color} strokeWidth="0.8"/>
    <circle cx="18.5" cy="10" r="0.9" fill={color} fillOpacity="0.3"/>
    {/* Large round left eye — spirit look */}
    <circle cx="9.5" cy="9.5" r="2.2" fill={color} fillOpacity="0.25" stroke={color} strokeWidth="1.1"/>
    <circle cx="9.5" cy="9.5" r="1.2" fill={color}/>
    <circle cx="9.9" cy="9" r="0.5" fill="rgba(255,255,255,0.7)"/>
    {/* Large round right eye */}
    <circle cx="14.5" cy="9.5" r="2.2" fill={color} fillOpacity="0.25" stroke={color} strokeWidth="1.1"/>
    <circle cx="14.5" cy="9.5" r="1.2" fill={color}/>
    <circle cx="14.9" cy="9" r="0.5" fill="rgba(255,255,255,0.7)"/>
    {/* Snout patch */}
    <ellipse cx="12" cy="12.5" rx="2.5" ry="1.8" fill={color} fillOpacity="0.2" stroke={color} strokeWidth="0.7" strokeOpacity="0.5"/>
    {/* Simple smile */}
    <path d="M10.5 13 Q12 14.5 13.5 13" stroke={color} strokeWidth="1" fill="none" strokeLinecap="round"/>
    {/* Body suggestion */}
    <path d="M7 17 Q8 20 12 21 Q16 20 17 17 Q15 16 12 16.5 Q9 16 7 17 Z" 
      fill={color} fillOpacity="0.15" stroke={color} strokeWidth="0.8"/>
    {/* Small hands */}
    <circle cx="6.5" cy="18" r="1.2" fill={color} fillOpacity="0.4"/>
    <circle cx="17.5" cy="18" r="1.2" fill={color} fillOpacity="0.4"/>
  </SvgWrap>
);

// Lookup map
export const AGENT_ICONS: Record<string, React.FC<{size?: number; color?: string}>> = {
  Tanuki:   TanukiIcon,
  Tsushima: TsushimaIcon,
  Iriomote: IriomoteIcon,
  Raiju:    RaijuIcon,
  Yamabiko: YamabikoIcon,
};
