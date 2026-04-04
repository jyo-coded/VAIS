import type { Finding } from '../App';

export interface IntentResult {
  enrichedText: string;
  suggestedAgent: string;
}

export function routeIntent(text: string, findings: Finding[]): IntentResult {
  const lower = text.toLowerCase();
  let enrichedText = text;
  let suggestedAgent = 'VAIS';

  // 1. Line Number Detection
  const lineMatch = text.match(/line\s+(\d+)/i);
  if (lineMatch) {
    const lineNum = parseInt(lineMatch[1]);
    const finding = findings.find(f => f.line_start === lineNum);
    if (finding) {
      enrichedText = `User asked about line ${lineNum}. Relevant finding: ${JSON.stringify({
        vuln_id: finding.vuln_id,
        cwe: finding.cwe,
        severity: finding.severity,
        function: finding.function_name,
        description: finding.description,
        risk_score: finding.risk_score
      })}. Answer as VAIS. ${text}`;
    }
  }

  // 2. Agent Character Detection
  if (lower.includes('tanuki')) {
    enrichedText = `Respond AS Tanuki in character. The user is asking: ${text}`;
    suggestedAgent = 'Tanuki';
  } else if (lower.includes('tsushima')) {
    enrichedText = `Respond AS Tsushima in character. The user is asking: ${text}`;
    suggestedAgent = 'Tsushima';
  } else if (lower.includes('iriomote')) {
    enrichedText = `Respond AS Iriomote in character. The user is asking: ${text}`;
    suggestedAgent = 'Iriomote';
  } else if (lower.includes('raiju')) {
    enrichedText = `Respond AS Raijū in character. The user is asking: ${text}`;
    suggestedAgent = 'Raijū';
  } else if (lower.includes('yamabiko')) {
    enrichedText = `Respond AS Yamabiko in character. The user is asking: ${text}`;
    suggestedAgent = 'Yamabiko';
  }

  // 3. Patch/Fix Intent
  if (lower.includes('fix') || lower.includes('patch') || lower.includes('remediate') || lower.includes('how do i')) {
    if (suggestedAgent === 'VAIS') {
      enrichedText = `Respond as Yamabiko the patch agent. Propose a concrete fix. The user asked: ${text}`;
      suggestedAgent = 'Yamabiko';
    }
  }

  // 4. ML/Scoring Intent
  if (lower.includes('ml') || lower.includes('score') || lower.includes('model') || lower.includes('codebert')) {
    if (suggestedAgent === 'VAIS') {
      enrichedText = `Respond as Raijū the ML agent. Use the current ML metrics from the scan. Answer: ${text}`;
      suggestedAgent = 'Raijū';
    }
  }

  // 5. Prioritization Intent
  if (lower.includes('worst') || lower.includes('most dangerous') || lower.includes('critical') || lower.includes('first')) {
    enrichedText = `Sort the current findings by risk_score descending and taint_confirmed first. Answer: ${text}`;
  }

  return { enrichedText, suggestedAgent };
}
