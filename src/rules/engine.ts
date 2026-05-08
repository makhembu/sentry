import { getDb } from '../db/init.js';
import { getActiveRules } from './loader.js';
import { DetectionRule, Finding, RuleField, MatchResult } from '../types.js';

const IRIS_URL = process.env.IRIS_API_URL || process.env.IRIS_URL || 'http://localhost:3000';

interface IocRecord {
  id: string;
  value: string;
  type: string;
  source: string;
  confidence: number;
  severity: string;
  category: string;
  description: string;
  tags: string;
  first_seen: string;
  last_seen: string;
}

async function fetchIocsFromIris(): Promise<IocRecord[]> {
  try {
    const res = await fetch(`${IRIS_URL}/iocs?limit=5000`);
    if (!res.ok) throw new Error(`iris returned ${res.status}`);
    const body = await res.json() as { iocs: IocRecord[] };
    return body.iocs || [];
  } catch (err) {
    console.error(`[sentry] Failed to fetch IOCs from iris: ${err}`);
    return [];
  }
}

function matchField(ioc: IocRecord, field: RuleField): boolean {
  const val = String(ioc[field.field as keyof IocRecord] ?? '');

  switch (field.operator) {
    case 'equals':
      return val.toLowerCase() === String(field.value).toLowerCase();
    case 'contains':
      return val.toLowerCase().includes(String(field.value).toLowerCase());
    case 'startsWith':
      return val.toLowerCase().startsWith(String(field.value).toLowerCase());
    case 'endsWith':
      return val.toLowerCase().endsWith(String(field.value).toLowerCase());
    case 'matches': {
      try {
        return new RegExp(String(field.value), 'i').test(val);
      } catch {
        return false;
      }
    }
    case 'gt':
      return Number(val) > Number(field.value);
    case 'lt':
      return Number(val) < Number(field.value);
    case 'in': {
      const raw = Array.isArray(field.value) ? field.value : [field.value];
      const values = raw.map(v => String(v));
      const lowerVal = val.toLowerCase();
      return values.some(v => lowerVal === v.toLowerCase() || lowerVal.includes(v.toLowerCase()));
    }
    default:
      return false;
  }
}

function matchRule(rule: DetectionRule, iocs: IocRecord[]): MatchResult {
  const matchedIocs: { ioc: string; field: string; reason: string }[] = [];
  const candidates = iocs.filter(ioc => rule.iocTypes.length === 0 || rule.iocTypes.includes(ioc.type as any));

  for (const ioc of candidates) {
    const { all, any } = rule.condition;

    if (all) {
      const allMatch = all.every(f => matchField(ioc, f));
      if (allMatch) {
        const reasons = all.map(f => `${f.field} ${f.operator} ${Array.isArray(f.value) ? f.value.join('|') : f.value}`);
        matchedIocs.push({ ioc: ioc.value, field: all[0].field, reason: reasons.join('; ') });
      }
    }

    if (any) {
      const matched = any.find(f => matchField(ioc, f));
      if (matched) {
        const reason = `${matched.field} ${matched.operator} ${Array.isArray(matched.value) ? matched.value.join('|') : matched.value}`;
        if (!matchedIocs.some(m => m.ioc === ioc.value)) {
          matchedIocs.push({ ioc: ioc.value, field: matched.field, reason });
        }
      }
    }
  }

  return { rule, matchedIocs, totalCandidates: candidates.length };
}

export async function runMatching(): Promise<{ findings: number; rulesMatched: number; iocsScanned: number; durationMs: number }> {
  const start = Date.now();
  const db = getDb();
  const rules = getActiveRules();
  const iocs = await fetchIocsFromIris();
  const allMatchResults: MatchResult[] = [];
  const findings: Finding[] = [];
  const now = new Date().toISOString();

  for (const rule of rules) {
    const result = matchRule(rule, iocs);
    if (result.matchedIocs.length > 0) {
      allMatchResults.push(result);
    }
  }

  const insertFinding = db.prepare(`
    INSERT OR IGNORE INTO findings (id, rule_id, rule_name, rule_severity, ioc_id, ioc_value, ioc_type, ioc_source, match_field, match_reason, confidence_at_match, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertTx = db.transaction(() => {
    for (const result of allMatchResults) {
      for (const matched of result.matchedIocs) {
        const ioc = iocs.find(i => i.value === matched.ioc);
        if (!ioc) continue;

        const findingId = `find_${result.rule.id.slice(0, 12)}_${Date.now().toString(36)}_${findings.length}`;
        insertFinding.run(
          findingId,
          result.rule.id,
          result.rule.name,
          result.rule.severity,
          ioc.id,
          ioc.value,
          ioc.type,
          ioc.source,
          matched.field,
          matched.reason,
          ioc.confidence,
          now,
        );

        findings.push({
          id: findingId,
          rule_id: result.rule.id,
          rule_name: result.rule.name,
          rule_severity: result.rule.severity,
          ioc_id: ioc.id,
          ioc_value: ioc.value,
          ioc_type: ioc.type as any,
          ioc_source: ioc.source,
          match_field: matched.field,
          match_reason: matched.reason,
          confidence_at_match: ioc.confidence,
          created_at: now,
          acknowledged: 0,
        });
      }
    }

    db.prepare(
      'INSERT INTO match_history (rules_matched, findings_generated, iocs_scanned, duration_ms) VALUES (?, ?, ?, ?)'
    ).run(allMatchResults.length, findings.length, iocs.length, Date.now() - start);
  });

  insertTx();
  db.close();

  const durationMs = Date.now() - start;
  console.log(`[sentry] Match run complete: ${allMatchResults.length} rules matched, ${findings.length} findings, ${iocs.length} IOCs scanned in ${durationMs}ms`);

  return { findings: findings.length, rulesMatched: allMatchResults.length, iocsScanned: iocs.length, durationMs };
}

if (process.argv[1]?.endsWith('engine.ts') || process.argv[1]?.endsWith('engine.js')) {
  runMatching();
}
