import fs from 'fs';
import path from 'path';
import YAML from 'yaml';
import { getDb } from '../db/init.js';
import { DetectionRule, RuleCondition, IocType, RuleSeverity } from '../types.js';

const RULES_DIR = process.env.RULES_DIR || './rules';

function generateId(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  return `rule_${slug}_${Date.now().toString(36)}`;
}

function parseYamlRule(filePath: string): Partial<DetectionRule> | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const parsed = YAML.parse(content);
    if (!parsed || !parsed.name) {
      console.warn(`[sentry] Skipping ${filePath}: missing name`);
      return null;
    }
    return {
      name: parsed.name,
      description: parsed.description || '',
      severity: (parsed.severity || 'medium') as RuleSeverity,
      category: parsed.category || 'other',
      tactic: parsed.tactic,
      technique: parsed.technique,
      iocTypes: (parsed.ioc_types || []) as IocType[],
      condition: parsed.condition || {},
      source: parsed.source || 'yaml',
      references: parsed.references || [],
      tags: parsed.tags || [],
      falsePositives: parsed.false_positives || [],
    };
  } catch (err: any) {
    console.warn(`[sentry] Error parsing ${filePath}: ${err.message}`);
    return null;
  }
}

export function loadRulesFromDir(): DetectionRule[] {
  const db = getDb();
  const loaded: DetectionRule[] = [];
  const now = new Date().toISOString();

  if (!fs.existsSync(RULES_DIR)) {
    fs.mkdirSync(RULES_DIR, { recursive: true });
    console.log(`[sentry] Created rules directory: ${RULES_DIR}`);
    db.close();
    return loaded;
  }

  const files = fs.readdirSync(RULES_DIR).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));

  const upsert = db.prepare(`
    INSERT INTO rules (id, name, description, severity, status, category, tactic, technique, ioc_types, condition_json, source, references_json, tags, false_positives, created_at, updated_at)
    VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(name) DO UPDATE SET
      description = excluded.description,
      severity = excluded.severity,
      category = excluded.category,
      ioc_types = excluded.ioc_types,
      condition_json = excluded.condition_json,
      tags = excluded.tags,
      updated_at = excluded.updated_at
  `);

  const transaction = db.transaction(() => {
    for (const file of files) {
      const filePath = path.join(RULES_DIR, file);
      const parsed = parseYamlRule(filePath);
      if (!parsed) continue;

      const id = generateId(parsed.name!);
      upsert.run(
        id,
        parsed.name,
        parsed.description,
        parsed.severity,
        parsed.category,
        parsed.tactic || null,
        parsed.technique || null,
        JSON.stringify(parsed.iocTypes),
        JSON.stringify(parsed.condition),
        parsed.source || 'yaml',
        JSON.stringify(parsed.references || []),
        JSON.stringify(parsed.tags || []),
        JSON.stringify(parsed.falsePositives || []),
        now,
        now
      );

      loaded.push({
        id,
        name: parsed.name!,
        description: parsed.description || '',
        severity: parsed.severity || 'medium',
        status: 'active',
        category: parsed.category || 'other',
        tactic: parsed.tactic,
        technique: parsed.technique,
        iocTypes: parsed.iocTypes || [],
        condition: parsed.condition as RuleCondition,
        source: parsed.source || 'yaml',
        references: parsed.references || [],
        tags: parsed.tags || [],
        falsePositives: parsed.falsePositives || [],
        created_at: now,
        updated_at: now,
      });
    }
  });

  transaction();
  console.log(`[sentry] Loaded ${loaded.length} rules from ${RULES_DIR}`);
  db.close();
  return loaded;
}

export function getActiveRules(): DetectionRule[] {
  const db = getDb();
  const rows = db.prepare("SELECT * FROM rules WHERE status = 'active'").all() as any[];
  db.close();
  return rows.map(row => ({
    id: row.id,
    name: row.name,
    description: row.description,
    severity: row.severity,
    status: row.status,
    category: row.category,
    tactic: row.tactic,
    technique: row.technique,
    iocTypes: JSON.parse(row.ioc_types || '[]'),
    condition: JSON.parse(row.condition_json || '{}'),
    source: row.source,
    references: JSON.parse(row.references_json || '[]'),
    tags: JSON.parse(row.tags || '[]'),
    falsePositives: JSON.parse(row.false_positives || '[]'),
    created_at: row.created_at,
    updated_at: row.updated_at,
  }));
}

if (process.argv[1]?.endsWith('loader.ts') || process.argv[1]?.endsWith('loader.js')) {
  const rules = loadRulesFromDir();
  console.log(`[sentry] ${rules.length} rules loaded`);
  for (const r of rules) {
    console.log(`  ${r.severity.padEnd(12)} ${r.name}`);
  }
}
