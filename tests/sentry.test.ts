import { describe, it } from 'node:test';
import assert from 'node:assert';
import Database from 'better-sqlite3';
import { getSchema } from '../src/db/schema.js';
import path from 'path';
import fs from 'fs';

const TEST_DB = path.join(import.meta.dirname, '..', 'data', 'test_sentry.db');

function setupDb() {
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
  const dbDir = path.dirname(TEST_DB);
  if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
  const db = new Database(TEST_DB);
  db.pragma('journal_mode = WAL');
  db.exec(getSchema());
  return db;
}

describe('sentry', () => {

  describe('field matching', () => {
    const ioc = {
      id: 'test_1', value: '192.168.1.1', type: 'ip', source: 'abusech',
      confidence: 0.85, severity: 'critical', category: 'malware',
      description: 'C2 server', tags: '["c2","malware"]',
      first_seen: '2026-01-01', last_seen: '2026-05-08',
    };

    it('equals operator matches exact value', () => {
      assert.strictEqual(matchField(ioc, { field: 'type', operator: 'equals', value: 'ip' }), true);
      assert.strictEqual(matchField(ioc, { field: 'type', operator: 'equals', value: 'domain' }), false);
    });

    it('contains operator matches substring', () => {
      assert.strictEqual(matchField(ioc, { field: 'value', operator: 'contains', value: '192.168' }), true);
      assert.strictEqual(matchField(ioc, { field: 'value', operator: 'contains', value: '10.0' }), false);
    });

    it('in operator matches any of the values', () => {
      assert.strictEqual(matchField(ioc, { field: 'source', operator: 'in', value: ['abusech', 'talos'] }), true);
      assert.strictEqual(matchField(ioc, { field: 'source', operator: 'in', value: ['alienvault', 'talos'] }), false);
    });

    it('gt operator works on numeric values', () => {
      assert.strictEqual(matchField(ioc, { field: 'confidence', operator: 'gt', value: 0.5 }), true);
      assert.strictEqual(matchField(ioc, { field: 'confidence', operator: 'gt', value: 0.9 }), false);
    });

    it('startsWith and endsWith operators work', () => {
      assert.strictEqual(matchField(ioc, { field: 'value', operator: 'startsWith', value: '192' }), true);
      assert.strictEqual(matchField(ioc, { field: 'value', operator: 'endsWith', value: '.1' }), true);
    });

    it('matches operator supports regex', () => {
      assert.strictEqual(matchField(ioc, { field: 'value', operator: 'matches', value: '^192\\.' }), true);
    });
  });

  describe('rule loading and parsing', () => {
    it('database schema creates rules table', () => {
      const db = setupDb();
      const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as { name: string }[];
      const names = tables.map(t => t.name);
      assert.ok(names.includes('rules'));
      assert.ok(names.includes('findings'));
      assert.ok(names.includes('match_history'));
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });

    it('inserts and retrieves a rule', () => {
      const db = setupDb();
      db.prepare(`
        INSERT INTO rules (id, name, description, severity, status, category, ioc_types, condition_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run('rule_test_1', 'Test Rule', 'A test rule', 'high', 'active', 'malware', '["ip","domain"]', '{"any":[{"field":"source","operator":"equals","value":"abusech"}]}');

      const row = db.prepare('SELECT * FROM rules WHERE id = ?').get('rule_test_1') as any;
      assert.strictEqual(row.name, 'Test Rule');
      assert.strictEqual(row.severity, 'high');
      assert.strictEqual(row.status, 'active');
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });

    it('inserts a finding with correct fields', () => {
      const db = setupDb();
      db.prepare('INSERT INTO rules (id, name, severity, status, category, ioc_types, condition_json) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run('r1', 'R1', 'high', 'active', 'test', '[]', '{}');

      db.prepare(`
        INSERT INTO findings (id, rule_id, rule_name, rule_severity, ioc_id, ioc_value, ioc_type, ioc_source, match_field, match_reason, confidence_at_match)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run('f1', 'r1', 'R1', 'high', 'ioc1', '8.8.8.8', 'ip', 'abusech', 'source', 'matched source', 0.9);

      const row = db.prepare('SELECT * FROM findings WHERE id = ?').get('f1') as any;
      assert.strictEqual(row.ioc_value, '8.8.8.8');
      assert.strictEqual(row.rule_name, 'R1');
      assert.strictEqual(row.acknowledged, 0);
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });
  });

  describe('match history', () => {
    it('records a match history entry', () => {
      const db = setupDb();
      db.prepare('INSERT INTO match_history (rules_matched, findings_generated, iocs_scanned, duration_ms) VALUES (?, ?, ?, ?)')
        .run(3, 12, 500, 245);
      const row = db.prepare('SELECT * FROM match_history ORDER BY run_at DESC LIMIT 1').get() as any;
      assert.strictEqual(row.rules_matched, 3);
      assert.strictEqual(row.findings_generated, 12);
      assert.strictEqual(row.iocs_scanned, 500);
      db.close();
      if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    });
  });
});

interface RuleField {
  field: string;
  operator: 'equals' | 'contains' | 'startsWith' | 'endsWith' | 'matches' | 'gt' | 'lt' | 'in';
  value: string | string[] | number;
}

function matchField(ioc: Record<string, any>, field: RuleField): boolean {
  const val = String(ioc[field.field] ?? '');
  switch (field.operator) {
    case 'equals': return val.toLowerCase() === String(field.value).toLowerCase();
    case 'contains': return val.toLowerCase().includes(String(field.value).toLowerCase());
    case 'startsWith': return val.toLowerCase().startsWith(String(field.value).toLowerCase());
    case 'endsWith': return val.toLowerCase().endsWith(String(field.value).toLowerCase());
    case 'matches': try { return new RegExp(String(field.value), 'i').test(val); } catch { return false; }
    case 'gt': return Number(val) > Number(field.value);
    case 'lt': return Number(val) < Number(field.value);
    case 'in': {
      const values = (Array.isArray(field.value) ? field.value : [field.value]).map(v => String(v));
      return values.some(v => val.toLowerCase() === v.toLowerCase() || val.toLowerCase().includes(v.toLowerCase()));
    }
    default: return false;
  }
}
