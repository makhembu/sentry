import { Hono } from 'hono';
import { getDb } from '../db/init.js';
import { loadRulesFromDir, getActiveRules } from '../rules/loader.js';
import { runMatching } from '../rules/engine.js';
import { DetectionRule, Finding, DashboardSummary } from '../types.js';

export const api = new Hono();

api.get('/health', (c) => {
  const db = getDb();
  try {
    const rules = (db.prepare('SELECT COUNT(*) as c FROM rules').get() as { c: number }).c;
    const findings = (db.prepare('SELECT COUNT(*) as c FROM findings').get() as { c: number }).c;
    db.close();
    return c.json({ status: 'ok', rules, findings, uptime: process.uptime() });
  } catch (err) {
    db.close();
    return c.json({ status: 'error', error: String(err) }, 500);
  }
});

api.get('/rules', (c) => {
  const db = getDb();
  const status = c.req.query('status');
  let rows;
  if (status) {
    rows = db.prepare('SELECT * FROM rules WHERE status = ? ORDER BY severity DESC, name').all(status);
  } else {
    rows = db.prepare('SELECT * FROM rules ORDER BY severity DESC, name').all();
  }
  db.close();
  const rules = (rows as any[]).map(row => ({
    ...row,
    ioc_types: JSON.parse(row.ioc_types || '[]'),
    condition_json: JSON.parse(row.condition_json || '{}'),
    references_json: JSON.parse(row.references_json || '[]'),
    tags: JSON.parse(row.tags || '[]'),
    false_positives: JSON.parse(row.false_positives || '[]'),
  }));
  return c.json(rules);
});

api.get('/rules/:id', (c) => {
  const db = getDb();
  const row = db.prepare('SELECT * FROM rules WHERE id = ?').get(c.req.param('id')) as any;
  db.close();
  if (!row) return c.json({ error: 'Rule not found' }, 404);
  return c.json({
    ...row,
    ioc_types: JSON.parse(row.ioc_types || '[]'),
    condition_json: JSON.parse(row.condition_json || '{}'),
    references_json: JSON.parse(row.references_json || '[]'),
    tags: JSON.parse(row.tags || '[]'),
    false_positives: JSON.parse(row.false_positives || '[]'),
  });
});

api.post('/rules/reload', (c) => {
  const rules = loadRulesFromDir();
  return c.json({ message: 'Rules reloaded', count: rules.length });
});

api.post('/rules/:id/toggle', (c) => {
  const db = getDb();
  const id = c.req.param('id');
  const rule = db.prepare('SELECT id, status FROM rules WHERE id = ?').get(id) as any;
  if (!rule) { db.close(); return c.json({ error: 'Rule not found' }, 404); }
  const newStatus = rule.status === 'active' ? 'inactive' : 'active';
  db.prepare('UPDATE rules SET status = ?, updated_at = datetime(\'now\') WHERE id = ?').run(newStatus, id);
  db.close();
  return c.json({ id, status: newStatus });
});

api.get('/findings', (c) => {
  const db = getDb();
  const acknowledged = c.req.query('acknowledged');
  const severity = c.req.query('severity');
  const ruleId = c.req.query('ruleId');
  const limit = Math.min(Number(c.req.query('limit')) || 50, 500);
  const offset = Number(c.req.query('offset')) || 0;

  let where = 'WHERE 1=1';
  const params: unknown[] = [];

  if (acknowledged === 'true') { where += ' AND acknowledged = 1'; }
  else if (acknowledged === 'false') { where += ' AND acknowledged = 0'; }
  if (severity) { where += ' AND rule_severity = ?'; params.push(severity); }
  if (ruleId) { where += ' AND rule_id = ?'; params.push(ruleId); }

  const total = (db.prepare(`SELECT COUNT(*) as c FROM findings ${where}`).get(...params) as { c: number }).c;
  const findings = db.prepare(`SELECT * FROM findings ${where} ORDER BY confidence_at_match DESC, created_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
  db.close();

  return c.json({ findings, total, query: { acknowledged, severity, ruleId, limit, offset } });
});

api.post('/findings/:id/acknowledge', (c) => {
  const db = getDb();
  db.prepare('UPDATE findings SET acknowledged = 1 WHERE id = ?').run(c.req.param('id'));
  db.close();
  return c.json({ status: 'acknowledged' });
});

api.post('/match/run', async (c) => {
  const results = await runMatching();
  return c.json({ message: 'Match run complete', ...results });
});

api.get('/match/history', (c) => {
  const db = getDb();
  const history = db.prepare('SELECT * FROM match_history ORDER BY run_at DESC LIMIT 20').all();
  db.close();
  return c.json(history);
});

api.get('/dashboard', (c) => {
  const db = getDb();

  const ruleStats = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
      severity,
      category
    FROM rules GROUP BY severity, category
  `).all() as any[];

  const total = ruleStats.reduce((s: number, r: any) => s + Number(r.total), 0);
  const active = Math.max(...ruleStats.map((r: any) => Number(r.active)));
  const bySeverity: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  for (const r of ruleStats) {
    bySeverity[r.severity] = (bySeverity[r.severity] || 0) + Number(r.total);
    byCategory[r.category] = (byCategory[r.category] || 0) + Number(r.total);
  }

  const findingsTotal = (db.prepare('SELECT COUNT(*) as c FROM findings').get() as { c: number }).c;
  const findingsOpen = (db.prepare('SELECT COUNT(*) as c FROM findings WHERE acknowledged = 0').get() as { c: number }).c;
  const findingsBySeverity = db.prepare('SELECT rule_severity, COUNT(*) as count FROM findings GROUP BY rule_severity ORDER BY count DESC').all() as any[];
  const topRules = db.prepare('SELECT rule_name, COUNT(*) as count FROM findings GROUP BY rule_name ORDER BY count DESC LIMIT 10').all() as any[];
  const recentFindings = db.prepare('SELECT * FROM findings ORDER BY created_at DESC LIMIT 20').all() as any[];
  const lastMatchRun = (db.prepare('SELECT run_at FROM match_history ORDER BY run_at DESC LIMIT 1').get() as any)?.run_at || null;

  db.close();

  const dashboard: DashboardSummary = {
    rules: { total, active, bySeverity, byCategory },
    findings: {
      total: findingsTotal,
      open: findingsOpen,
      bySeverity: Object.fromEntries(findingsBySeverity.map((r: any) => [r.rule_severity, r.count])),
      topRules: topRules.map((r: any) => ({ rule_name: r.rule_name, count: r.count })),
      recent: recentFindings as any,
    },
    lastMatchRun,
  };

  return c.json(dashboard);
});
