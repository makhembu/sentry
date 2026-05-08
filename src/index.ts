import { serve } from '@hono/node-server';
import { api } from './api/routes.js';
import { initDb } from './db/init.js';
import { loadRulesFromDir } from './rules/loader.js';
import { runMatching } from './rules/engine.js';
import { Hono } from 'hono';

const app = new Hono();

app.route('/', api);

app.get('/', (c) => {
  return c.json({
    name: 'Sentry — Detection Rule Engine',
    version: '1.0.0',
    description: 'YAML-based detection rules, IOC matching engine, and findings management',
    docs: {
      health: 'GET /health',
      rules: 'GET /rules?status=',
      ruleDetail: 'GET /rules/:id',
      reloadRules: 'POST /rules/reload',
      toggleRule: 'POST /rules/:id/toggle',
      findings: 'GET /findings?acknowledged=&severity=&ruleId=&limit=&offset=',
      acknowledge: 'POST /findings/:id/acknowledge',
      matchRun: 'POST /match/run',
      matchHistory: 'GET /match/history',
      dashboard: 'GET /dashboard',
    },
  });
});

const PORT = Number(process.env.PORT) || 3001;

initDb();
loadRulesFromDir();

if (process.env.SENTRY_AUTO_MATCH === 'true') {
  runMatching();
}

console.log(`[sentry] Starting server on port ${PORT}`);
serve({ fetch: app.fetch, port: PORT });

export default app;
