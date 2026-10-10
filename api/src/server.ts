import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { PgPersistence } from './persistence.js';
import { Store } from './store.js';
import { httpAnalyticsClient } from './analytics.js';
import { anthropicProvider, openaiProvider } from './llm.js';
import { ruleBasedProvider } from './analysis.js';

const config = loadConfig();
const store = new Store();
let persistence: PgPersistence | undefined;
if (process.env.DATABASE_URL) {
  const { default: pg } = await import('pg');
  persistence = new PgPersistence(new pg.Pool({ connectionString: process.env.DATABASE_URL }));
  await persistence.migrate();
  await persistence.load(store);
  config.log({ msg: 'persistence', backend: 'postgres' });
} else config.log({ msg: 'persistence', backend: 'memory', warning: 'data is lost on restart; set DATABASE_URL' });
const need = (name: string) => process.env[name] ?? (() => { throw new Error(`${name} is required for AEGIS_ANALYSIS_PROVIDER=${process.env.AEGIS_ANALYSIS_PROVIDER}`); })();
const provider = process.env.AEGIS_ANALYSIS_PROVIDER === 'anthropic' ? anthropicProvider({ apiKey: need('ANTHROPIC_API_KEY'), model: process.env.AEGIS_LLM_MODEL })
  : process.env.AEGIS_ANALYSIS_PROVIDER === 'openai' ? openaiProvider({ apiKey: need('OPENAI_API_KEY'), model: need('AEGIS_LLM_MODEL'), baseUrl: process.env.OPENAI_BASE_URL })
  : ruleBasedProvider;
config.log({ msg: 'analysis_provider', name: provider.name });
const { app } = createApp({ config, store, persistence, provider, analytics: process.env.ANALYTICS_URL ? httpAnalyticsClient(process.env.ANALYTICS_URL, { log: config.log }) : undefined });
const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => config.log({ msg: 'listening', port, demoKeys: !process.env.AEGIS_API_KEYS }));
