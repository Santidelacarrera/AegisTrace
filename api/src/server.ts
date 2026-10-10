import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { PgPersistence } from './persistence.js';
import { Store } from './store.js';

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
const { app } = createApp({ config, store, persistence });
const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => config.log({ msg: 'listening', port, demoKeys: !process.env.AEGIS_API_KEYS }));
