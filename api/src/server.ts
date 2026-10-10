import { createApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const { app } = createApp({ config });
const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => config.log({ msg: 'listening', port, demoKeys: !process.env.AEGIS_API_KEYS }));
