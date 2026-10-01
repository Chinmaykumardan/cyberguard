import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { spawn, execSync } from 'child_process';
import path from 'path';

const app = express();
let PORT = 3000;
const portIdx = process.argv.indexOf('--port');
if (portIdx !== -1 && process.argv[portIdx + 1]) {
  PORT = parseInt(process.argv[portIdx + 1], 10);
} else if (process.env.APP_PORT) {
  PORT = parseInt(process.env.APP_PORT, 10);
}
const FLASK_PORT = 5000;

// Ensure MariaDB is running
try {
  execSync('service mariadb status || service mariadb start', { stdio: 'ignore' });
} catch {
  try {
    execSync('service mariadb start', { stdio: 'ignore' });
  } catch (err) {
    console.warn('Could not start MariaDB service via system script:', err);
  }
}

// Start Python Flask backend process
console.log('[HoneyShield] Starting Python Flask backend on port ' + FLASK_PORT + '...');
const pythonProc = spawn('python3', ['app.py'], {
  cwd: process.cwd(),
  env: {
    ...process.env,
    PORT: String(FLASK_PORT),
    FLASK_ENV: 'development',
    PYTHONUNBUFFERED: '1',
  },
  stdio: 'inherit',
});

pythonProc.on('error', (err) => {
  console.error('[HoneyShield] Failed to start Python backend:', err);
});

pythonProc.on('exit', (code, signal) => {
  console.log(`[HoneyShield] Python process exited with code ${code}, signal ${signal}`);
});

process.on('SIGTERM', () => {
  pythonProc.kill('SIGTERM');
  process.exit(0);
});

process.on('SIGINT', () => {
  pythonProc.kill('SIGINT');
  process.exit(0);
});

// Proxy all requests directly to the Python Flask backend
app.use(
  '/',
  createProxyMiddleware({
    target: `http://127.0.0.1:${FLASK_PORT}`,
    changeOrigin: true,
    ws: true,
  })
);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[HoneyShield] Web operations console listening on port ${PORT}`);
});
