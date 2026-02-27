const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {

  // ── CORS PREFLIGHT ────────────────────────────────────────
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS'
    });
    res.end();
    return;
  }

  // ── STREAMING GRADE ENDPOINT ──────────────────────────────
  if (req.method === 'POST' && req.url === '/api/grade') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const parsed = JSON.parse(body);

      // Add stream:true to the request
      parsed.stream = true;

      const options = {
        hostname: 'api.anthropic.com',
        path: '/v1/messages',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.ANTHROPIC_API_KEY || '',
          'anthropic-version': '2023-06-01',
        }
      };

      // Stream response headers back to browser
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Access-Control-Allow-Origin': '*',
        'Connection': 'keep-alive',
      });

      const apiReq = https.request(options, apiRes => {
        apiRes.on('data', chunk => {
          // Forward SSE chunks directly to the browser
          res.write(chunk);
        });
        apiRes.on('end', () => res.end());
      });

      apiReq.on('error', err => {
        console.error('API error:', err);
        res.write(`data: ${JSON.stringify({ type: 'error', message: err.message })}\n\n`);
        res.end();
      });

      apiReq.write(JSON.stringify(parsed));
      apiReq.end();
    });
    return;
  }

  // ── SERVE HTML FILES ──────────────────────────────────────
  let filePath = '.' + req.url;
  if (filePath === './') filePath = './practice-screen.html';

  // Strip query strings
  filePath = filePath.split('?')[0];

  const ext = path.extname(filePath);
  const contentType = ext === '.html' ? 'text/html'
    : ext === '.js' ? 'application/javascript'
    : ext === '.css' ? 'text/css'
    : 'text/plain';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      console.log('File not found:', filePath);
      res.writeHead(404);
      res.end('Not found: ' + filePath);
      return;
    }
    res.writeHead(200, {
      'Content-Type': contentType,
      'Access-Control-Allow-Origin': '*'
    });
    res.end(content);
  });
});

server.listen(PORT, () => {
  console.log(`✓ Server running at http://localhost:${PORT}`);
  console.log(`✓ API key: ${process.env.ANTHROPIC_API_KEY ? 'SET ✓' : 'MISSING ✗'}`);
});
