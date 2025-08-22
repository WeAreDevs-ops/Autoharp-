import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(bodyParser.text({ type: '*/*' }));

// Serve the frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// API endpoint to convert PowerShell to .ROBLOSECURITY
app.post('/convert', (req, res) => {
  const input = req.body;
  const regex = /\.ROBLOSECURITY=([^;]+)/;
  const match = input.match(regex);

  if (match) {
    res.json({ roblosecurity: match[1] });
  } else {
    res.status(400).json({ error: 'No .ROBLOSECURITY token found' });
  }
});

app.listen(3000, () => console.log('Local tool running at http://localhost:3000'));
