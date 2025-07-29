const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const multer = require('multer');
const sanitizeHtml = require('sanitize-html');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const sharp = require('sharp');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Database setup
const db = new sqlite3.Database('./itf.db', (err) => {
  if (err) console.error('Database connection error:', err.message);
  else initializeDatabase();
});

// File upload configuration
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = './uploads';
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, uniqueSuffix + path.extname(file.originalname));
    }
  }),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Database initialization
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      nickname TEXT UNIQUE NOT NULL,
      ordinal INTEGER DEFAULT 0,
      pronouns TEXT DEFAULT '',
      description TEXT DEFAULT '',
      profile_pic TEXT DEFAULT '',
      banner TEXT DEFAULT '',
      status TEXT DEFAULT 'offline',
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_admin BOOLEAN DEFAULT FALSE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Servers tables
    db.run(`CREATE TABLE IF NOT EXISTS servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      code TEXT UNIQUE NOT NULL,
      is_public BOOLEAN DEFAULT TRUE,
      owner_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_id) REFERENCES users (id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS server_members (
      server_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (server_id, user_id),
      FOREIGN KEY (server_id) REFERENCES servers (id),
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Add missing tables
    db.run(`CREATE TABLE IF NOT EXISTS read_receipts (
      user_id INTEGER NOT NULL,
      channel_id INTEGER,
      dm_conversation_id INTEGER,
      last_read_message_id INTEGER NOT NULL,
      PRIMARY KEY (user_id, channel_id, dm_conversation_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS typing_indicators (
      user_id INTEGER NOT NULL,
      channel_id INTEGER,
      dm_conversation_id INTEGER,
      is_typing BOOLEAN DEFAULT FALSE,
      last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, channel_id, dm_conversation_id)
    )`);
    
    // Channels tables
    db.run(`CREATE TABLE IF NOT EXISTS channels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      is_private BOOLEANE DEFAULT FALSE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (server_id) REFERENCES servers (id)
    )`);

    // Messages tables
    db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      channel_id INTEGER,
      dm_conversation_id INTEGER,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      reply_to INTEGER,
      is_edited BOOLEAN DEFAULT FALSE,
      edited_at DATETIME,
      moderator_comment TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (channel_id) REFERENCES channels (id),
      FOREIGN KEY (dm_conversation_id) REFERENCES dm_conversations (id),
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (reply_to) REFERENCES messages (id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS reactions (
      message_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      emoji TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (message_id, user_id, emoji),
      FOREIGN KEY (message_id) REFERENCES messages (id),
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Direct Messages tables
    db.run(`CREATE TABLE IF NOT EXISTS dm_conversations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user1_id INTEGER NOT NULL,
      user2_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user1_id) REFERENCES users (id),
      FOREIGN KEY (user2_id) REFERENCES users (id),
      UNIQUE (user1_id, user2_id)
    )`);

    // Friends and relationships tables
    db.run(`CREATE TABLE IF NOT EXISTS friend_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user_id INTEGER NOT NULL,
      to_user_id INTEGER NOT NULL,
      message TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (from_user_id) REFERENCES users (id),
      FOREIGN KEY (to_user_id) REFERENCES users (id)
    )`);
    
    // Friends table
    // Removed CHECK (user1_id < user2_id) constraint to fix the error
    db.run(`CREATE TABLE IF NOT EXISTS friends (
      user1_id INTEGER NOT NULL,
      user2_id INTEGER NOT NULL,
      status TEXT DEFAULT 'accepted',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user1_id, user2_id),
      FOREIGN KEY (user1_id) REFERENCES users (id),
      FOREIGN KEY (user2_id) REFERENCES users (id)
    )`);

    // Settings tables
    db.run(`CREATE TABLE IF NOT EXISTS user_settings (
      user_id INTEGER PRIMARY KEY,
      theme TEXT DEFAULT 'dark',
      notifications_enabled BOOLEAN DEFAULT TRUE,
      privacy_profile TEXT DEFAULT 'public',
      show_online_status BOOLEAN DEFAULT TRUE,
      allow_friend_requests BOOLEAN DEFAULT TRUE,
      allow_dms BOOLEAN DEFAULT TRUE,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS server_settings (
      server_id INTEGER PRIMARY KEY,
      default_channel_id INTEGER,
      join_permissions TEXT DEFAULT 'code',
      allow_public_join BOOLEAN DEFAULT TRUE,
      require_verification BOOLEAN DEFAULT FALSE,
      FOREIGN KEY (server_id) REFERENCES servers (id),
      FOREIGN KEY (default_channel_id) REFERENCES channels (id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS dm_settings (
      conversation_id INTEGER PRIMARY KEY,
      notifications_enabled BOOLEAN DEFAULT TRUE,
      custom_notification_sound TEXT,
      FOREIGN KEY (conversation_id) REFERENCES dm_conversations (id)
    )`);

    // Moderation tables
    db.run(`CREATE TABLE IF NOT EXISTS bans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      server_id INTEGER,
      reason TEXT,
      banned_by INTEGER NOT NULL,
      banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (server_id) REFERENCES servers (id),
      FOREIGN KEY (banned_by) REFERENCES users (id)
    )`);

    // Server invites table
    db.run(`CREATE TABLE IF NOT EXISTS server_invites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      code TEXT UNIQUE NOT NULL,
      created_by INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      max_uses INTEGER,
      use_count INTEGER DEFAULT 0,
      FOREIGN KEY (server_id) REFERENCES servers (id),
      FOREIGN KEY (created_by) REFERENCES users (id)
    )`);

    // Additional indexes for performance
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_dm ON messages(dm_conversation_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_server_members_user ON server_members(user_id)`);
  });
}

// WebSocket connections map
const activeConnections = new Map();

wss.on('connection', (ws, req) => {
  const token = req.url.split('token=')[1] || req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    ws.close(1008, 'Authentication required');
    return;
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      ws.close(1008, 'Invalid token');
      return;
    }

    const userId = decoded.userId;
    activeConnections.set(userId, ws);
    updateUserStatus(userId, 'online');

    ws.on('message', (message) => {
      handleWebSocketMessage(userId, message);
    });

    ws.on('close', () => {
      activeConnections.delete(userId);
      updateUserStatus(userId, 'offline');
    });

    ws.on('error', (err) => {
      console.error('WebSocket error:', err);
      activeConnections.delete(userId);
      updateUserStatus(userId, 'offline');
    });
  });
});

// WebSocket message handlers
function handleWebSocketMessage(userId, message) {
  try {
    const data = JSON.parse(message);
    
    switch (data.type) {
      case 'typing':
        handleTypingIndicator(userId, data);
        break;
      case 'message':
        handleMessage(userId, data);
        break;
      case 'reaction':
        handleReaction(userId, data);
        break;
      case 'read':
        handleReadReceipt(userId, data);
        break;
      default:
        console.log('Unknown WebSocket message type:', data.type);
    }
  } catch (err) {
    console.error('WebSocket message processing error:', err);
  }
}

function handleTypingIndicator(userId, { isTyping, channelId, dmConversationId }) {
  db.run(
    `INSERT OR REPLACE INTO typing_indicators 
     VALUES (?, ?, ?, ?, datetime('now'))`,
    [userId, channelId, dmConversationId, isTyping],
    (err) => {
      if (err) return console.error('Typing indicator error:', err);
      
      const broadcastData = {
        type: 'typing',
        userId,
        isTyping,
        channelId,
        dmConversationId
      };
      
      if (channelId) broadcastToChannel(channelId, broadcastData, userId);
      else if (dmConversationId) broadcastToDmConversation(dmConversationId, broadcastData, userId);
    }
  );
}

function handleMessage(userId, { content, channelId, dmConversationId, replyTo }) {
  const sanitizedContent = sanitizeHtml(content, { 
    allowedTags: [], 
    allowedAttributes: {} 
  });

  if (!sanitizedContent.trim()) return;

  let idColumn, idValue;
  
  if (channelId) {
    idColumn = 'channel_id';
    idValue = channelId;
  } else if (dmConversationId) {
    idColumn = 'dm_conversation_id';
    idValue = dmConversationId;
  } else return;

  db.run(
    `INSERT INTO messages (${idColumn}, user_id, content, reply_to) 
     VALUES (?, ?, ?, ?)`,
    [idValue, userId, sanitizedContent, replyTo],
    function(err) {
      if (err) return console.error('Message save error:', err);
      
      const messageId = this.lastID;
      // Fetch the message with user details and reactions
      getMessageWithDetails(messageId, (err, message) => {
        if (err) return console.error('Message retrieval error:', err);
        
        const broadcastData = { 
          type: 'message', 
          message: message
        };
        
        if (channelId) broadcastToChannel(channelId, broadcastData, userId);
        else if (dmConversationId) broadcastToDmConversation(dmConversationId, broadcastData, userId);
      });
    }
  );
}

function getMessageWithDetails(messageId, callback) {
  db.get(
    `SELECT m.*, u.nickname, u.ordinal, u.status, u.profile_pic 
     FROM messages m JOIN users u ON m.user_id = u.id 
     WHERE m.id = ?`,
    [messageId],
    (err, message) => {
      if (err) return callback(err);
      if (!message) return callback(new Error('Message not found'));

      message.userIdentifier = `${message.nickname}-itl${message.ordinal.toString().padStart(4, '0')}`;
      if (message.status === 'hibernating') {
        message.content = `🛏️ ${message.content} 🛏️`;
      }

      db.all(
        `SELECT emoji, user_id FROM reactions WHERE message_id = ?`,
        [messageId],
        (err, reactions) => {
          if (err) return callback(err);
          message.reactions = reactions; // Store as array of {emoji, user_id}
          callback(null, message);
        }
      );
    }
  );
}


function handleReaction(userId, { messageId, emoji, action }) {
  if (action === 'add') {
    db.run(
      `INSERT OR IGNORE INTO reactions VALUES (?, ?, ?, datetime('now'))`,
      [messageId, userId, emoji],
      (err) => {
        if (err) return console.error('Reaction add error:', err);
        broadcastReactionUpdate(messageId);
      }
    );
  } else if (action === 'remove') {
    db.run(
      `DELETE FROM reactions WHERE message_id = ? AND user_id = ? AND emoji = ?`,
      [messageId, userId, emoji],
      (err) => {
        if (err) return console.error('Reaction remove error:', err);
        broadcastReactionUpdate(messageId);
      }
    );
  }
}

function broadcastReactionUpdate(messageId) {
  db.get(
    `SELECT channel_id, dm_conversation_id FROM messages WHERE id = ?`,
    [messageId],
    (err, message) => {
      if (err) return console.error('Message location error:', err);
      
      // Fetch all reactions for the message, including user_id
      db.all(
        `SELECT emoji, user_id FROM reactions WHERE message_id = ?`,
        [messageId],
        (err, reactions) => {
          if (err) return console.error('Reactions retrieval error:', err);
          
          // Group reactions by emoji and count them
          const groupedReactions = reactions.reduce((acc, r) => {
            if (!acc[r.emoji]) {
              acc[r.emoji] = { emoji: r.emoji, count: 0, user_ids: [] };
            }
            acc[r.emoji].count++;
            acc[r.emoji].user_ids.push(r.user_id);
            return acc;
          }, {});

          const broadcastData = { 
            type: 'reaction_update', 
            messageId, 
            reactions: Object.values(groupedReactions) // Send array of {emoji, count, user_ids}
          };
          
          if (message.channel_id) broadcastToChannel(message.channel_id, broadcastData);
          else if (message.dm_conversation_id) broadcastToDmConversation(message.dm_conversation_id, broadcastData);
        }
      );
    }
  );
}

function handleReadReceipt(userId, { channelId, dmConversationId, lastMessageId }) {
  if (!lastMessageId) return;

  db.run(
    `INSERT OR REPLACE INTO read_receipts 
     (user_id, channel_id, dm_conversation_id, last_read_message_id) 
     VALUES (?, ?, ?, ?)`,
    [userId, channelId, dmConversationId, lastMessageId],
    (err) => {
      if (err) console.error('Read receipt error:', err);
    }
  );
}

// Broadcast functions
function broadcastToChannel(channelId, data, excludeUserId = null) {
  db.all(
    `SELECT user_id FROM server_members sm
     JOIN channels c ON sm.server_id = c.server_id
     WHERE c.id = ?`,
    [channelId],
    (err, members) => {
      if (err) return console.error('Channel members retrieval error:', err);
      
      members.forEach(member => {
        if (member.user_id.toString() !== excludeUserId?.toString()) {
          const ws = activeConnections.get(member.user_id.toString());
          if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
        }
      });
    }
  );
}

function broadcastToDmConversation(conversationId, data, excludeUserId = null) {
  db.get(
    `SELECT user1_id, user2_id FROM dm_conversations WHERE id = ?`,
    [conversationId],
    (err, conversation) => {
      if (err) return console.error('DM conversation retrieval error:', err);
      
      [conversation.user1_id, conversation.user2_id]
        .filter(id => id.toString() !== excludeUserId?.toString())
        .forEach(userId => {
          const ws = activeConnections.get(userId.toString());
          if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
        });
    }
  );
}

function updateUserStatus(userId, status) {
  db.run(
    `UPDATE users SET status = ?, last_seen = datetime('now') WHERE id = ?`,
    [status, userId],
    (err) => {
      if (err) return console.error('Status update error:', err);
      notifyUserStatusChange(userId, status);
    }
  );
}

function notifyUserStatusChange(userId, status) {
  // Notify all servers the user is in
  db.all(
    `SELECT DISTINCT server_id FROM server_members WHERE user_id = ?`,
    [userId],
    (err, servers) => {
      if (err) return console.error('User servers retrieval error:', err);
      
      servers.forEach(server => {
        broadcastToServer(server.server_id, { 
          type: 'user_status', 
          userId, 
          status 
        });
      });
    }
  );
  
  // Notify all DM conversations the user is in
  db.all(
    `SELECT id FROM dm_conversations WHERE user1_id = ? OR user2_id = ?`,
    [userId, userId],
    (err, conversations) => {
      if (err) return console.error('User DM conversations error:', err);
      
      conversations.forEach(conversation => {
        broadcastToDmConversation(conversation.id, { 
          type: 'user_status', 
          userId, 
          status 
        }, userId);
      });
    }
  );
}

function broadcastToServer(serverId, data, excludeUserId = null) {
  db.all(
    `SELECT user_id FROM server_members WHERE server_id = ?`,
    [serverId],
    (err, members) => {
      if (err) return console.error('Server members retrieval error:', err);
      
      members.forEach(member => {
        if (member.user_id.toString() !== excludeUserId?.toString()) {
          const ws = activeConnections.get(member.user_id.toString());
          if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
        }
      });
    }
  );
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const token = req.cookies.session_token || req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// API Routes

// Auth Routes
app.post('/api/register', async (req, res) => {
  const { email, password, nickname } = req.body;
  
  if (!email || !password || !nickname) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  try {
    // Check if this is the first user (will be admin)
    const isFirstUser = await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
        if (err) reject(err);
        else resolve(row.count === 0);
      });
    });
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Generate unique ordinal for nickname
    const existingNicknames = await new Promise((resolve, reject) => {
      db.all('SELECT ordinal FROM users WHERE nickname = ? ORDER BY ordinal', [nickname], (err, rows) => {
        if (err) reject(err);
        else resolve(rows.map(r => r.ordinal));
      });
    });
    
    let ordinal = 0;
    if (existingNicknames.length > 0) {
      for (let i = 0; i <= existingNicknames.length; i++) {
        if (i === existingNicknames.length || existingNicknames[i] > i) {
          ordinal = i;
          break;
        }
      }
      
      if (ordinal > 9999) {
        return res.status(400).json({ error: 'Nickname limit reached' });
      }
    }
    
    // Create user
    db.run(
      `INSERT INTO users (email, password, nickname, ordinal, is_admin) 
       VALUES (?, ?, ?, ?, ?)`,
      [email, hashedPassword, nickname, ordinal, isFirstUser],
      function(err) {
        if (err) {
          if (err.message.includes('users.email')) return res.status(400).json({ error: 'Email already in use' });
          if (err.message.includes('users.nickname')) return res.status(400).json({ error: 'Nickname already in use' });
          return res.status(500).json({ error: 'Registration failed' });
        }
        
        const userId = this.lastID;
        
        // Create default user settings
        db.run(`INSERT INTO user_settings (user_id) VALUES (?)`, [userId], (err) => {
          if (err) console.error('User settings creation error:', err);
          
          // Generate default profile images
          generateDefaultProfileImages(nickname, userId)
            .then(() => {
              // Create JWT token
              const token = jwt.sign({ 
                userId, 
                isAdmin: isFirstUser 
              }, JWT_SECRET, { expiresIn: '7d' });
              
              // Set HTTP-only cookie
              res.cookie('session_token', token, { 
                httpOnly: true, 
                secure: process.env.NODE_ENV === 'production',
                maxAge: 7 * 24 * 60 * 60 * 1000
              });
              
              res.status(201).json({ 
                userId,
                isAdmin: isFirstUser,
                token
              });
            })
            .catch(err => {
              console.error('Default images error:', err);
              res.status(201).json({ 
                userId,
                isAdmin: isFirstUser,
                warning: 'Default images not generated'
              });
            });
        });
      }
    );
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

async function generateDefaultProfileImages(nickname, userId) {
  const firstLetter = nickname.charAt(0).toUpperCase();
  const bgColor = `hsl(${Math.floor(Math.random() * 360)}, 70%, 50%)`;
  
  // Generate avatar SVG
  const avatarSvg = `
    <svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
      <rect width="200" height="200" fill="${bgColor}"/>
      <text x="100" y="120" font-family="Arial" font-size="100" 
            fill="white" text-anchor="middle" dominant-baseline="middle">
        ${firstLetter}
      </text>
    </svg>
  `;
  
  const avatarFilename = `avatar-${userId}.png`;
  await sharp(Buffer.from(avatarSvg))
    .png()
    .toFile(`./uploads/${avatarFilename}`);
  
  // Generate banner
  const bannerFilename = `banner-${userId}.png`;
  await sharp({
    create: {
      width: 600,
      height: 200,
      channels: 4,
      background: bgColor
    }
  }).png().toFile(`./uploads/${bannerFilename}`);
  
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET profile_pic = ?, banner = ? WHERE id = ?`,
      [avatarFilename, bannerFilename, userId],
      (err) => {
        if (err) reject(err);
        else resolve();
      }
    );
  });
}

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  
  db.get(
    `SELECT id, password, is_admin FROM users WHERE email = ?`,
    [email],
    async (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });
      
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) return res.status(401).json({ error: 'Invalid credentials' });
      
      // Update user status to online
      db.run(
        `UPDATE users SET status = 'online', last_seen = datetime('now') WHERE id = ?`,
        [user.id],
        (err) => {
          if (err) console.error('Status update error:', err);
        }
      );
      
      // Create JWT token
      const token = jwt.sign({ 
        userId: user.id, 
        isAdmin: user.is_admin 
      }, JWT_SECRET, { expiresIn: '7d' });
      
      // Set HTTP-only cookie
      res.cookie('session_token', token, { 
        httpOnly: true, 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });
      
      res.json({ 
        userId: user.id,
        isAdmin: user.is_admin,
        token
      });
    }
  );
});

app.post('/api/logout', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  
  // Update user status to offline
  db.run(
    `UPDATE users SET status = 'offline', last_seen = datetime('now') WHERE id = ?`,
    [userId],
    (err) => {
      if (err) console.error('Status update error:', err);
    }
  );
  
  // Clear session cookie
  res.clearCookie('session_token');
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/verify-token', authenticateToken, (req, res) => {
  res.json({ userId: req.user.userId });
});

// User Routes
app.get('/api/user/:id', authenticateToken, (req, res) => {
  const userId = req.params.id;
  
  db.get(
    `SELECT id, email, nickname, ordinal, pronouns, description, 
            profile_pic, banner, status, last_seen, created_at,
            (SELECT COUNT(*) FROM friends WHERE (user1_id = users.id OR user2_id = users.id) AND status = 'accepted') as friend_count,
            (SELECT COUNT(*) FROM server_members WHERE user_id = users.id) as server_count
     FROM users WHERE id = ?`,
    [userId],
    (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(404).json({ error: 'User not found' });
      
      // Generate user identifier (nickname-itl0000)
      user.identifier = `${user.nickname}-itl${user.ordinal.toString().padStart(4, '0')}`;
      
      // Calculate account age in days
      user.account_age = Math.floor((new Date() - new Date(user.created_at)) / (1000 * 60 * 60 * 24));
      
      res.json(user);
    }
  );
});

app.put('/api/user/:id', authenticateToken, upload.fields([
  { name: 'profile_pic', maxCount: 1 },
  { name: 'banner', maxCount: 1 }
]), (req, res) => {
  const userId = req.params.id;
  const currentUserId = req.user.userId;
  
  // Verify user can only update their own profile
  if (userId !== currentUserId.toString()) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  const { pronouns, description, status } = req.body;
  const validStatuses = ['online', 'offline', 'unavailable', 'hibernating'];
  
  // Validate status
  if (status && !validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  
  // Build dynamic update query
  const updates = {};
  const params = [];
  
  if (pronouns !== undefined) { // Allow empty string to clear
    updates.pronouns = pronouns;
    params.push(pronouns);
  }
  if (description !== undefined) { // Allow empty string to clear
    updates.description = description;
    params.push(description);
  }
  if (status) {
    updates.status = status;
    params.push(status);
  }
  
  // Handle file uploads
  if (req.files?.profile_pic) {
    const profilePic = req.files.profile_pic[0];
    updates.profile_pic = profilePic.filename;
    params.push(profilePic.filename);
  }
  
  if (req.files?.banner) {
    const banner = req.files.banner[0];
    updates.banner = banner.filename;
    params.push(banner.filename);
  }
  
  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }
  
  const setClause = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  params.push(userId);
  
  db.run(
    `UPDATE users SET ${setClause} WHERE id = ?`,
    params,
    function(err) {
      if (err) {
        console.error('Update user profile failed:', err);
        return res.status(500).json({ error: 'Update failed' });
      }
      
      // Notify status change if updated
      if (updates.status) notifyUserStatusChange(userId, updates.status);
      
      res.json({ message: 'Profile updated' });
    }
  );
});

// Server Routes
app.get('/api/user/:id/servers', authenticateToken, (req, res) => {
  const userId = req.params.id;
  const currentUserId = req.user.userId;

  // Users can only view their own servers (or admins)
  if (userId.toString() !== currentUserId.toString() && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Not authorized to view these servers' });
  }

  db.all(
    `SELECT s.id, s.name, s.description, s.code, s.owner_id,
            (SELECT COUNT(*) FROM server_members WHERE server_id = s.id) as member_count
     FROM servers s
     JOIN server_members sm ON s.id = sm.server_id
     WHERE sm.user_id = ?`,
    [userId],
    (err, servers) => {
      if (err) {
        console.error('Database error fetching user servers:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(servers);
    }
  );
});

app.post('/api/servers', authenticateToken, (req, res) => {
  const { name, description, isPublic, channelName } = req.body;
  const userId = req.user.userId;
  
  if (!name) return res.status(400).json({ error: 'Name required' });
  if (!channelName) return res.status(400).json({ error: 'Channel name required' });
  
  // Generate unique server code
  const code = generateServerCode();
  
  db.run(
    `INSERT INTO servers (name, description, code, is_public, owner_id)
     VALUES (?, ?, ?, ?, ?)`,
    [name, description || '', code, isPublic || true, userId],
    function(err) {
      if (err) {
        console.error('Server creation failed:', err);
        return res.status(500).json({ error: 'Server creation failed' });
      }
      
      const serverId = this.lastID;
      
      // Add creator as first member
      db.run(
        `INSERT INTO server_members (server_id, user_id) VALUES (?, ?)`,
        [serverId, userId],
        (err) => {
          if (err) console.error('Member addition error:', err);
          
          // Create default general channel
          db.run(
            `INSERT INTO channels (server_id, name, description) VALUES (?, ?, ?)`,
            [serverId, channelName, 'Default channel'],
            function(err) {
              if (err) console.error('Channel creation error:', err);
              
              // Create default server settings
              db.run(
                `INSERT INTO server_settings (server_id, default_channel_id) VALUES (?, ?)`,
                [serverId, this.lastID],
                (err) => {
                  if (err) console.error('Settings creation error:', err);
                  
                  res.status(201).json({ serverId, code });
                }
              );
            }
          );
        }
      );
    }
  );
});

function generateServerCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 8; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

app.get('/api/servers/public', (req, res) => {
  db.all(
    `SELECT s.id, s.name, s.description, s.code, s.created_at, 
            u.nickname as owner_name, COUNT(sm.user_id) as member_count
     FROM servers s
     JOIN users u ON s.owner_id = u.id
     LEFT JOIN server_members sm ON s.id = sm.server_id
     WHERE s.is_public = TRUE
     GROUP BY s.id
     ORDER BY s.created_at DESC
     LIMIT 50`,
    (err, servers) => {
      if (err) {
        console.error('Database error fetching public servers:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(servers);
    }
  );
});

app.post('/api/servers/join', authenticateToken, (req, res) => {
  const { code } = req.body;
  const userId = req.user.userId;
  
  if (!code) return res.status(400).json({ error: 'Code required' });
  
  db.get(
    `SELECT id, is_public FROM servers WHERE code = ?`,
    [code],
    (err, server) => {
      if (err) {
        console.error('Database error finding server by code:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!server) return res.status(404).json({ error: 'Server not found' });
      
      // Check if user is already a member
      db.get(
        `SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?`,
        [server.id, userId],
        (err, row) => {
          if (err) {
            console.error('Database error checking membership:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          if (row) return res.status(400).json({ error: 'Already a member' });
          
          // Add user to server
          db.run(
            `INSERT INTO server_members (server_id, user_id) VALUES (?, ?)`,
            [server.id, userId],
            (err) => {
              if (err) {
                console.error('Failed to add user to server_members:', err);
                return res.status(500).json({ error: 'Join failed' });
              }
              
              res.json({ message: 'Joined server', serverId: server.id });
            }
          );
        }
      );
    }
  );
});

// Server Routes
app.get('/api/servers/:id', authenticateToken, (req, res) => {
  const serverId = req.params.id;
  const userId = req.user.userId;

  db.get(
    `SELECT s.*, u.nickname as owner_name 
     FROM servers s
     JOIN users u ON s.owner_id = u.id
     WHERE s.id = ?`,
    [serverId],
    (err, server) => {
      if (err) {
        console.error('Database error fetching server details:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!server) return res.status(404).json({ error: 'Server not found' });

      // Check if user is member
      db.get(
        `SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?`,
        [serverId, userId],
        (err, row) => {
          if (err) {
            console.error('Database error checking server membership:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          if (!row && !req.user.isAdmin) return res.status(403).json({ error: 'Not a member' });

          res.json(server);
        }
      );
    }
  );
});

// Channel Routes
app.get('/api/servers/:serverId/channels', authenticateToken, (req, res) => {
  const serverId = req.params.serverId;
  const userId = req.user.userId;
  
  // Verify user is a member of the server
  db.get(
    `SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?`,
    [serverId, userId],
    (err, row) => {
      if (err) {
        console.error('Database error verifying server membership for channels:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) return res.status(403).json({ error: 'Not a member of this server' });
      
      // Get all channels for the server
      db.all(
        `SELECT * FROM channels WHERE server_id = ? ORDER BY created_at`,
        [serverId],
        (err, channels) => {
          if (err) {
            console.error('Database error fetching channels:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          res.json(channels);
        }
      );
    }
  );
});

// Channel Routes
app.post('/api/servers/:serverId/channels', authenticateToken, (req, res) => {
  const serverId = req.params.serverId;
  const { name, description, isPrivate } = req.body;
  const userId = req.user.userId;
  
  if (!name) return res.status(400).json({ error: 'Name required' });
  
  // Only server owner can create channels
  db.get(
    `SELECT owner_id FROM servers WHERE id = ?`,
    [serverId],
    (err, server) => {
      if (err) {
        console.error('Database error fetching server owner:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!server) return res.status(404).json({ error: 'Server not found' });
      if (server.owner_id !== userId && !req.user.isAdmin) return res.status(403).json({ error: 'Not authorized to create channels' });
      
      db.run(
        `INSERT INTO channels (server_id, name, description, is_private)
         VALUES (?, ?, ?, ?)`,
        [serverId, name, description || '', isPrivate || false],
        function(err) {
          if (err) {
            console.error('Channel creation failed:', err);
            return res.status(500).json({ error: 'Channel creation failed' });
          }
          
          res.status(201).json({ channelId: this.lastID });
        }
      );
    }
  );
});

// Server Members Route - Added this missing endpoint
app.get('/api/servers/:serverId/members', authenticateToken, (req, res) => {
  const serverId = req.params.serverId;
  const userId = req.user.userId;
  
  // Verify user is a member of the server
  db.get(
    `SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?`,
    [serverId, userId],
    (err, row) => {
      if (err) {
        console.error('Database error verifying server membership for members:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) return res.status(403).json({ error: 'Not a member of this server' });
      
      // Get all members of the server
      db.all(
        `SELECT u.id, u.nickname, u.ordinal, u.profile_pic, u.status
         FROM users u
         JOIN server_members sm ON u.id = sm.user_id
         WHERE sm.server_id = ?
         ORDER BY u.nickname`,
        [serverId],
        (err, members) => {
          if (err) {
            console.error('Database error fetching server members:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          
          // Add user identifier to each member
          members.forEach(member => {
            member.identifier = `${member.nickname}-itl${member.ordinal.toString().padStart(4, '0')}`;
          });
          
          res.json(members);
        }
      );
    }
  );
});

// DM Conversations Routes
app.get('/api/user/:userId/dm-conversations', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    
    // Ensure user can only fetch their own DMs
    if (userId.toString() !== req.user.userId.toString()) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    try {
        const conversations = await new Promise((resolve, reject) => {
            db.all(
                `SELECT dc.id, 
                 CASE WHEN dc.user1_id = ? THEN dc.user2_id ELSE dc.user1_id END as other_user_id,
                 u.nickname as other_user_nickname,
                 u.ordinal as other_user_ordinal,
                 u.profile_pic as other_user_profile_pic,
                 u.status as other_user_status,
                 (SELECT content FROM messages WHERE dm_conversation_id = dc.id ORDER BY created_at DESC LIMIT 1) as last_message,
                 (SELECT created_at FROM messages WHERE dm_conversation_id = dc.id ORDER BY created_at DESC LIMIT 1) as last_message_time
                 FROM dm_conversations dc
                 JOIN users u ON (CASE WHEN dc.user1_id = ? THEN dc.user2_id ELSE dc.user1_id END) = u.id
                 WHERE dc.user1_id = ? OR dc.user2_id = ?
                 ORDER BY last_message_time DESC`, // Order by last message time
                [userId, userId, userId, userId],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
        
        res.json(conversations);
    } catch (err) {
        console.error('Error fetching DM conversations:', err);
        res.status(500).json({ error: 'Failed to fetch DM conversations' });
    }
});

// Friends Routes
app.get('/api/user/:userId/friends', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    
    // Ensure user can only fetch their own friends
    if (userId.toString() !== req.user.userId.toString()) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    try {
        const friends = await new Promise((resolve, reject) => {
            db.all(
                `SELECT u.id, u.nickname, u.ordinal, u.profile_pic, u.status
                 FROM friends f
                 JOIN users u ON (f.user1_id = u.id AND f.user2_id = ?) OR (f.user2_id = u.id AND f.user1_id = ?)
                 WHERE (f.user1_id = ? OR f.user2_id = ?) AND f.status = 'accepted'
                 ORDER BY u.nickname`,
                [userId, userId, userId, userId], // Pass userId multiple times for the JOIN and WHERE clauses
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
        
        // Add the identifier in JavaScript
        friends.forEach(friend => {
            friend.identifier = `${friend.nickname}-itl${friend.ordinal.toString().padStart(4, '0')}`;
        });
        
        res.json(friends);
    } catch (err) {
        console.error('Error fetching friends:', err);
        res.status(500).json({ error: 'Failed to fetch friends' });
    }
});

// Friend Requests Routes
app.get('/api/user/:userId/friend-requests', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    
    // Ensure user can only fetch their own friend requests
    if (userId.toString() !== req.user.userId.toString()) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    try {
        const requests = await new Promise((resolve, reject) => {
            db.all(
                `SELECT fr.id, fr.from_user_id, fr.to_user_id, fr.message, fr.status, fr.created_at,
                 u.nickname as from_user_nickname, u.profile_pic as from_user_profile_pic, u.status as from_user_status
                 FROM friend_requests fr
                 JOIN users u ON fr.from_user_id = u.id
                 WHERE fr.to_user_id = ? AND fr.status = 'pending'
                 ORDER BY fr.created_at DESC`,
                [userId],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });
        
        res.json(requests);
    } catch (err) {
        console.error('Error fetching friend requests:', err);
        res.status(500).json({ error: 'Failed to fetch friend requests' });
    }
});

// Find User by Identifier
app.post('/api/users/find', authenticateToken, async (req, res) => {
    const { nickname, ordinal } = req.body;
    
    if (!nickname || ordinal === undefined) {
        return res.status(400).json({ error: 'Nickname and ordinal are required' });
    }
    
    try {
        const user = await new Promise((resolve, reject) => {
            db.get(
                `SELECT id, nickname, ordinal, profile_pic, status 
                 FROM users 
                 WHERE nickname = ? AND ordinal = ?`,
                [nickname, ordinal],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(user);
    } catch (err) {
        console.error('Error finding user:', err);
        res.status(500).json({ error: 'Failed to find user' });
    }
});

// Start DM Conversation
app.post('/api/dm-conversations/start', authenticateToken, async (req, res) => {
    const { friendId } = req.body;
    const userId = req.user.userId;
    
    if (!friendId) {
        return res.status(400).json({ error: 'Friend ID is required' });
    }
    if (userId === friendId) {
        return res.status(400).json({ error: 'Cannot start DM with yourself' });
    }
    
    try {
        // Verificar se já são amigos
        const isFriend = await new Promise((resolve, reject) => {
            db.get(
                `SELECT 1 FROM friends 
                 WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)) 
                 AND status = 'accepted'`,
                [userId, friendId, friendId, userId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(!!row);
                }
            );
        });
        
        if (!isFriend) {
            return res.status(403).json({ error: 'You can only start DMs with friends' });
        }
        
        // Verificar se já existe uma conversa
        const existingConversation = await new Promise((resolve, reject) => {
            db.get(
                `SELECT id FROM dm_conversations 
                 WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)`,
                [userId, friendId, friendId, userId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
        
        if (existingConversation) {
            return res.json(existingConversation);
        }
        
        // Criar nova conversa
        const conversation = await new Promise((resolve, reject) => {
            // Ensure user1_id is always smaller to maintain uniqueness constraint
            const u1 = Math.min(userId, friendId);
            const u2 = Math.max(userId, friendId);

            db.run(
                `INSERT INTO dm_conversations (user1_id, user2_id) 
                 VALUES (?, ?)`,
                [u1, u2],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID });
                }
            );
        });
        
        res.status(201).json(conversation);
    } catch (err) {
        console.error('Error starting DM conversation:', err);
        res.status(500).json({ error: 'Failed to start DM conversation' });
    }
});

// Friend Request Routes
app.post('/api/friend-requests', authenticateToken, async (req, res) => {
    const { toUserId, message } = req.body;
    const fromUserId = req.user.userId;
    
    if (!toUserId) {
        return res.status(400).json({ error: 'Recipient ID is required' });
    }
    if (fromUserId === toUserId) {
        return res.status(400).json({ error: 'Cannot send friend request to yourself' });
    }
    
    try {
        // Verificar se já existe uma solicitação pendente (de ou para)
        const existingRequest = await new Promise((resolve, reject) => {
            db.get(
                `SELECT 1 FROM friend_requests 
                 WHERE ((from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)) 
                 AND status = 'pending'`,
                [fromUserId, toUserId, toUserId, fromUserId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(!!row);
                }
            );
        });
        
        if (existingRequest) {
            return res.status(400).json({ error: 'Friend request already sent or received and pending' });
        }
        
        // Verificar se já são amigos
        const isFriend = await new Promise((resolve, reject) => {
            db.get(
                `SELECT 1 FROM friends 
                 WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)`,
                [fromUserId, toUserId, toUserId, fromUserId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(!!row);
                }
            );
        });
        
        if (isFriend) {
            return res.status(400).json({ error: 'You are already friends' });
        }
        
        // Criar nova solicitação
        const request = await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO friend_requests (from_user_id, to_user_id, message) 
                 VALUES (?, ?, ?)`,
                [fromUserId, toUserId, message || null],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID });
                }
            );
        });
        
        res.status(201).json(request);
    } catch (err) {
        console.error('Error sending friend request:', err);
        res.status(500).json({ error: 'Failed to send friend request' });
    }
});

// Respond to Friend Request
app.post('/api/friend-requests/:requestId/:action', authenticateToken, async (req, res) => {
    const { requestId, action } = req.params;
    const userId = req.user.userId;
    
    if (!['accept', 'reject'].includes(action)) {
        return res.status(400).json({ error: 'Invalid action' });
    }
    
    try {
        // Verificar se a solicitação existe e é para o usuário atual
        const request = await new Promise((resolve, reject) => {
            db.get(
                `SELECT id, from_user_id, to_user_id FROM friend_requests 
                 WHERE id = ? AND to_user_id = ? AND status = 'pending'`,
                [requestId, userId],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
        
        if (!request) {
            return res.status(404).json({ error: 'Friend request not found or already processed' });
        }
        
        // Atualizar status da solicitação
        await new Promise((resolve, reject) => {
            db.run(
                `UPDATE friend_requests SET status = ? WHERE id = ?`,
                [action === 'accept' ? 'accepted' : 'rejected', requestId],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });
        
        // Se aceito, adicionar como amigo
        if (action === 'accept') {
            await new Promise((resolve, reject) => {
                // Ensure user1_id is always smaller to maintain uniqueness constraint
                const u1 = Math.min(request.from_user_id, request.to_user_id);
                const u2 = Math.max(request.from_user_id, request.to_user_id);

                db.run(
                    `INSERT OR IGNORE INTO friends (user1_id, user2_id, status) 
                     VALUES (?, ?, 'accepted')`,
                    [u1, u2],
                    function(err) {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });
            
            // Criar conversa de DM automaticamente (se não existir)
            await new Promise((resolve, reject) => {
                const u1 = Math.min(request.from_user_id, request.to_user_id);
                const u2 = Math.max(request.from_user_id, request.to_user_id);

                db.run(
                    `INSERT OR IGNORE INTO dm_conversations (user1_id, user2_id) 
                     VALUES (?, ?)`,
                    [u1, u2],
                    function(err) {
                        if (err) reject(err);
                        else resolve();
                    }
                );
            });
        }
        
        res.json({ message: `Friend request ${action === 'accept' ? 'accepted' : 'rejected'}` });
    } catch (err) {
        console.error('Error responding to friend request:', err);
        res.status(500).json({ error: 'Failed to respond to friend request' });
    }
});

// Remove Friend
app.delete('/api/friends/:friendId', authenticateToken, async (req, res) => {
    const { friendId } = req.params;
    const userId = req.user.userId;
    
    try {
        // Remover amizade
        await new Promise((resolve, reject) => {
            db.run(
                `DELETE FROM friends 
                 WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)`,
                [userId, friendId, friendId, userId],
                function(err) {
                    if (err) reject(err);
                    else if (this.changes === 0) reject(new Error('Friendship not found or already removed.'));
                    else resolve();
                }
            );
        });
        
        // Opcional: Remover a conversa de DM associada (ou apenas não mostrar mais)
        // Para remover, você precisaria do ID da conversa.
        // Por simplicidade, vamos apenas deixar a conversa existir, mas ela não será mais acessível via "Amigos".
        // Se quiser remover, adicione:
        /*
        await new Promise((resolve, reject) => {
            const u1 = Math.min(userId, friendId);
            const u2 = Math.max(userId, friendId);
            db.run(
                `DELETE FROM dm_conversations WHERE user1_id = ? AND user2_id = ?`,
                [u1, u2],
                function(err) {
                    if (err) console.error('Error deleting DM conversation:', err);
                    resolve(); // Resolve even if no conversation was found/deleted
                }
            );
        });
        */

        res.json({ message: 'Friend removed successfully' });
    } catch (err) {
        console.error('Error removing friend:', err.message);
        res.status(500).json({ error: err.message || 'Failed to remove friend' });
    }
});

// Message Routes
app.get('/api/channels/:channelId/messages', authenticateToken, (req, res) => {
  const channelId = req.params.channelId;
  const { before, after, limit = 50 } = req.query; 
  const userId = req.user.userId;
  
  // Verify user has access to the channel
  db.get(
    `SELECT 1 FROM server_members sm
     JOIN channels c ON sm.server_id = c.server_id
     WHERE c.id = ? AND sm.user_id = ?`,
    [channelId, userId],
    (err, row) => {
      if (err) {
        console.error('Database error verifying channel access:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) return res.status(403).json({ error: 'Not authorized to access this channel' });
      
      let query = `
        SELECT m.id, m.channel_id, m.dm_conversation_id, m.user_id, m.content, m.reply_to, 
               m.is_edited, m.edited_at, m.moderator_comment, m.created_at,
               u.nickname, u.ordinal, u.profile_pic, u.status
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.channel_id = ?
      `;
      
      const params = [channelId];
      
      if (before) {
        query += ` AND m.id < ?`;
        params.push(before);
      } else if (after) { // New condition for polling
        query += ` AND m.id > ?`;
        params.push(after);
      }
      
      query += `
        ORDER BY m.id ASC
        LIMIT ?
      `;
      params.push(limit);
      
      db.all(query, params, async (err, messages) => {
        if (err) {
          console.error('Database error fetching channel messages:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        // Fetch reactions for each message
        for (const msg of messages) {
          msg.userIdentifier = `${msg.nickname}-itl${msg.ordinal.toString().padStart(4, '0')}`;
          if (msg.status === 'hibernating') {
            msg.content = `🛏️ ${msg.content} 🛏️`;
          }
          
          const reactions = await new Promise((resolve, reject) => {
            db.all(`SELECT emoji, user_id FROM reactions WHERE message_id = ?`, [msg.id], (err, rows) => {
              if (err) reject(err);
              else resolve(rows);
            });
          });
          msg.reactions = reactions; // Store as array of {emoji, user_id}
        }
        
        res.json(messages); // Return messages in chronological order
      });
    }
  );
});

// DM Messages Route
app.get('/api/dm-conversations/:conversationId/messages', authenticateToken, (req, res) => {
  const conversationId = req.params.conversationId;
  const { before, after, limit = 50 } = req.query; 
  const userId = req.user.userId;
  
  // Verify user is part of the conversation
  db.get(
    `SELECT 1 FROM dm_conversations 
     WHERE id = ? AND (user1_id = ? OR user2_id = ?)`,
    [conversationId, userId, userId],
    (err, row) => {
      if (err) {
        console.error('Database error verifying DM conversation access:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) return res.status(403).json({ error: 'Not authorized to access this conversation' });
      
      let query = `
        SELECT m.id, m.channel_id, m.dm_conversation_id, m.user_id, m.content, m.reply_to, 
               m.is_edited, m.edited_at, m.moderator_comment, m.created_at,
               u.nickname, u.ordinal, u.profile_pic, u.status
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.dm_conversation_id = ?
      `;
      
      const params = [conversationId];
      
      if (before) {
        query += ` AND m.id < ?`;
        params.push(before);
      } else if (after) { // New condition for polling
        query += ` AND m.id > ?`;
        params.push(after);
      }
      
      query += `
        ORDER BY m.id ASC
        LIMIT ?
      `;
      params.push(limit);
      
      db.all(query, params, async (err, messages) => {
        if (err) {
          console.error('Database error fetching DM messages:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        // Fetch reactions for each message
        for (const msg of messages) {
          msg.userIdentifier = `${msg.nickname}-itl${msg.ordinal.toString().padStart(4, '0')}`;
          if (msg.status === 'hibernating') {
            msg.content = `🛏️ ${msg.content} 🛏️`;
          }
          
          const reactions = await new Promise((resolve, reject) => {
            db.all(`SELECT emoji, user_id FROM reactions WHERE message_id = ?`, [msg.id], (err, rows) => {
              if (err) reject(err);
              else resolve(rows);
            });
          });
          msg.reactions = reactions; // Store as array of {emoji, user_id}
        }
        
        res.json(messages); // Return messages in chronological order
      });
    }
  );
});

// Server Settings Routes
app.get('/api/servers/:serverId/settings', authenticateToken, (req, res) => {
  const serverId = req.params.serverId;
  const userId = req.user.userId;
  
  // Verify user is server owner or admin
  db.get(
    `SELECT 1 FROM servers WHERE id = ? AND owner_id = ?`,
    [serverId, userId],
    (err, row) => {
      if (err) {
        console.error('Database error checking server ownership for settings:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row && !req.user.isAdmin) return res.status(403).json({ error: 'Not authorized to view server settings' });
      
      db.get(
        `SELECT * FROM server_settings WHERE server_id = ?`,
        [serverId],
        (err, settings) => {
          if (err) {
            console.error('Database error fetching server settings:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          
          res.json(settings || {});
        }
      );
    }
  );
});

app.put('/api/servers/:serverId/settings', authenticateToken, (req, res) => {
  const serverId = req.params.serverId;
  const userId = req.user.userId;
  const { default_channel_id, join_permissions, allow_public_join, require_verification } = req.body;
  
  // Verify user is server owner or admin
  db.get(
    `SELECT 1 FROM servers WHERE id = ? AND owner_id = ?`,
    [serverId, userId],
    (err, row) => {
      if (err) {
        console.error('Database error checking server ownership for settings update:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row && !req.user.isAdmin) return res.status(403).json({ error: 'Not authorized to update server settings' });
      
      db.run(
        `INSERT OR REPLACE INTO server_settings 
         (server_id, default_channel_id, join_permissions, allow_public_join, require_verification)
         VALUES (?, ?, ?, ?, ?)`,
        [serverId, default_channel_id || null, join_permissions || 'code', allow_public_join || false, require_verification || false],
        function(err) {
          if (err) {
            console.error('Failed to update server settings:', err);
            return res.status(500).json({ error: 'Failed to update settings' });
          }
          
          res.json({ message: 'Settings updated' });
        }
      );
    }
  );
});

// User Settings Routes
app.get('/api/user/:userId/settings', authenticateToken, (req, res) => {
  const userId = req.params.userId;
  
  // Verify user can only access their own settings
  if (userId !== req.user.userId.toString()) {
    return res.status(403).json({ error: 'Not authorized' });
  }
  
  db.get(
    `SELECT * FROM user_settings WHERE user_id = ?`,
    [userId],
    (err, settings) => {
      if (err) {
        console.error('Database error fetching user settings:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json(settings || {});
    }
  );
});

app.put('/api/user/:userId/settings', authenticateToken, (req, res) => {
  const userId = req.params.userId;
  
  // Verify user can only update their own settings
  if (userId !== req.user.userId.toString()) {
    return res.status(403).json({ error: 'Not authorized' });
  }
  
  const { theme, notifications_enabled, privacy_profile, show_online_status, allow_friend_requests, allow_dms } = req.body;
  
  db.run(
    `INSERT OR REPLACE INTO user_settings 
     (user_id, theme, notifications_enabled, privacy_profile, show_online_status, allow_friend_requests, allow_dms)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId, theme || 'dark', notifications_enabled, privacy_profile || 'public', show_online_status, allow_friend_requests, allow_dms],
    function(err) {
      if (err) {
        console.error('Failed to update user settings:', err);
        return res.status(500).json({ error: 'Failed to update settings' });
      }
      
      res.json({ message: 'Settings updated' });
    }
  );
});

// Serve frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Cleanup inactive connections
setInterval(() => {
  const now = new Date().getTime();
  const timeout = 5 * 60 * 1000; // 5 minutes
  
  activeConnections.forEach((ws, userId) => {
    db.get(
      `SELECT last_seen FROM users WHERE id = ?`,
      [userId],
      (err, user) => {
        if (err || !user) return;
        
        const lastSeen = new Date(user.last_seen).getTime();
        if (now - lastSeen > timeout) {
          ws.close();
          activeConnections.delete(userId);
          updateUserStatus(userId, 'offline');
        }
      }
    );
  });
}, 60 * 1000); // Run every minute

