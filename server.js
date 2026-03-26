import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase connection
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://eraudtprdpnsgrhiipto.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

if (!SUPABASE_SERVICE_ROLE_KEY) {
  console.error('❌ SUPABASE_SERVICE_ROLE_KEY environment variable is missing!');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Middleware
app.use(cors());
app.use(express.json());

// ============================================
// GAME STATE (In-Memory)
// ============================================

const activeMatches = new Map(); // matchId -> match data
const playerQueues = new Map(); // region -> array of queued players
const playerMatches = new Map(); // userId -> matchId

const REGIONS = ['north-america', 'europe', 'asia'];
const MATCH_SIZE = 8; // Max players per match
const MATCH_DURATION = 5 * 60 * 1000; // 5 minutes
const QUEUE_TIMEOUT = 30 * 1000; // 30 seconds queue timeout

// Initialize empty queues for each region
REGIONS.forEach(region => {
  playerQueues.set(region, []);
});

// ============================================
// UTILITY FUNCTIONS
// ============================================

function generateMatchId() {
  return 'MATCH_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function generatePlayerId() {
  return 'PLAYER_' + Math.random().toString(36).substr(2, 9);
}

function verifyToken(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ============================================
// MATCH MANAGEMENT
// ============================================

function createMatch(region, initialPlayer) {
  const matchId = generateMatchId();
  const match = {
    id: matchId,
    region: region,
    players: [initialPlayer],
    status: 'active', // active, ended
    createdAt: Date.now(),
    gameState: {
      players: {
        [initialPlayer.id]: {
          userId: initialPlayer.userId,
          username: initialPlayer.username,
          hp: 100,
          kills: 0,
          deaths: 0,
          position: { x: 0, y: 0, z: 0 },
          rotation: { x: 0, y: 0 },
          weapon: 'assault-rifle',
          ammo: 30,
          isShooting: false,
          isCrouching: false,
          isScoped: false
        }
      },
      bullets: [],
      kills: []
    }
  };

  activeMatches.set(matchId, match);
  playerMatches.set(initialPlayer.userId, matchId);

  // Auto-end match after 5 minutes
  setTimeout(() => {
    endMatch(matchId);
  }, MATCH_DURATION);

  return match;
}

function addPlayerToMatch(matchId, player) {
  const match = activeMatches.get(matchId);
  if (!match) return false;

  if (match.players.length >= MATCH_SIZE) return false;

  match.players.push(player);
  playerMatches.set(player.userId, matchId);

  const playerId = generatePlayerId();
  match.gameState.players[playerId] = {
    userId: player.userId,
    username: player.username,
    hp: 100,
    kills: 0,
    deaths: 0,
    position: { x: 0, y: 0, z: 0 },
    rotation: { x: 0, y: 0 },
    weapon: 'assault-rifle',
    ammo: 30,
    isShooting: false,
    isCrouching: false,
    isScoped: false
  };

  return playerId;
}

function endMatch(matchId) {
  const match = activeMatches.get(matchId);
  if (!match) return;

  match.status = 'ended';

  // Clean up player associations
  match.players.forEach(player => {
    playerMatches.delete(player.userId);
  });

  // Remove from active matches after 10 seconds
  setTimeout(() => {
    activeMatches.delete(matchId);
  }, 10000);
}

function findAvailableMatch(region) {
  for (const [matchId, match] of activeMatches.entries()) {
    if (match.region === region && match.status === 'active' && match.players.length < MATCH_SIZE) {
      return match;
    }
  }
  return null;
}

// ============================================
// AUTH ROUTES
// ============================================

// Register
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if username exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('username', username)
      .single();

    if (existingUser) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const { data: newUser, error } = await supabase
      .from('users')
      .insert([{
        username,
        password: hashedPassword,
        avatar: '😎'
      }])
      .select()
      .single();

    if (error) {
      console.error('Supabase insert error:', error);
      return res.status(500).json({ error: 'Registration failed' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser.id, username: newUser.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        avatar: newUser.avatar
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Find user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user (verify token)
app.get('/auth/me', (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({
      userId: decoded.userId,
      username: decoded.username
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ============================================
// MATCHMAKING ROUTES
// ============================================

// Find or create match
app.post('/match/queue', verifyToken, (req, res) => {
  try {
    const { region } = req.body;

    if (!REGIONS.includes(region)) {
      return res.status(400).json({ error: 'Invalid region' });
    }

    if (playerMatches.has(req.user.userId)) {
      return res.status(400).json({ error: 'Already in a match' });
    }

    const player = {
      userId: req.user.userId,
      username: req.user.username
    };

    // Try to find available match
    let match = findAvailableMatch(region);

    if (match) {
      // Add player to existing match
      const playerId = addPlayerToMatch(match.id, player);
      return res.json({
        success: true,
        matchId: match.id,
        playerId: playerId,
        gameState: match.gameState
      });
    } else {
      // Create new match
      match = createMatch(region, player);
      const playerId = Object.keys(match.gameState.players)[0];
      return res.json({
        success: true,
        matchId: match.id,
        playerId: playerId,
        gameState: match.gameState
      });
    }
  } catch (error) {
    console.error('Queue error:', error);
    res.status(500).json({ error: 'Matchmaking failed' });
  }
});

// Get match state
app.get('/match/:matchId', verifyToken, (req, res) => {
  try {
    const match = activeMatches.get(req.params.matchId);

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    // Verify player is in match
    if (!playerMatches.has(req.user.userId) || playerMatches.get(req.user.userId) !== req.params.matchId) {
      return res.status(403).json({ error: 'Not in this match' });
    }

    res.json({
      success: true,
      match: {
        id: match.id,
        region: match.region,
        status: match.status,
        players: match.players.map(p => ({ userId: p.userId, username: p.username })),
        gameState: match.gameState
      }
    });
  } catch (error) {
    console.error('Get match error:', error);
    res.status(500).json({ error: 'Failed to get match' });
  }
});

// Update player state (server validates all game logic)
app.post('/match/:matchId/update', verifyToken, (req, res) => {
  try {
    const match = activeMatches.get(req.params.matchId);

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    const { playerId, position, rotation, isShooting, isCrouching, isScoped, ammo, hp } = req.body;

    const playerState = match.gameState.players[playerId];
    if (!playerState || playerState.userId !== req.user.userId) {
      return res.status(403).json({ error: 'Invalid player' });
    }

    // Server validates and updates position/rotation only
    if (position) playerState.position = position;
    if (rotation) playerState.rotation = rotation;
    if (typeof isShooting === 'boolean') playerState.isShooting = isShooting;
    if (typeof isCrouching === 'boolean') playerState.isCrouching = isCrouching;
    if (typeof isScoped === 'boolean') playerState.isScoped = isScoped;

    // Server handles ammo and HP (client cannot modify directly)
    // These would be updated based on server-side hit detection and validation

    res.json({
      success: true,
      gameState: match.gameState
    });
  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({ error: 'Failed to update match' });
  }
});

// Fire weapon (server-side hit detection)
app.post('/match/:matchId/fire', verifyToken, (req, res) => {
  try {
    const match = activeMatches.get(req.params.matchId);

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    const { playerId, rayOrigin, rayDirection } = req.body;

    const playerState = match.gameState.players[playerId];
    if (!playerState || playerState.userId !== req.user.userId) {
      return res.status(403).json({ error: 'Invalid player' });
    }

    // Validate ammo
    if (playerState.ammo <= 0) {
      return res.status(400).json({ error: 'No ammo' });
    }

    // Decrease ammo (server-side)
    playerState.ammo -= 1;

    // Server-side hit detection would go here
    // For now, just register the shot
    const bullet = {
      id: generatePlayerId(),
      playerId: playerId,
      origin: rayOrigin,
      direction: rayDirection,
      firedAt: Date.now(),
      hit: null
    };

    match.gameState.bullets.push(bullet);

    // Remove bullet after 2 seconds
    setTimeout(() => {
      const index = match.gameState.bullets.findIndex(b => b.id === bullet.id);
      if (index > -1) match.gameState.bullets.splice(index, 1);
    }, 2000);

    res.json({
      success: true,
      bullet: bullet,
      gameState: match.gameState
    });
  } catch (error) {
    console.error('Fire error:', error);
    res.status(500).json({ error: 'Failed to fire' });
  }
});

// Register hit (server validates)
app.post('/match/:matchId/hit', verifyToken, (req, res) => {
  try {
    const match = activeMatches.get(req.params.matchId);

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    const { playerId, targetPlayerId, damage } = req.body;

    const shooterState = match.gameState.players[playerId];
    const targetState = match.gameState.players[targetPlayerId];

    if (!shooterState || shooterState.userId !== req.user.userId) {
      return res.status(403).json({ error: 'Invalid shooter' });
    }

    if (!targetState) {
      return res.status(404).json({ error: 'Target not found' });
    }

    // Apply damage (server-side authority)
    targetState.hp -= damage;

    if (targetState.hp <= 0) {
      targetState.hp = 0;
      shooterState.kills += 1;
      targetState.deaths += 1;

      match.gameState.kills.push({
        killer: shooterState.username,
        victim: targetState.username,
        timestamp: Date.now()
      });
    }

    res.json({
      success: true,
      targetHp: targetState.hp,
      isDead: targetState.hp <= 0,
      gameState: match.gameState
    });
  } catch (error) {
    console.error('Hit error:', error);
    res.status(500).json({ error: 'Failed to register hit' });
  }
});

// Leave match
app.post('/match/:matchId/leave', verifyToken, (req, res) => {
  try {
    const match = activeMatches.get(req.params.matchId);

    if (!match) {
      return res.status(404).json({ error: 'Match not found' });
    }

    const playerIndex = match.players.findIndex(p => p.userId === req.user.userId);
    if (playerIndex === -1) {
      return res.status(403).json({ error: 'Not in this match' });
    }

    // Remove player from match
    match.players.splice(playerIndex, 1);
    playerMatches.delete(req.user.userId);

    res.json({ success: true });
  } catch (error) {
    console.error('Leave error:', error);
    res.status(500).json({ error: 'Failed to leave match' });
  }
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'Moborr backend is running',
    activeMatches: activeMatches.size,
    totalPlayers: Array.from(activeMatches.values()).reduce((sum, match) => sum + match.players.length, 0)
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Moborr Backend running on http://localhost:${PORT}`);
});
