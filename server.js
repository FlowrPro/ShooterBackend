// ===========================
// Moborr.io Server (Auth + Characters + Game)
// ===========================

import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';

const app = express();
const PORT = process.env.PORT || 3000;

// Secrets
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

// ----------------------------
// Helper: authenticate middleware
// ----------------------------
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.userId, username: decoded.username };
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============================================
// AUTH ROUTES
// ============================================

app.post('/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('username', username)
      .maybeSingle();

    if (existingUser) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

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

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

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
// CHARACTER ENDPOINTS
// ============================================

app.get('/characters', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('characters')
      .select('*')
      .eq('user_id', req.user.id)
      .order('slot', { ascending: true });

    if (error) {
      console.error('Supabase select characters error:', error);
      return res.status(500).json({ error: 'Failed to fetch characters' });
    }

    const slots = [null, null, null];
    (data || []).forEach((c) => {
      if (typeof c.slot === 'number' && c.slot >= 0 && c.slot <= 2) {
        slots[c.slot] = c;
      }
    });

    return res.json({ characters: slots });
  } catch (err) {
    console.error('GET /characters error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/characters', authenticate, async (req, res) => {
  try {
    const { slot, name, avatar } = req.body;

    if (typeof slot !== 'number' || slot < 0 || slot > 2) {
      return res.status(400).json({ error: 'Invalid slot (must be 0,1,2)' });
    }

    if (!name || typeof name !== 'string' || name.trim().length < 2) {
      return res.status(400).json({ error: 'Invalid name (min 2 characters)' });
    }

    const trimmedName = name.trim();

    const { data: existing, error: selectErr } = await supabase
      .from('characters')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('slot', slot)
      .maybeSingle();

    if (selectErr) {
      console.error('Supabase select character error:', selectErr);
      return res.status(500).json({ error: 'Failed to check existing character' });
    }

    if (existing) {
      const { data: updated, error: updateErr } = await supabase
        .from('characters')
        .update({ name: trimmedName, avatar: avatar ?? existing.avatar, updated_at: new Date() })
        .eq('id', existing.id)
        .select()
        .single();

      if (updateErr) {
        console.error('Supabase update character error:', updateErr);
        return res.status(500).json({ error: 'Failed to update character' });
      }

      return res.json({ character: updated });
    } else {
      const insertPayload = {
        user_id: req.user.id,
        slot,
        name: trimmedName,
        avatar: avatar ?? '😎'
      };

      const { data: created, error: insertErr } = await supabase
        .from('characters')
        .insert([insertPayload])
        .select()
        .single();

      if (insertErr) {
        console.error('Supabase insert character error:', insertErr);
        return res.status(500).json({ error: 'Failed to create character' });
      }

      return res.status(201).json({ character: created });
    }
  } catch (err) {
    console.error('POST /characters error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// GAME CONFIG & STATE
// ============================================

const GAME_CONFIG = {
  MAP_WIDTH: 50000,
  MAP_HEIGHT: 50000,
  PLAYER_RADIUS: 25,
  PLAYER_SPEED: 7,
  TICK_RATE: 60,
  TICK_DURATION: 1000 / 60
};

const players = new Map(); // playerId -> { id, username, x, y, inputState, ws, characterName }

// ============================================
// HTTP SERVER + WEBSOCKET
// ============================================

const server = createServer(app);
const wss = new WebSocketServer({ server });

function updatePlayerPhysics() {
  players.forEach((player) => {
    const input = player.inputState;
    const speed = GAME_CONFIG.PLAYER_SPEED;

    if (input.w) {
      player.y = Math.max(GAME_CONFIG.PLAYER_RADIUS, player.y - speed);
    }
    if (input.s) {
      player.y = Math.min(GAME_CONFIG.MAP_HEIGHT - GAME_CONFIG.PLAYER_RADIUS, player.y + speed);
    }
    if (input.a) {
      player.x = Math.max(GAME_CONFIG.PLAYER_RADIUS, player.x - speed);
    }
    if (input.d) {
      player.x = Math.min(GAME_CONFIG.MAP_WIDTH - GAME_CONFIG.PLAYER_RADIUS, player.x + speed);
    }
  });
}

function broadcastGameState() {
  const gameState = {
    type: 'playerUpdate',
    players: Array.from(players.values()).map((p) => ({
      id: p.id,
      username: p.username,
      characterName: p.characterName,
      x: p.x,
      y: p.y,
      avatar: p.avatar
    }))
  };

  players.forEach((player) => {
    if (player.ws.readyState === 1) {
      player.ws.send(JSON.stringify(gameState));
    }
  });
}

function gameServerLoop() {
  updatePlayerPhysics();
  broadcastGameState();
}

setInterval(gameServerLoop, GAME_CONFIG.TICK_DURATION);

// WebSocket connection handler
wss.on('connection', (ws) => {
  console.log('🟢 New WebSocket connection');

  let player = null;

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data);

      if (message.type === 'join') {
        try {
          const decoded = jwt.verify(message.token, JWT_SECRET);
          const playerId = decoded.userId;

          if (players.has(playerId)) {
            player = players.get(playerId);
            player.ws = ws;
          } else {
            player = {
              id: playerId,
              username: message.username,
              characterName: message.characterName,
              avatar: message.avatar,
              x: GAME_CONFIG.MAP_WIDTH / 2 + Math.random() * 200 - 100,
              y: GAME_CONFIG.MAP_HEIGHT / 2 + Math.random() * 200 - 100,
              inputState: { w: false, a: false, s: false, d: false },
              ws
            };
            players.set(playerId, player);
          }

          const gameState = {
            type: 'gameState',
            config: GAME_CONFIG,
            you: {
              id: player.id,
              username: player.username,
              characterName: player.characterName,
              x: player.x,
              y: player.y,
              avatar: player.avatar
            },
            players: Array.from(players.values())
              .filter((p) => p.id !== playerId)
              .map((p) => ({
                id: p.id,
                username: p.username,
                characterName: p.characterName,
                x: p.x,
                y: p.y,
                avatar: p.avatar
              }))
          };

          ws.send(JSON.stringify(gameState));

          const joinMessage = {
            type: 'playerJoined',
            playerId: player.id,
            username: player.username,
            characterName: player.characterName,
            x: player.x,
            y: player.y,
            avatar: player.avatar
          };

          players.forEach((p) => {
            if (p.id !== playerId && p.ws.readyState === 1) {
              p.ws.send(JSON.stringify(joinMessage));
            }
          });

          console.log(`✅ Player ${player.characterName} (${player.username}) joined. Total: ${players.size}`);
        } catch (error) {
          console.error('Token verification failed:', error);
          ws.close(1008, 'Unauthorized');
        }
      } else if (message.type === 'move') {
        if (player) {
          player.inputState = {
            w: message.w === true,
            a: message.a === true,
            s: message.s === true,
            d: message.d === true
          };
        }
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  });

  ws.on('close', () => {
    if (player) {
      console.log(`👋 Player ${player.characterName} (${player.username}) disconnected`);

      const leftMessage = {
        type: 'playerLeft',
        playerId: player.id
      };

      players.forEach((p) => {
        if (p.id !== player.id && p.ws.readyState === 1) {
          p.ws.send(JSON.stringify(leftMessage));
        }
      });

      players.delete(player.id);
    }
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Moborr server running',
    playersOnline: players.size
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`🚀 Moborr Server running on http://localhost:${PORT}`);
  console.log(`📡 WebSocket available at ws://localhost:${PORT}`);
});
