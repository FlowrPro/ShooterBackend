// ===========================
// Moborr.io Server (Auth + Characters)
// ===========================

import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

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
// AUTH ROUTES (unchanged behavior)
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
// CHARACTER ENDPOINTS (new)
// - GET /characters         -> returns array length 3 with character objects or null for empty slots
// - POST /characters        -> create/update a character in a slot for the authenticated user
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

    // produce array of length 3 (slots 0..2)
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

    // Check if a character already exists in that slot for this user
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
      // Update
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
      // Insert
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
// HEALTH CHECK
// ============================================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Moborr server running (game disabled)',
    playersOnline: 0
  });
});

// Start server (no WebSocket)
app.listen(PORT, () => {
  console.log(`🚀 Moborr Server running on http://localhost:${PORT}`);
});
