/**
 * server.js
 * Single-file backend for MERN chat app (all functionality in this file).
 *
 * Endpoints:
 *  - POST /api/auth/signup {email, password, displayName}
 *  - POST /api/auth/login {email, password}
 *  - POST /api/auth/logout
 *  - GET  /api/auth/me
 *  - GET  /api/groups
 *  - POST /api/groups { name, isPublic, metadata }
 *  - POST /api/groups/:id/join
 *  - POST /api/groups/:id/leave
 *  - GET  /api/groups/:id/messages
 *  - POST /api/groups/:id/messages { body }
 *
 * Serves static files from ./public (index.html + app.js frontend)
 *
 * Requirements:
 *  - MongoDB connection (MONGODB_URI env var)
 *  - JWT_SECRET env var (or default used for dev)
 *
 * Notes:
 *  - This single-file server is intentionally simple for clarity and demonstration.
 *  - In production, split responsibilities (validation, rate-limit, sanitize, HTTPS, secrets).
 */

const express = require('express');
const http = require('http');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { Server } = require('socket.io');

require('dotenv').config();

const MONGODB_URI = process.env.MONGODB_URI ;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
const PORT = process.env.PORT || 4000;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || `http://localhost:4000`; // static served same host

// ---- Simple config ----
const ACCESS_TOKEN_EXPIRY = '1h'; // access token lifetime

// ---- App init ----
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  // CORS allowed for local testing
  cors: { origin: CLIENT_ORIGIN, credentials: true },
});

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: CLIENT_ORIGIN,
  credentials: true,
}));

// Serve static frontend from ./public
app.use(express.static(path.join(__dirname, 'public')));

// ---- Mongoose Models (single-file) ----
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Mongo connected'))
  .catch(err => {
    console.error('Mongo connection error:', err);
    process.exit(1);
  });

const { Schema, model, Types } = mongoose;

const UserSchema = new Schema({
  email: { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  displayName: { type: String, required: true },
  avatarUrl: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  lastSeenAt: { type: Date, default: Date.now },
});

const GroupSchema = new Schema({
  name: { type: String, required: true },
  creatorId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  isPublic: { type: Boolean, default: true },
  metadata: { type: Schema.Types.Mixed, default: {} },
  memberCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const MembershipSchema = new Schema({
  groupId: { type: Schema.Types.ObjectId, ref: 'Group', required: true, index: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  joinedAt: { type: Date, default: Date.now },
  lastActiveAt: { type: Date, default: Date.now },
});

const MessageSchema = new Schema({
  groupId: { type: Schema.Types.ObjectId, ref: 'Group', required: true, index: true },
  userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  body: { type: String, required: true },
  edited: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

const User = model('User', UserSchema);
const Group = model('Group', GroupSchema);
const Membership = model('Membership', MembershipSchema);
const Message = model('Message', MessageSchema);

// ---- Helper utilities ----
function signToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
}

async function authMiddleware(req, res, next) {
  try {
    // Expect token in Authorization header "Bearer <token>" or cookie "token"
    const auth = req.headers.authorization || '';
    let token = null;
    if (auth.startsWith('Bearer ')) token = auth.slice(7);
    else if (req.cookies && req.cookies.token) token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized: no token' });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.id);
    if (!user) return res.status(401).json({ error: 'Unauthorized: user not found' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized: invalid token' });
  }
}

// ---- Auth routes ----
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, displayName } = req.body;
    if (!email || !password || !displayName) return res.status(400).json({ error: 'Missing fields' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already in use' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = new User({ email, passwordHash, displayName });
    await user.save();
    const token = signToken(user);
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    return res.json({ token, user: { id: user._id, email: user.email, displayName: user.displayName } });
  } catch (err) {
    console.error('Signup error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = signToken(user);
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    await User.findByIdAndUpdate(user._id, { lastSeenAt: new Date() });
    return res.json({ token, user: { id: user._id, email: user.email, displayName: user.displayName } });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  try {
    res.clearCookie('token');
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const u = req.user;
  res.json({ id: u._id, email: u.email, displayName: u.displayName, avatarUrl: u.avatarUrl });
});

// ---- Group & membership endpoints ----

// List public groups
app.get('/api/groups', authMiddleware, async (req, res) => {
  try {
    const groups = await Group.find({ isPublic: true }).sort({ updatedAt: -1 }).lean();
    return res.json(groups);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Create group
app.post('/api/groups', authMiddleware, async (req, res) => {
  try {
    const { name, isPublic = true, metadata = {} } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const group = new Group({
      name,
      creatorId: req.user._id,
      isPublic,
      metadata,
      memberCount: 0,
    });
    await group.save();

    // create membership for creator
    const mem = new Membership({ groupId: group._id, userId: req.user._id });
    await mem.save();
    group.memberCount = 1;
    await group.save();

    // notify clients via socket
    io.emit('group_created', { groupId: group._id.toString(), name: group.name, memberCount: group.memberCount });

    return res.json({ group });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Join group
app.post('/api/groups/:id/join', authMiddleware, async (req, res) => {
  try {
    const groupId = req.params.id;
    if (!Types.ObjectId.isValid(groupId)) return res.status(400).json({ error: 'Invalid group id' });
    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ error: 'Group not found' });

    const existing = await Membership.findOne({ groupId, userId: req.user._id });
    if (existing) return res.json({ ok: true, message: 'Already a member' });

    await Membership.create({ groupId, userId: req.user._id });
    // increment memberCount
    group.memberCount = (group.memberCount || 0) + 1;
    group.updatedAt = new Date();
    await group.save();

    io.to(groupId.toString()).emit('member_joined', { groupId: groupId.toString(), userId: req.user._id.toString(), memberCount: group.memberCount });

    return res.json({ ok: true, groupId, memberCount: group.memberCount });
  } catch (err) {
    console.error('join error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Leave group (explicit leave)
app.post('/api/groups/:id/leave', authMiddleware, async (req, res) => {
  try {
    const groupId = req.params.id;
    if (!Types.ObjectId.isValid(groupId)) return res.status(400).json({ error: 'Invalid group id' });

    const membership = await Membership.findOneAndDelete({ groupId, userId: req.user._id });
    if (!membership) return res.status(400).json({ error: 'Not a member' });

    // decrement memberCount in DB
    const group = await Group.findById(groupId);
    if (!group) {
      // membership removed but group missing -> nothing else
      return res.json({ ok: true });
    }
    group.memberCount = Math.max(0, (group.memberCount || 1) - 1);
    group.updatedAt = new Date();
    await group.save();

    io.emit('member_left', { groupId: groupId.toString(), userId: req.user._id.toString(), memberCount: group.memberCount });

    // if memberCount is zero -> perform deletion after small grace (to reduce race)
    if (group.memberCount === 0) {
      // schedule deletion with small grace to reduce race with simultaneous joins
      setTimeout(async () => {
        try {
          // re-check actual membership count in DB before deleting
          const count = await Membership.countDocuments({ groupId });
          if (count === 0) {
            // delete messages
            await Message.deleteMany({ groupId });
            // delete memberships (ones that may exist)
            await Membership.deleteMany({ groupId });
            // delete group
            await Group.findByIdAndDelete(groupId);
            io.emit('group_deleted', { groupId: groupId.toString() });
            console.log(`Group ${groupId} auto-deleted (no members)`);
          } else {
            // someone rejoined meanwhile; update group count
            const grp = await Group.findById(groupId);
            if (grp) {
              grp.memberCount = count;
              await grp.save();
            }
          }
        } catch (errInner) {
          console.error('Error in auto-delete worker:', errInner);
        }
      }, 3500); // 3.5s grace
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error('leave error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Get messages
app.get('/api/groups/:id/messages', authMiddleware, async (req, res) => {
  try {
    const groupId = req.params.id;
    if (!Types.ObjectId.isValid(groupId)) return res.status(400).json({ error: 'Invalid group id' });

    const messages = await Message.find({ groupId }).sort({ createdAt: 1 }).limit(200).lean();
    return res.json(messages);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Post message
app.post('/api/groups/:id/messages', authMiddleware, async (req, res) => {
  try {
    const groupId = req.params.id;
    const { body } = req.body;
    if (!body || !body.trim()) return res.status(400).json({ error: 'Message empty' });

    if (!Types.ObjectId.isValid(groupId)) return res.status(400).json({ error: 'Invalid group id' });

    // ensure membership
    const member = await Membership.findOne({ groupId, userId: req.user._id });
    if (!member) return res.status(403).json({ error: 'Not a member of group' });

    const message = new Message({ groupId, userId: req.user._id, body });
    await message.save();

    const out = {
      _id: message._id,
      groupId: message.groupId.toString(),
      userId: message.userId.toString(),
      body: message.body,
      createdAt: message.createdAt,
    };

    // broadcast to group room
    io.to(groupId.toString()).emit('message', out);

    return res.json(out);
  } catch (err) {
    console.error('post message error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ---- Socket.IO realtime ----

// Simple in-memory map of socketId -> userId for quick lookup
const socketUser = new Map();

io.use(async (socket, next) => {
  try {
    // Expect token in query.token or cookie
    const token = socket.handshake.auth?.token || (socket.handshake.headers?.cookie && (() => {
      const ck = socket.handshake.headers.cookie.split(';').find(c => c.trim().startsWith('token='));
      return ck ? ck.split('=')[1] : null;
    })());
    if (!token) return next(new Error('Authentication error: missing token'));
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.id);
    if (!user) return next(new Error('Authentication error: user not found'));
    socket.user = { id: user._id.toString(), displayName: user.displayName };
    return next();
  } catch (err) {
    return next(new Error('Authentication error'));
  }
});

io.on('connection', (socket) => {
  const user = socket.user;
  socketUser.set(socket.id, user.id);

  socket.on('join_group', async ({ groupId }) => {
    try {
      if (!Types.ObjectId.isValid(groupId)) {
        socket.emit('error', { message: 'Invalid group id' });
        return;
      }
      const group = await Group.findById(groupId);
      if (!group) {
        socket.emit('error', { message: 'Group not found' });
        return;
      }

      // add membership if not exists
      const exists = await Membership.findOne({ groupId, userId: user.id });
      if (!exists) {
        await Membership.create({ groupId, userId: user.id });
        group.memberCount = (group.memberCount || 0) + 1;
        await group.save();
        io.emit('member_joined', { groupId, userId: user.id, memberCount: group.memberCount });
      }

      socket.join(groupId);
      // load recent messages and send
      const recent = await Message.find({ groupId }).sort({ createdAt: 1 }).limit(200).lean();
      socket.emit('joined', { groupId, recentMessages: recent, userId: user.id, displayName: user.displayName });
    } catch (err) {
      console.error('socket join_group error', err);
      socket.emit('error', { message: 'Join failed' });
    }
  });

  socket.on('leave_group', async ({ groupId }) => {
    try {
      if (!Types.ObjectId.isValid(groupId)) {
        socket.emit('error', { message: 'Invalid group id' });
        return;
      }
      // remove membership
      await Membership.findOneAndDelete({ groupId, userId: user.id });

      const grp = await Group.findById(groupId);
      if (grp) {
        grp.memberCount = Math.max(0, (grp.memberCount || 1) - 1);
        grp.updatedAt = new Date();
        await grp.save();
        io.emit('member_left', { groupId, userId: user.id, memberCount: grp.memberCount });
        // schedule delete if zero
        if (grp.memberCount === 0) {
          setTimeout(async () => {
            try {
              const count = await Membership.countDocuments({ groupId });
              if (count === 0) {
                await Message.deleteMany({ groupId });
                await Membership.deleteMany({ groupId });
                await Group.findByIdAndDelete(groupId);
                io.emit('group_deleted', { groupId });
                console.log(`Group ${groupId} auto-deleted by socket flow`);
              } else {
                const g2 = await Group.findById(groupId);
                if (g2) { g2.memberCount = count; await g2.save(); }
              }
            } catch (e) {
              console.error('socket auto-delete error', e);
            }
          }, 3500);
        }
      }
      socket.leave(groupId);
      socket.emit('left', { groupId });
    } catch (err) {
      console.error('socket leave_group error', err);
      socket.emit('error', { message: 'Leave failed' });
    }
  });

  socket.on('message', async ({ groupId, body }) => {
    try {
      if (!body || !body.trim()) return;
      if (!Types.ObjectId.isValid(groupId)) {
        socket.emit('error', { message: 'Invalid group id' });
        return;
      }
      const member = await Membership.findOne({ groupId, userId: user.id });
      if (!member) {
        socket.emit('error', { message: 'Not a member' });
        return;
      }
      const msg = new Message({ groupId, userId: user.id, body });
      await msg.save();
      const out = {
        _id: msg._id,
        groupId: groupId,
        userId: user.id,
        body: msg.body,
        createdAt: msg.createdAt,
      };
      io.to(groupId).emit('message', out);
    } catch (err) {
      console.error('socket message error', err);
      socket.emit('error', { message: 'Message send failed' });
    }
  });

  socket.on('typing', ({ groupId, isTyping }) => {
    if (groupId) {
      socket.to(groupId).emit('typing', { userId: user.id, displayName: user.displayName, isTyping });
    }
  });

  socket.on('disconnect', async () => {
    try {
      // Optionally: mark last active; we don't remove memberships on disconnect by default.
      socketUser.delete(socket.id);
    } catch (err) {
      // ignore
    }
  });
});

// fallback to index.html for SPA routing
app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
// ---- Start server ----
server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
