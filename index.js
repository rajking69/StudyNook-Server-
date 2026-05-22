const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { jwtVerify, createRemoteJWKSet } = require('jose');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

dotenv.config();

const isProduction = process.env.NODE_ENV === 'production';

const app = express();
if (isProduction) {
  app.set('trust proxy', 1);
}
const port = process.env.PORT || 5000;
const clientOrigin =
  process.env.CLIENT_ORIGIN ||
  process.env.CLIENT_URL ||
  'http://localhost:3000';

app.use(
  cors({
    origin: clientOrigin,
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error('Missing MONGODB_URI environment variable.');
  process.exit(1);
}

const jwtSecret = process.env.JWT_SECRET || 'dev-secret-change-me';
if (jwtSecret === 'dev-secret-change-me') {
  console.warn('Warning: JWT_SECRET is not set. Using a development fallback.');
}

const betterAuthBaseUrl = (
  process.env.BETTER_AUTH_URL ||
  process.env.CLIENT_ORIGIN ||
  'http://localhost:3000'
).replace(/\/$/, '');

let betterAuthJwks = null;

const getBetterAuthJwks = () => {
  if (!betterAuthJwks) {
    betterAuthJwks = createRemoteJWKSet(
      new URL(`${betterAuthBaseUrl}/api/auth/jwks`)
    );
  }
  return betterAuthJwks;
};

if (isProduction) {
  console.log('Production mode: auth cookies use secure=true (HTTPS required).');
}

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

/** Challenge 7.1 - JWT in HTTP-only cookie (httpOnly, secure in prod, sameSite strict in prod). */
const authCookieOptions = {
  httpOnly: true,
  sameSite: isProduction ? 'strict' : 'lax',
  secure: isProduction,
  maxAge: 1000 * 60 * 60 * 24 * 7,
  path: '/',
};

const clearAuthCookieOptions = {
  httpOnly: authCookieOptions.httpOnly,
  sameSite: authCookieOptions.sameSite,
  secure: authCookieOptions.secure,
  path: authCookieOptions.path,
};

const createToken = (user) => {
  const userId = user?._id ? user._id.toString() : user?.id;
  if (!userId || typeof userId !== 'string') {
    throw new Error('Cannot issue token without a valid user id.');
  }
  return jwt.sign({ userId }, jwtSecret, { expiresIn: '7d' });
};

const setAuthCookie = (res, user) => {
  const token = createToken(user);
  res.cookie('token', token, authCookieOptions);
};

const clearAuthCookie = (res) => {
  res.clearCookie('token', clearAuthCookieOptions);
};

const hasPasswordHash = (user) =>
  typeof user?.passwordHash === 'string' && user.passwordHash.length > 0;

const validatePasswordRules = (password) => {
  if (password.length < 6) {
    return 'Password must be at least 6 characters.';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password must include at least one uppercase letter.';
  }
  if (!/[a-z]/.test(password)) {
    return 'Password must include at least one lowercase letter.';
  }
  return null;
};

const sanitizeUser = (user) => ({
  id: user?._id != null ? String(user._id) : '',
  name: user.name,
  email: user.email,
  photoURL: user.photoURL || null,
  hasPassword: hasPasswordHash(user),
});

const ownerIdMatches = (ownerId, userId) =>
  ownerId != null &&
  userId != null &&
  String(ownerId).trim() === String(userId).trim();

const parseObjectId = (value) => {
  try {
    return new ObjectId(value);
  } catch {
    return null;
  }
};

const findUserById = async (collection, idValue) => {
  if (idValue === undefined || idValue === null) {
    return null;
  }
  const idString = String(idValue).trim();
  if (!idString) {
    return null;
  }

  const objectId = parseObjectId(idString);
  if (objectId) {
    const byObjectId = await collection.findOne({ _id: objectId });
    if (byObjectId) {
      return byObjectId;
    }
  }

  return collection.findOne({ _id: idString });
};

const extractBearerToken = (req) => {
  const header = req.headers.authorization;
  if (typeof header === 'string' && header.startsWith('Bearer ')) {
    return header.slice(7).trim();
  }
  return null;
};

/** Challenge 7.1 — Express JWT from httpOnly `token` cookie. */
const verifyExpressJwt = (token) => {
  const decoded = jwt.verify(token, jwtSecret);
  const userId = decoded?.userId;
  if (!userId || typeof userId !== 'string') {
    return null;
  }
  return userId;
};

/** Better Auth JWT plugin — verified via JWKS (no DB hit). */
const verifyBetterAuthJwt = async (token) => {
  const { payload } = await jwtVerify(token, getBetterAuthJwks(), {
    issuer: betterAuthBaseUrl,
    audience: betterAuthBaseUrl,
  });
  return payload;
};

const resolveExpressUserId = async (payload, usersCollection) => {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const email =
    typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : '';
  if (email) {
    const byEmail = await usersCollection.findOne({ email });
    if (byEmail?._id != null) {
      return String(byEmail._id);
    }
  }

  const idCandidates = [payload.userId, payload.sub, payload.id].filter(Boolean);
  for (const candidate of idCandidates) {
    const user = await findUserById(usersCollection, candidate);
    if (user?._id != null) {
      return String(user._id);
    }
  }

  return null;
};

/**
 * Auth middleware: verify Express `token` cookie and/or Bearer JWT.
 * 1) httpOnly cookie `token` (Express JWT, Challenge 7.1)
 * 2) Authorization: Bearer <Express JWT | Better Auth JWT>
 */
const createAuthMiddleware = (usersCollection) => async (req, res, next) => {
  try {
    const cookieToken = req.cookies?.token;
    if (cookieToken && typeof cookieToken === 'string') {
      try {
        const userId = verifyExpressJwt(cookieToken);
        if (userId) {
          req.user = { id: userId };
          return next();
        }
      } catch {
        /* fall through */
      }
    }

    const bearerToken = extractBearerToken(req);
    if (bearerToken) {
      try {
        const userId = verifyExpressJwt(bearerToken);
        if (userId) {
          req.user = { id: userId };
          return next();
        }
      } catch {
        /* not an Express JWT — try Better Auth */
      }

      try {
        const payload = await verifyBetterAuthJwt(bearerToken);
        const userId = await resolveExpressUserId(payload, usersCollection);
        if (userId) {
          req.user = { id: userId };
          return next();
        }
      } catch {
        /* invalid Better Auth JWT */
      }
    }

    return res.status(401).send({ message: 'Unauthorized' });
  } catch (err) {
    return next(err);
  }
};

let authMiddleware = (req, res, next) =>
  res.status(503).send({ message: 'Server is starting.' });

const parseDate = (value) => {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed;
};

const parseNumber = (value) => {
  if (value === undefined || value === null || value === '') {
    return null;
  }
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
};

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Rooms seeded/imported with string _id; user-created rooms use ObjectId. */
const findRoomById = async (collection, idValue) => {
  if (idValue === undefined || idValue === null) {
    return null;
  }
  const idString = String(idValue).trim();
  if (!idString) {
    return null;
  }

  const objectId = parseObjectId(idString);
  if (objectId) {
    const byObjectId = await collection.findOne({ _id: objectId });
    if (byObjectId) {
      return byObjectId;
    }
  }

  return collection.findOne({ _id: idString });
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

async function start() {
  await client.connect();
  const db = client.db(process.env.DB_NAME || 'StudyNook');
  const roomsCollection = db.collection(process.env.ROOMS_COLLECTION || 'rooms');
  const usersCollection = db.collection('users');
  const bookingsCollection = db.collection(process.env.BOOKINGS_COLLECTION || 'bookings');

  authMiddleware = createAuthMiddleware(usersCollection);
  console.log(`Auth: Express JWT cookie + Bearer (JWKS ${betterAuthBaseUrl}/api/auth/jwks)`);

  await roomsCollection.createIndex({ name: 1 });
  await bookingsCollection.createIndex({ roomId: 1, startAt: 1, endAt: 1 });
  await usersCollection.createIndex({ email: 1 }, { unique: true });

  await roomsCollection.updateMany(
    { bookingCount: { $exists: false } },
    { $set: { bookingCount: 0 } }
  );
  await roomsCollection.updateMany(
    { roomName: { $exists: true }, name: { $exists: false } },
    [
      {
        $set: {
          name: '$roomName',
          location: '$floor',
          pricePerHour: '$hourlyRate',
          bookingCount: { $ifNull: ['$bookingCount', 0] },
        },
      },
    ]
  );
  await usersCollection.updateMany(
    { bookings: { $exists: false } },
    { $set: { bookings: [] } }
  );

  app.get('/', (req, res) => {
    res.send('StudyNook API is running');
  });

  const buildRoomsQuery = (query) => {
    const filters = [];

    const search = typeof query.search === 'string' ? query.search.trim() : '';
    if (search) {
      const safe = escapeRegex(search);
      filters.push({
        $or: [
          { name: { $regex: safe, $options: 'i' } },
          { roomName: { $regex: safe, $options: 'i' } },
        ],
      });
    }

    const amenitiesParam = typeof query.amenities === 'string' ? query.amenities : '';
    const amenities = amenitiesParam
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    if (amenities.length) {
      filters.push({
        $or: [
          { amenities: { $in: amenities } },
          { features: { $in: amenities } },
        ],
      });
    }

    const floor = typeof query.floor === 'string' ? query.floor.trim() : '';
    if (floor) {
      const safe = escapeRegex(floor);
      filters.push({
        $or: [
          { location: { $regex: safe, $options: 'i' } },
          { floor: { $regex: safe, $options: 'i' } },
        ],
      });
    }

    const minRate = parseNumber(query.minRate);
    const maxRate = parseNumber(query.maxRate);
    if (minRate !== null || maxRate !== null) {
      const range = {};
      if (minRate !== null) range.$gte = minRate;
      if (maxRate !== null) range.$lte = maxRate;
      filters.push({
        $or: [{ pricePerHour: range }, { hourlyRate: range }],
      });
    }

    return filters.length ? { $and: filters } : {};
  };

  const handleRoomsList = asyncHandler(async (req, res) => {
    const parsedLimit = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(parsedLimit) ? parsedLimit : 0;
    const sort = req.query.sort === 'latest'
      ? { createdAt: -1 }
      : { name: 1 };
    const query = buildRoomsQuery(req.query);
    const rooms = await roomsCollection.find(query).sort(sort).limit(limit).toArray();
    res.send(rooms);
  });

  app.get('/rooms', handleRoomsList);
  app.get('/api/rooms', handleRoomsList);

  const getMyRoomsHandler = asyncHandler(async (req, res) => {
    const userId = String(req.user.id).trim();
    const ownerFilter = { $or: [{ createdBy: userId }] };
    const objectId = parseObjectId(userId);
    if (objectId) {
      ownerFilter.$or.push({ createdBy: objectId });
    }
    const rooms = await roomsCollection
      .find(ownerFilter)
      .sort({ createdAt: -1 })
      .toArray();
    res.send(rooms);
  });

  // Register /mine before /:id — otherwise Express treats "mine" as a room id.
  app.get('/rooms/mine', authMiddleware, getMyRoomsHandler);
  app.get('/api/rooms/mine', authMiddleware, getMyRoomsHandler);

  const getRoomById = asyncHandler(async (req, res) => {
    const room = await findRoomById(roomsCollection, req.params.id);
    if (!room) {
      return res.status(404).send({ message: 'Room not found.' });
    }
    res.send(room);
  });

  app.get('/rooms/:id', getRoomById);
  app.get('/api/rooms/:id', getRoomById);

  const createRoomHandler = asyncHandler(async (req, res) => {
    const {
      name,
      capacity,
      location,
      description,
      features,
      image,
      pricePerHour,
      noiseLevel,
      amenities,
    } = req.body;

    const nameValue = typeof name === 'string' ? name.trim() : '';
    const locationValue = typeof location === 'string' ? location.trim() : '';
    const imageValue = typeof image === 'string' ? image.trim() : '';
    const descriptionValue = typeof description === 'string' ? description.trim() : '';
    const capacityValue = parseNumber(capacity);
    const priceValue = parseNumber(pricePerHour);
    const noiseValue = typeof noiseLevel === 'string' && noiseLevel.trim()
      ? noiseLevel.trim()
      : 'Quiet';

    if (!nameValue || !locationValue) {
      return res
        .status(400)
        .send({ message: 'Room name and location are required.' });
    }
    if (!imageValue) {
      return res.status(400).send({ message: 'Room image URL is required.' });
    }

    const room = {
      name: nameValue,
      capacity: capacityValue,
      location: locationValue,
      description: descriptionValue,
      features: Array.isArray(features) ? features : [],
      amenities: Array.isArray(amenities) ? amenities : [],
      noiseLevel: noiseValue,
      image: imageValue,
      pricePerHour: priceValue,
      bookingCount: 0,
      createdAt: new Date(),
      createdBy: req.user.id,
    };

    const result = await roomsCollection.insertOne(room);
    res.status(201).send({ ...room, _id: result.insertedId });
  });

  app.post('/rooms', authMiddleware, createRoomHandler);
  app.post('/api/rooms', authMiddleware, createRoomHandler);

  const updateRoomHandler = asyncHandler(async (req, res) => {
    const existing = await findRoomById(roomsCollection, req.params.id);
    if (!existing) {
      return res.status(404).send({ message: 'Room not found.' });
    }
    if (!ownerIdMatches(existing.createdBy, req.user.id)) {
      return res.status(403).send({ message: 'You are not the owner of this room.' });
    }

    const {
      name, capacity, location, description,
      features, image, pricePerHour, noiseLevel, amenities,
    } = req.body;

    const updates = { updatedAt: new Date() };

    if (typeof name === 'string') {
      updates.name = name.trim();
    }
    if (typeof location === 'string') {
      updates.location = location.trim();
    }
    if (typeof description === 'string') {
      updates.description = description.trim();
    }
    if (typeof image === 'string') {
      updates.image = image.trim();
    }
    if (capacity !== undefined) {
      updates.capacity = parseNumber(capacity);
    }
    if (pricePerHour !== undefined) {
      updates.pricePerHour = parseNumber(pricePerHour);
    }
    if (typeof noiseLevel === 'string') {
      updates.noiseLevel = noiseLevel.trim() || 'Quiet';
    }
    if (Array.isArray(features)) {
      updates.features = features;
    }
    if (Array.isArray(amenities)) {
      updates.amenities = amenities;
    }

    await roomsCollection.updateOne({ _id: existing._id }, { $set: updates });
    const updated = await roomsCollection.findOne({ _id: existing._id });
    res.send(updated);
  });

  app.put('/rooms/:id', authMiddleware, updateRoomHandler);
  app.put('/api/rooms/:id', authMiddleware, updateRoomHandler);

  const deleteRoomHandler = asyncHandler(async (req, res) => {
    const existing = await findRoomById(roomsCollection, req.params.id);
    if (!existing) {
      return res.status(404).send({ message: 'Room not found.' });
    }
    if (!ownerIdMatches(existing.createdBy, req.user.id)) {
      return res.status(403).send({ message: 'You are not the owner of this room.' });
    }

    const roomIdKey = String(existing._id);
    await bookingsCollection.deleteMany({ roomId: roomIdKey });
    await roomsCollection.deleteOne({ _id: existing._id });
    res.send({ message: 'Room deleted successfully.' });
  });

  app.delete('/rooms/:id', authMiddleware, deleteRoomHandler);
  app.delete('/api/rooms/:id', authMiddleware, deleteRoomHandler);

  app.post('/auth/register', asyncHandler(async (req, res) => {
    const { name, email, password, photoURL } = req.body;
    const nameValue = typeof name === 'string' ? name.trim() : '';
    const emailValue = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const passwordValue = typeof password === 'string' ? password : '';
    const photoValue = typeof photoURL === 'string' ? photoURL.trim() : '';

    if (!nameValue || !emailValue || !passwordValue) {
      return res
        .status(400)
        .send({ message: 'Name, email, and password are required.' });
    }
    const passwordError = validatePasswordRules(passwordValue);
    if (passwordError) {
      return res.status(400).send({ message: passwordError });
    }

    const existingUser = await usersCollection.findOne({ email: emailValue });
    if (existingUser) {
      if (!hasPasswordHash(existingUser)) {
        const passwordHash = await bcrypt.hash(passwordValue, 10);
        const linkUpdates = { passwordHash, updatedAt: new Date() };
        if (nameValue && (!existingUser.name || existingUser.name === 'Google User')) {
          linkUpdates.name = nameValue;
        }
        if (!existingUser.photoURL) {
          linkUpdates.photoURL = photoValue;
        }
        await usersCollection.updateOne(
          { _id: existingUser._id },
          { $set: linkUpdates }
        );
        return res.status(200).send({
          message: 'Password linked. Please login.',
          linked: true,
        });
      }
      return res.status(409).send({ message: 'Email already registered.' });
    }

    const passwordHash = await bcrypt.hash(passwordValue, 10);
    const newUser = {
      name: nameValue,
      email: emailValue,
      photoURL: photoValue || null,
      passwordHash,
      bookings: [],
      createdAt: new Date(),
    };

    await usersCollection.insertOne(newUser);
    res.status(201).send({ message: 'Registration successful! Please login.' });
  }));

  app.post('/auth/login', asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const emailValue = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const passwordValue = typeof password === 'string' ? password : '';

    if (!emailValue || !passwordValue) {
      return res
        .status(400)
        .send({ message: 'Email and password are required.' });
    }

    const user = await usersCollection.findOne({ email: emailValue });
    if (!user) {
      return res.status(401).send({ message: 'Invalid credentials.' });
    }

    if (!hasPasswordHash(user)) {
      return res.status(401).send({
        code: 'GOOGLE_ONLY',
        message:
          'No password on this account. Use Continue with Google, or add one on Register with this email.',
      });
    }

    const isValid = await bcrypt.compare(passwordValue, user.passwordHash);
    if (!isValid) {
      return res.status(401).send({ message: 'Invalid credentials.' });
    }

    setAuthCookie(res, user);
    res.send(sanitizeUser(user));
  }));

  app.post('/auth/logout', (req, res) => {
    clearAuthCookie(res);
    res.send({ message: 'Logged out' });
  });

  app.post('/auth/google', asyncHandler(async (req, res) => {
    const { name, email, photoURL, uid } = req.body;
    const emailValue = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const nameValue = typeof name === 'string' && name.trim() ? name.trim() : '';
    const photoValue = typeof photoURL === 'string' && photoURL.trim() ? photoURL.trim() : '';

    if (!emailValue) {
      return res.status(400).send({ message: 'Email is required.' });
    }
    const normalizedEmail = emailValue;

    try {
      let existing = await usersCollection.findOne({ email: normalizedEmail });
      if (existing) {
        const linkUpdates = { updatedAt: new Date() };
        if (uid && !existing.googleUid) {
          linkUpdates.googleUid = uid;
        }
        if (photoValue && !existing.photoURL) {
          linkUpdates.photoURL = photoValue;
        }
        if (nameValue && (!existing.name || existing.name === 'Google User')) {
          linkUpdates.name = nameValue;
        }
        if (Object.keys(linkUpdates).length > 1) {
          await usersCollection.updateOne(
            { _id: existing._id },
            { $set: linkUpdates }
          );
          existing = await usersCollection.findOne({ _id: existing._id });
        }
        setAuthCookie(res, existing);
        return res.send(sanitizeUser(existing));
      }

      const newUser = {
        name: nameValue || 'Google User',
        email: normalizedEmail,
        photoURL: photoValue || null,
        googleUid: uid || null,
        bookings: [],
        createdAt: new Date(),
      };

      const result = await usersCollection.insertOne(newUser);
      const user = { ...newUser, _id: result.insertedId };

      setAuthCookie(res, user);
      return res.send(sanitizeUser(user));
    } catch (err) {
      if (err?.code === 11000) {
        let existing = await usersCollection.findOne({ email: normalizedEmail });
        if (existing) {
          const linkUpdates = { updatedAt: new Date() };
          if (uid && !existing.googleUid) linkUpdates.googleUid = uid;
          if (photoValue && !existing.photoURL) linkUpdates.photoURL = photoValue;
          if (nameValue && (!existing.name || existing.name === 'Google User')) {
            linkUpdates.name = nameValue;
          }
          if (Object.keys(linkUpdates).length > 1) {
            await usersCollection.updateOne(
              { _id: existing._id },
              { $set: linkUpdates }
            );
            existing = await usersCollection.findOne({ _id: existing._id });
          }
          setAuthCookie(res, existing);
          return res.send(sanitizeUser(existing));
        }
      }
      console.error('Google auth error:', err);
      res.status(500).send({ message: 'Google sign-in failed. Please try again.' });
    }
  }));

  app.get('/auth/me', authMiddleware, asyncHandler(async (req, res) => {
    const user = await findUserById(usersCollection, req.user.id);
    if (!user) {
      return res.status(404).send({ message: 'User not found.' });
    }
    res.send(sanitizeUser(user));
  }));

  app.patch('/auth/me', authMiddleware, asyncHandler(async (req, res) => {
    const existingUser = await findUserById(usersCollection, req.user.id);
    if (!existingUser) {
      return res.status(404).send({ message: 'User not found.' });
    }
    const userId = existingUser._id;

    const { name, photoURL } = req.body;
    const updates = {};

    if (typeof name === 'string' && name.trim()) {
      updates.name = name.trim();
    }

    if (typeof photoURL === 'string') {
      updates.photoURL = photoURL.trim() || null;
    }

    if (!Object.keys(updates).length) {
      return res.status(400).send({ message: 'No profile updates provided.' });
    }

    updates.updatedAt = new Date();

    await usersCollection.updateOne({ _id: userId }, { $set: updates });

    const user = await usersCollection.findOne({ _id: userId });
    if (!user) {
      return res.status(404).send({ message: 'User not found.' });
    }
    res.send(sanitizeUser(user));
  }));

  app.post('/auth/set-password', authMiddleware, asyncHandler(async (req, res) => {
    const { password } = req.body;
    if (!password || typeof password !== 'string') {
      return res.status(400).send({ message: 'Password is required.' });
    }

    const passwordError = validatePasswordRules(password);
    if (passwordError) {
      return res.status(400).send({ message: passwordError });
    }

    const user = await findUserById(usersCollection, req.user.id);
    if (!user) {
      return res.status(404).send({ message: 'User not found.' });
    }
    const userId = user._id;
    if (hasPasswordHash(user)) {
      return res.status(400).send({ message: 'Password already set. Use login to sign in.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await usersCollection.updateOne(
      { _id: userId },
      { $set: { passwordHash, updatedAt: new Date() } }
    );

    const updated = await usersCollection.findOne({ _id: userId });
    res.send(sanitizeUser(updated));
  }));

  const createBookingHandler = asyncHandler(async (req, res) => {
    const { roomId, startAt, endAt, purpose, notes } = req.body;

    if (!roomId || !startAt || !endAt) {
      return res
        .status(400)
        .send({ message: 'Room, start time, and end time are required.' });
    }

    const room = await findRoomById(roomsCollection, roomId);
    if (!room) {
      return res.status(404).send({ message: 'Room not found.' });
    }

    const startDate = parseDate(startAt);
    const endDate = parseDate(endAt);
    if (!startDate || !endDate || endDate <= startDate) {
      return res
        .status(400)
        .send({ message: 'Provide a valid booking time range.' });
    }

    const conflict = await bookingsCollection.findOne({
      roomId,
      status: { $ne: 'cancelled' },
      $or: [
        { startAt: { $gte: startDate, $lte: endDate } },
        { endAt: { $gte: startDate, $lte: endDate } },
        {
          $and: [
            { startAt: { $lte: startDate } },
            { endAt: { $gte: endDate } },
          ],
        },
      ],
    });

    if (conflict) {
      return res
        .status(409)
        .send({ message: 'This room is already booked for that time.' });
    }

    const userId = req.user.id;
    const purposeValue = typeof purpose === 'string' ? purpose.trim() : '';
    const notesValue = typeof notes === 'string' ? notes.trim() : '';

    const booking = {
      roomId,
      roomName: room.name || room.roomName || 'Study Room',
      roomImage: room.image || '',
      startAt: startDate,
      endAt: endDate,
      purpose: purposeValue,
      notes: notesValue,
      userId,
      status: 'confirmed',
      createdAt: new Date(),
    };

    const result = await bookingsCollection.insertOne(booking);
    const bookingId = result.insertedId.toString();

    await Promise.all([
      roomsCollection.updateOne({ _id: room._id }, { $inc: { bookingCount: 1 } }),
      usersCollection.updateOne(
        { _id: new ObjectId(userId) },
        { $push: { bookings: bookingId } }
      ),
    ]);

    res.status(201).send({ ...booking, _id: result.insertedId });
  });

  app.post('/bookings', authMiddleware, createBookingHandler);
  app.post('/api/bookings', authMiddleware, createBookingHandler);

  const getMyBookingsHandler = asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const bookings = await bookingsCollection
      .find({ userId })
      .sort({ startAt: -1 })
      .toArray();

    const roomIds = [
      ...new Set(
        bookings
          .map((b) => (b.roomId !== undefined && b.roomId !== null ? String(b.roomId) : ''))
          .filter(Boolean)
      ),
    ];

    const rooms = roomIds.length
      ? await roomsCollection.find({ _id: { $in: roomIds } }).toArray()
      : [];
    const imageByRoomId = Object.fromEntries(
      rooms.map((r) => [String(r._id), r.image || ''])
    );

    res.send(
      bookings.map((b) => ({
        ...b,
        roomImage: b.roomImage || imageByRoomId[b.roomId] || '',
      }))
    );
  });

  app.get('/bookings/my', authMiddleware, getMyBookingsHandler);
  app.get('/api/bookings/my', authMiddleware, getMyBookingsHandler);

  const cancelBookingHandler = asyncHandler(async (req, res) => {
    const bookingId = parseObjectId(req.params.id);
    if (!bookingId) {
      return res.status(400).send({ message: 'Invalid booking id.' });
    }

    const booking = await bookingsCollection.findOne({ _id: bookingId });
    if (!booking) {
      return res.status(404).send({ message: 'Booking not found.' });
    }
    const userId = req.user.id;
    if (booking.userId !== userId) {
      return res.status(403).send({ message: 'You can only cancel your own bookings.' });
    }
    if (booking.status === 'cancelled') {
      return res.status(400).send({ message: 'Booking is already cancelled.' });
    }

    await bookingsCollection.updateOne(
      { _id: bookingId },
      { $set: { status: 'cancelled', cancelledAt: new Date() } }
    );

    const room = await findRoomById(roomsCollection, booking.roomId);
    const updates = [
      usersCollection.updateOne(
        { _id: new ObjectId(userId) },
        { $pull: { bookings: bookingId.toString() } }
      ),
    ];
    if (room) {
      updates.push(
        roomsCollection.updateOne({ _id: room._id }, { $inc: { bookingCount: -1 } })
      );
    }
    await Promise.all(updates);

    res.send({ message: 'Booking cancelled.' });
  });

  app.patch('/bookings/:id/cancel', authMiddleware, cancelBookingHandler);
  app.patch('/api/bookings/:id/cancel', authMiddleware, cancelBookingHandler);

  app.use((err, req, res, next) => {
    console.error('API error:', err);
    if (res.headersSent) {
      return next(err);
    }
    const status =
      err?.status ||
      err?.statusCode ||
      (err?.code === 11000 ? 409 : 500);

    const message =
      status === 409
        ? 'Duplicate key error.'
        : status >= 400 && status < 500 && err?.message
          ? err.message
          : 'Internal server error.';

    res.status(status).send({ message });
  });

  app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running on port ${port}`);
  });
}

start().catch((err) => {
  console.error('Failed to start server', err);
  process.exit(1);
});