const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
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

/**
 * Reads req.cookies.token, verifies JWT, sets req.user = { id: userId }.
 * Private routes: add/list/edit/delete rooms, bookings, cancel, /auth/me, etc.
 */
const authMiddleware = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token || typeof token !== 'string') {
    return res.status(401).send({ message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    const userId = decoded?.userId;
    if (!userId || typeof userId !== 'string') {
      return res.status(401).send({ message: 'Unauthorized' });
    }
    req.user = { id: userId };
    return next();
  } catch {
    return res.status(401).send({ message: 'Unauthorized' });
  }
};

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

  const getRoomById = asyncHandler(async (req, res) => {
    const room = await findRoomById(roomsCollection, req.params.id);
    if (!room) {
      return res.status(404).send({ message: 'Room not found.' });
    }
    res.send(room);
  });

  app.get('/rooms/:id', getRoomById);
  app.get('/api/rooms/:id', getRoomById);

  app.get('/rooms/mine', authMiddleware, asyncHandler(async (req, res) => {
    const rooms = await roomsCollection
      .find({ createdBy: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(rooms);
  }));

  app.get('/api/rooms/mine', authMiddleware, asyncHandler(async (req, res) => {
    const rooms = await roomsCollection
      .find({ createdBy: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(rooms);
  }));

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

  app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running on port ${port}`);
  });
}

start().catch((err) => {
  console.error('Failed to start server', err);
  process.exit(1);
});