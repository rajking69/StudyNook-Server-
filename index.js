const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion } = require('mongodb');

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

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

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

  app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running on port ${port}`);
  });
}

start().catch((err) => {
  console.error('Failed to start server', err);
  process.exit(1);
});