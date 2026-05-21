const { MongoClient, ServerApiVersion } = require('mongodb');
const dotenv = require('dotenv');
dotenv.config();

const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error('Missing MONGODB_URI environment variable.');
  process.exit(1);
}
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

const rooms = [
  {
    name: 'Innovation Hub',
    description:
      'A modern collaborative workspace suitable for team meetings and brainstorming sessions.',
    image: 'https://images.unsplash.com/photo-1497366754035-f200968a6e72',
    location: '3rd Floor',
    capacity: 4,
    pricePerHour: 5,
    amenities: ['Whiteboard', 'Wi-Fi', 'Power Outlets', 'Air Conditioning'],
    bookingCount: 0,
    createdAt: new Date(),
  },
  {
    name: 'Focus Chamber',
    description:
      'Quiet private room designed for focused work, interviews, and online meetings.',
    image: 'https://images.unsplash.com/photo-1497366412874-3415097a27e7',
    location: '2nd Floor',
    capacity: 2,
    pricePerHour: 4,
    amenities: ['Wi-Fi', 'Power Outlets', 'Monitor'],
    bookingCount: 0,
    createdAt: new Date(),
  },
  {
    name: 'Creative Studio',
    description:
      'Spacious room equipped for presentations, workshops, and collaborative creative projects.',
    image: 'https://images.unsplash.com/photo-1524758631624-e2822e304c36',
    location: '5th Floor',
    capacity: 8,
    pricePerHour: 10,
    amenities: ['Projector', 'Whiteboard', 'Wi-Fi', 'Air Conditioning'],
    bookingCount: 0,
    createdAt: new Date(),
  },
  {
    name: 'Executive Suite',
    description:
      'Premium private office with ergonomic furniture for high-profile meetings and deep work.',
    image: 'https://images.unsplash.com/photo-1497366216548-37526070297c',
    location: '6th Floor',
    capacity: 6,
    pricePerHour: 15,
    amenities: ['Wi-Fi', 'Air Conditioning', 'Power Outlets', 'Smart TV'],
    bookingCount: 0,
    createdAt: new Date(),
  },
  {
    name: 'The Reading Nook',
    description:
      'A cozy, silent corner surrounded by bookshelves — perfect for solo deep study.',
    image: 'https://images.unsplash.com/photo-1481627834876-b7833e8f5570',
    location: '1st Floor',
    capacity: 1,
    pricePerHour: 2,
    amenities: ['Wi-Fi', 'Natural Lighting', 'Power Outlets'],
    bookingCount: 0,
    createdAt: new Date(),
  },
  {
    name: 'Seminar Hall',
    description:
      'Large open hall with lecture-style seating for seminars, study groups, and workshops.',
    image: 'https://images.unsplash.com/photo-1588072432836-e10032774350',
    location: 'Ground Floor',
    capacity: 20,
    pricePerHour: 20,
    amenities: ['Projector', 'Whiteboard', 'Wi-Fi', 'Air Conditioning', 'Sound System'],
    bookingCount: 0,
    createdAt: new Date(),
  },
];

async function seed() {
  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME || 'StudyNook');
    const col = db.collection(process.env.ROOMS_COLLECTION || 'rooms');

    const existing = await col.countDocuments();
    if (existing > 0) {
      console.log(`✓ Collection already has ${existing} rooms. Skipping seed.`);
      console.log('  Run with --force to clear and re-seed.');
      if (!process.argv.includes('--force')) {
        return;
      }
      await col.deleteMany({});
      console.log('  Cleared existing rooms.');
    }

    const result = await col.insertMany(rooms);
    console.log(`✅ Seeded ${result.insertedCount} rooms into StudyNook.rooms`);
  } catch (err) {
    console.error('Seed failed:', err?.message || err);
    process.exitCode = 1;
  } finally {
    await client.close();
  }
}

seed();
