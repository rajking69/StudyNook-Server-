const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const cookieParser = require('cookie-parser');

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

app.get('/', (req, res) => {
  res.send('StudyNook API is running');
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server is running on port ${port}`);
});