# StudyNook API

Express REST API for StudyNook room booking.

**Production deploy:** see [DEPLOY.md](../DEPLOY.md) (Render + Vercel).

## Setup

```bash
npm install
```

Create `.env`:

```env
MONGODB_URI=
JWT_SECRET=
CLIENT_ORIGIN=http://localhost:3000
PORT=5000
NODE_ENV=development
DB_NAME=StudyNook
```

```bash
node index.js
```

## Production cookies

When `NODE_ENV=production`, JWT cookies are set with `secure: true` and `sameSite: strict`. Serve the API over **HTTPS** so browsers accept cookies.

## Data migration on boot

- Rooms missing `bookingCount` → set to `0`
- Users missing `bookings` array → set to `[]`

## Challenge 7.1 — JWT (HTTP-only cookie)

| Step | Implementation |
|------|----------------|
| Login / Google success | `jwt.sign({ userId: user._id }, …)` via `setAuthCookie()` |
| Cookie flags | `httpOnly: true`, `sameSite: 'strict'`, `secure: true` when `NODE_ENV=production` |
| `authMiddleware` | Reads `req.cookies.token`, verifies JWT, sets `req.user = { id: userId }`, else **401 Unauthorized** |
| Protected routes | `POST/PUT/DELETE` rooms, `POST` bookings, `GET` bookings/my, `PATCH` cancel, `GET` rooms/mine, `/auth/me`, `/auth/set-password` |
| Logout | `POST /auth/logout` → `clearAuthCookie()` (same path/options as set) |

Client sends cookies with `axios` `withCredentials: true` and `/backend` proxy on Vercel.

## Main endpoints

See client [README](../studynook/README.md) for the full `/api` route list.
