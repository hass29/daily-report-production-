# Secure DPR — MERN Stack

A MERN conversion of the supplied Secure DPR Daily Production Report application.

## Requirements
- Node.js 20+
- MongoDB Atlas account (or local MongoDB)
- npm

## 1. Configure the backend

```powershell
cd backend
Copy-Item .env.example .env
npm install
```

Edit `backend/.env`. Set `MONGODB_URI`, a long random `SESSION_SECRET`, and `CLIENT_URL=http://localhost:5173`.

## 2. Start the backend

```powershell
npm run dev
```

Backend: http://localhost:4000

## 3. Start the frontend (second terminal)

```powershell
cd frontend
Copy-Item .env.example .env
npm install
npm run dev
```

Frontend: http://localhost:5173

On first launch, use **Initial administrator setup**. There is no default admin password. Save the one-time recovery code displayed after setup.

## Security notes
- Passwords and recovery codes are hashed with bcrypt on the server.
- Authentication uses server-side sessions stored in MongoDB and an HttpOnly cookie.
- Authorization is enforced by Express, not just by React.
- Set `SESSION_COOKIE_SECURE=true` when serving over HTTPS in production.
- Set a strong, unique `SESSION_SECRET`; never commit `.env`.
- Password recovery in this project requires the account's recovery code. It does not email reset links.
- Do not expose MongoDB credentials in frontend environment variables.
- Configure MongoDB Atlas Network Access and a least-privilege database user before deployment.
