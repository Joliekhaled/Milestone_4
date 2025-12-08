# Quick Start Guide

## Prerequisites

- Node.js (v14 or higher)
- MongoDB (running locally or MongoDB Atlas account)
- npm or yarn

## Setup Steps

1. **Navigate to backend directory:**
   ```bash
   cd backend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Create environment file:**
   ```bash
   cp .env.example .env
   ```

4. **Edit `.env` file:**
   - Update `MONGODB_URI` with your MongoDB connection string
   - Update `JWT_SECRET` with a strong secret key
   - Adjust `PORT` if needed (default: 3000)

5. **Set up MongoDB:**
   
   **Option A: MongoDB Atlas (Cloud - No Installation Required!)**
   - Sign up at https://www.mongodb.com/cloud/atlas/register
   - Create a free cluster and get your connection string
   - Update `MONGODB_URI` in `.env` with your Atlas connection string
   - See `QUICK_MONGODB_ATLAS.md` for quick steps or `MONGODB_ATLAS_SETUP.md` for detailed guide
   
   **Option B: Local MongoDB (if you have it installed)**
   ```bash
   # macOS (if installed via Homebrew)
   brew services start mongodb-community
   ```

6. **Start the server:**
   ```bash
   # Development mode (auto-reload)
   npm run dev
   
   # Production mode
   npm start
   ```

7. **Test the API:**
   - Server should be running on `http://localhost:3000`
   - Health check: `GET http://localhost:3000/api/health`
   - Use Postman or curl to test endpoints

## First API Call Example

**Register a new user:**
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "password123"
  }'
```

**Login:**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "password123"
  }'
```

**Create a post (use token from login response):**
```bash
curl -X POST http://localhost:3000/api/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "title": "My First Post",
    "content": "This is my first post content",
    "status": "published"
  }'
```

## Troubleshooting

- **MongoDB connection error:** Make sure MongoDB is running or check your `MONGODB_URI`
- **Port already in use:** Change `PORT` in `.env` file
- **Module not found:** Run `npm install` again

