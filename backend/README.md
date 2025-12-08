# Backend API Documentation

A RESTful API backend built with Node.js, Express.js, and MongoDB. This API provides user authentication and CRUD operations for users and posts.

## Features

- ✅ RESTful API design
- ✅ User authentication with JWT
- ✅ Password hashing with bcrypt
- ✅ MongoDB database integration
- ✅ Error handling middleware
- ✅ Request logging middleware
- ✅ Role-based access control (Admin/User)
- ✅ Input validation
- ✅ Secure password handling

## Project Structure

```
backend/
├── config/
│   ├── database.js      # MongoDB connection configuration
│   └── jwt.js           # JWT configuration
├── controllers/
│   ├── authController.js    # Authentication logic
│   ├── userController.js    # User CRUD operations
│   └── postController.js    # Post CRUD operations
├── middleware/
│   ├── auth.js          # JWT authentication middleware
│   ├── errorHandler.js  # Global error handling
│   └── logger.js        # Request logging
├── models/
│   ├── User.js          # User schema/model
│   └── Post.js          # Post schema/model
├── routes/
│   ├── authRoutes.js    # Authentication routes
│   ├── userRoutes.js    # User routes
│   └── postRoutes.js    # Post routes
├── .env.example         # Environment variables template
├── .gitignore           # Git ignore file
├── package.json         # Dependencies and scripts
├── server.js            # Application entry point
└── README.md            # This file
```

## Installation

1. **Install dependencies:**
   ```bash
   cd backend
   npm install
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and update the following:
   ```
   PORT=3000
   MONGODB_URI=mongodb://localhost:27017/dental-clinic-api
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
   JWT_EXPIRE=7d
   ```

3. **Set up MongoDB:**
   
   **Option A: MongoDB Atlas (Cloud - Recommended if you can't install locally)**
   - Sign up for free at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas/register)
   - Create a free cluster (M0 tier)
   - Get your connection string and update `MONGODB_URI` in `.env`
   - See `MONGODB_ATLAS_SETUP.md` for detailed instructions
   
   **Option B: Local MongoDB**
   - Install MongoDB if you haven't already
   - Start MongoDB service:
     ```bash
     # macOS
     brew services start mongodb-community
     
     # Linux
     sudo systemctl start mongod
     
     # Windows
     net start MongoDB
     ```

4. **Start the server:**
   ```bash
   # Development mode (with nodemon for auto-reload)
   npm run dev
   
   # Production mode
   npm start
   ```

The server will start on `http://localhost:3000` (or the port specified in your `.env` file).

## API Endpoints

### Authentication Endpoints

#### Register User
- **POST** `/api/auth/register`
- **Access:** Public
- **Body:**
  ```json
  {
    "name": "John Doe",
    "email": "john@example.com",
    "password": "password123"
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "message": "User registered successfully",
    "data": {
      "user": {
        "id": "...",
        "name": "John Doe",
        "email": "john@example.com",
        "role": "user"
      },
      "token": "jwt_token_here"
    }
  }
  ```

#### Login
- **POST** `/api/auth/login`
- **Access:** Public
- **Body:**
  ```json
  {
    "email": "john@example.com",
    "password": "password123"
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "message": "Login successful",
    "data": {
      "user": {
        "id": "...",
        "name": "John Doe",
        "email": "john@example.com",
        "role": "user"
      },
      "token": "jwt_token_here"
    }
  }
  ```

#### Get Current User
- **GET** `/api/auth/me`
- **Access:** Private
- **Headers:** `Authorization: Bearer <token>`

### User Endpoints

#### Create User (Admin Only)
- **POST** `/api/users`
- **Access:** Private/Admin
- **Headers:** `Authorization: Bearer <token>`
- **Body:**
  ```json
  {
    "name": "Jane Doe",
    "email": "jane@example.com",
    "password": "password123",
    "role": "user"
  }
  ```

#### Get All Users (Admin Only)
- **GET** `/api/users`
- **Access:** Private/Admin
- **Headers:** `Authorization: Bearer <token>`

#### Get User by ID
- **GET** `/api/users/:id`
- **Access:** Private
- **Headers:** `Authorization: Bearer <token>`

#### Update User
- **PUT** `/api/users/:id`
- **Access:** Private (users can update themselves, admins can update anyone)
- **Headers:** `Authorization: Bearer <token>`
- **Body:**
  ```json
  {
    "name": "Updated Name",
    "email": "updated@example.com"
  }
  ```

#### Delete User (Admin Only)
- **DELETE** `/api/users/:id`
- **Access:** Private/Admin
- **Headers:** `Authorization: Bearer <token>`

### Post Endpoints

#### Create Post
- **POST** `/api/posts`
- **Access:** Private
- **Headers:** `Authorization: Bearer <token>`
- **Body:**
  ```json
  {
    "title": "My First Post",
    "content": "This is the content of my post",
    "status": "published",
    "tags": ["tag1", "tag2"]
  }
  ```

#### Get All Posts
- **GET** `/api/posts`
- **Access:** Public
- **Query Parameters (optional):**
  - `status`: Filter by status (draft/published)
  - `author`: Filter by author ID

#### Get Post by ID
- **GET** `/api/posts/:id`
- **Access:** Public

#### Update Post
- **PUT** `/api/posts/:id`
- **Access:** Private (authors can update their own posts, admins can update any)
- **Headers:** `Authorization: Bearer <token>`
- **Body:**
  ```json
  {
    "title": "Updated Title",
    "content": "Updated content",
    "status": "published"
  }
  ```

#### Delete Post
- **DELETE** `/api/posts/:id`
- **Access:** Private (authors can delete their own posts, admins can delete any)
- **Headers:** `Authorization: Bearer <token>`

## Testing with Postman

1. **Import the API endpoints:**
   - Create a new collection in Postman
   - Add requests for each endpoint

2. **Testing Flow:**
   - First, register a new user or login to get a JWT token
   - Copy the token from the response
   - For protected routes, add the token to the Authorization header:
     - Type: Bearer Token
     - Token: `<paste your token here>`

3. **Example Postman Collection:**
   ```
   1. POST /api/auth/register
   2. POST /api/auth/login
   3. GET /api/auth/me (with token)
   4. POST /api/posts (with token)
   5. GET /api/posts
   6. GET /api/posts/:id
   7. PUT /api/posts/:id (with token)
   8. DELETE /api/posts/:id (with token)
   9. GET /api/users/:id (with token)
   10. PUT /api/users/:id (with token)
   ```

## Security Features

- ✅ Passwords are hashed using bcrypt before storing
- ✅ JWT tokens for stateless authentication
- ✅ Protected routes require valid JWT tokens
- ✅ Role-based access control (Admin/User)
- ✅ Input validation using express-validator
- ✅ Error handling that doesn't expose sensitive information
- ✅ CORS enabled for cross-origin requests

## Error Handling

The API uses a centralized error handling middleware. Errors are returned in the following format:

```json
{
  "success": false,
  "message": "Error message here"
}
```

Common HTTP status codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

## Environment Variables

- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment (development/production)
- `MONGODB_URI` - MongoDB connection string (can be local or MongoDB Atlas cloud)
- `JWT_SECRET` - Secret key for JWT tokens
- `JWT_EXPIRE` - JWT token expiration time

## Dependencies

- **express** - Web framework
- **mongoose** - MongoDB ODM
- **bcryptjs** - Password hashing
- **jsonwebtoken** - JWT authentication
- **dotenv** - Environment variables
- **cors** - Cross-origin resource sharing
- **express-validator** - Input validation
- **morgan** - HTTP request logger

## Development Dependencies

- **nodemon** - Auto-reload server during development

## License

ISC

