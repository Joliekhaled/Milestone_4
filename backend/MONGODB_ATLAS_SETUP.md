# MongoDB Atlas Setup Guide

Since you can't install MongoDB locally, we'll use **MongoDB Atlas** (free cloud database). Follow these steps:

## Step 1: Create MongoDB Atlas Account

1. Go to [https://www.mongodb.com/cloud/atlas/register](https://www.mongodb.com/cloud/atlas/register)
2. Sign up for a free account (no credit card required)
3. Verify your email address

## Step 2: Create a Free Cluster

1. After logging in, click **"Build a Database"** or **"Create"**
2. Choose the **FREE (M0) tier** - it's perfect for development
3. Select a cloud provider and region (choose the closest to you):
   - AWS, Google Cloud, or Azure
   - Pick a region close to you (e.g., `us-east-1` for US East)
4. Give your cluster a name (e.g., "Cluster0") or use the default
5. Click **"Create Cluster"** (takes 1-3 minutes)

## Step 3: Create Database User

1. While the cluster is being created, you'll see a security setup screen
2. Create a database user:
   - **Username**: `admin` (or any username you prefer)
   - **Password**: Create a strong password (save it somewhere safe!)
   - Click **"Create Database User"**
3. For **Network Access**, click **"Add My Current IP Address"**
   - This allows your computer to connect
   - For development, you can also click **"Allow Access from Anywhere"** (0.0.0.0/0)
   - Click **"Finish and Close"**

## Step 4: Get Your Connection String

1. Once your cluster is ready, click **"Connect"** button
2. Choose **"Connect your application"**
3. Select **"Node.js"** as the driver
4. Copy the connection string - it will look like:
   ```
   mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```

## Step 5: Update Your .env File

1. Open the `.env` file in the `backend` folder
2. Replace the `MONGODB_URI` with your connection string
3. Replace `<username>` with your database username
4. Replace `<password>` with your database password
5. Add a database name at the end (before the `?`):
   ```
   MONGODB_URI=mongodb+srv://admin:yourpassword@cluster0.xxxxx.mongodb.net/dental-clinic-api?retryWrites=true&w=majority
   ```

**Example:**
```
MONGODB_URI=mongodb+srv://admin:MySecurePass123@cluster0.abc123.mongodb.net/dental-clinic-api?retryWrites=true&w=majority
```

## Step 6: Test the Connection

1. Restart your server:
   ```bash
   cd backend
   npm run dev
   ```

2. You should see: `MongoDB Connected: ...` in the console

## Troubleshooting

- **Connection timeout**: Make sure you added your IP address in Network Access
- **Authentication failed**: Double-check your username and password in the connection string
- **Can't find cluster**: Make sure the cluster is fully created (green status)

## Security Note

- Never commit your `.env` file to git (it's already in `.gitignore`)
- Keep your database password secure
- For production, use environment-specific connection strings

