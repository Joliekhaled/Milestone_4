# Quick MongoDB Atlas Setup (No Installation Required!)

Since you can't install MongoDB locally, use **MongoDB Atlas** (free cloud database).

## Quick Steps:

1. **Sign up**: Go to https://www.mongodb.com/cloud/atlas/register
2. **Create free cluster**: Click "Build a Database" → Choose FREE tier → Create
3. **Create user**: Username + Password (save these!)
4. **Network Access**: Click "Add My Current IP Address" or "Allow Access from Anywhere"
5. **Get connection string**: Click "Connect" → "Connect your application" → Copy the string
6. **Update .env**: Replace `MONGODB_URI` in your `.env` file with:
   ```
   mongodb+srv://YOUR_USERNAME:YOUR_PASSWORD@cluster0.xxxxx.mongodb.net/dental-clinic-api?retryWrites=true&w=majority
   ```
   (Replace YOUR_USERNAME and YOUR_PASSWORD with your actual credentials)

7. **Restart server**: `npm run dev`

That's it! Your server will connect to the cloud database.

**See `MONGODB_ATLAS_SETUP.md` for detailed step-by-step instructions with screenshots.**

