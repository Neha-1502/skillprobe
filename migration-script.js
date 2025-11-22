// migration-script.js
import { createClient } from "@libsql/client";
import dotenv from "dotenv";
import crypto from 'crypto';

dotenv.config();

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN
});

async function migrateExistingUsers() {
  try {
    // Get all users without google_id
    const result = await db.execute({
      sql: `SELECT user_id, email FROM Users WHERE google_id IS NULL AND password != 'google_oauth'`
    });

    console.log(`Found ${result.rows.length} users to migrate...`);

    for (const user of result.rows) {
      // Generate a consistent Google ID based on email
      const googleId = 'manual_' + crypto.createHash('md5').update(user.email).digest('hex').substring(0, 16);
      
      await db.execute({
        sql: `UPDATE Users SET google_id = ? WHERE user_id = ?`,
        args: [googleId, user.user_id]
      });
      
      console.log(`Updated user ${user.email} with Google ID: ${googleId}`);
    }

    console.log('Migration completed successfully!');
  } catch (error) {
    console.error('Migration error:', error);
  }
}

migrateExistingUsers();