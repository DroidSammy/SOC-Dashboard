import bcrypt from 'bcryptjs';
import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

async function addUser(name, email, password) {
  const hash = bcrypt.hashSync(password, 10);
  const id = `user-${Date.now()}`;
  try {
    await pool.query(
      `INSERT INTO users (id, name, email, role, password_hash) VALUES ($1, $2, $3, $4, $5)`,
      [id, name, email, 'admin', hash]
    );
    console.log(`\n✅ Successfully created user: ${name} (${email})!`);
  } catch (err) {
    if (err.code === '23505') {
      console.log(`\n❌ Error: The email ${email} is already registered.`);
    } else {
      console.error('\n❌ Database error:', err.message);
    }
  } finally {
    await pool.end();
  }
}

const args = process.argv.slice(2);
if (args.length < 3) {
  console.log('\nUsage: node add_user.js "Your Name" "your@email.com" "yourpassword123"\n');
  process.exit(1);
}

addUser(args[0], args[1], args[2]);
