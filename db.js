import pg from "pg";
import bcrypt from "bcrypt";
import "dotenv/config";

// Supabase's pooler requires SSL; keep the pool tiny for serverless.
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || undefined,
  ssl: { rejectUnauthorized: false },
  max: 3,
});

// Create tables and seed admins. Runs once per cold start. It is exposed as a
// promise (not top-level await) so a database problem becomes a clean 500
// response instead of crashing the whole function at import time.
async function seedAdmin(name, username, email, password) {
  if (!password) return;
  const { rowCount } = await pool.query(
    "SELECT 1 FROM users WHERE username = $1",
    [username],
  );
  if (rowCount) return;
  const hashed = await bcrypt.hash(password, await bcrypt.genSalt());
  await pool.query(
    "INSERT INTO users (name, username, email, password, role) VALUES ($1, $2, $3, $4, 'admin')",
    [name, username, email, hashed],
  );
}

async function init() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is not set");
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT NOT NULL UNIQUE,
      email TEXT,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin'))
    );
    CREATE TABLE IF NOT EXISTS session (
      sid VARCHAR PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_session_expire ON session (expire);
    ALTER TABLE users ENABLE ROW LEVEL SECURITY;
    ALTER TABLE session ENABLE ROW LEVEL SECURITY;
  `);
  await seedAdmin("Jay", "AdminJay", "AdminJay@gmail.com", process.env.ADMIN_JAY_PASSWORD);
  await seedAdmin("James", "Admin2", "Admin2sederia@gmail.com", process.env.ADMIN2_PASSWORD);
  console.log("postgres connected");
}

const ready = init();
ready.catch((err) => console.error("Database init failed:", err.message));

async function getUsers() {
  const { rows } = await pool.query("SELECT * FROM users WHERE role = 'user'");
  return rows;
}

async function getAdmins() {
  const { rows } = await pool.query("SELECT * FROM users WHERE role = 'admin'");
  return rows;
}

async function Register(user) {
  try {
    const hashedPassword = await bcrypt.hash(user.password, await bcrypt.genSalt());
    const result = await pool.query(
      "INSERT INTO users (name, username, email, password) VALUES ($1, $2, $3, $4) RETURNING id",
      [user.name, user.username, user.email, hashedPassword],
    );
    return result;
  } catch (err) {
    console.log("error: " + err);
    return;
  }
}

async function Login(username, password) {
  const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [
    username,
  ]);
  const user = rows[0];

  if (!user) {
    throw new Error("User not found");
  }

  const CheckedPassword = await bcrypt.compare(password, user.password);
  if (!CheckedPassword) {
    throw new Error("Invalid password");
  }
  return user;
}

async function sendEmail(email) {
  const { rows } = await pool.query("SELECT email FROM users WHERE email = $1", [
    email,
  ]);

  if (!rows[0]) {
    throw new Error("User email not found.");
  }
  return rows[0];
}

async function resetPassword(password, confrim_password, email) {
  if (password !== confrim_password) {
    throw new Error("Password does not match confirm password.");
  }

  const hashedPassword = await bcrypt.hash(password, await bcrypt.genSalt());
  return pool.query("UPDATE users SET password = $1 WHERE email = $2", [
    hashedPassword,
    email,
  ]);
}

export { pool, ready, Register, Login, getUsers, getAdmins, sendEmail, resetPassword };
