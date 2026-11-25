const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 10000;
const API_KEY = process.env.COINGECKO_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

// -------------------- SECURITY MIDDLEWARE --------------------

// Restrict browser access to the VELTRO frontend and explicitly approved domains.
// Requests without an Origin header remain available to native/server clients.
const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || "https://veltro-crypto.onrender.com")
    .split(",").map(origin => origin.trim().replace(/\/$/, "")).filter(Boolean)
);

app.disable("x-powered-by");
app.set("trust proxy", 1); // Render is behind a reverse proxy.
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cross-Origin-Resource-Policy", "same-site");
  next();
});
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin.replace(/\/$/, ""))) return callback(null, true);
    return callback(null, false);
  },
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 86400
}));

// Lightweight per-process limiter; no new dependency or paid service required.
// For multiple Render instances, replace the in-memory store with shared storage.
const rateBuckets = new Map();
function rateLimit({ windowMs, max, message }) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip}:${req.baseUrl}${req.path}`;
    let bucket = rateBuckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      rateBuckets.set(key, bucket);
    }
    bucket.count += 1;
    res.setHeader("RateLimit-Limit", String(max));
    res.setHeader("RateLimit-Remaining", String(Math.max(0, max - bucket.count)));
    res.setHeader("RateLimit-Reset", String(Math.ceil(bucket.resetAt / 1000)));
    if (bucket.count > max) {
      res.setHeader("Retry-After", String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))));
      return res.status(429).json({ error: message || "Too many requests. Please try again shortly." });
    }
    next();
  };
}
const rateCleanup = setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) if (now >= bucket.resetAt) rateBuckets.delete(key);
}, 5 * 60 * 1000);
if (typeof rateCleanup.unref === "function") rateCleanup.unref();

app.use(express.json({ limit: "10kb" }));
app.use("/api", rateLimit({ windowMs: 60 * 1000, max: 120,
  message: "Too many API requests. Please wait one minute and try again." }));
const authRateLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10,
  message: "Too many login or registration attempts. Please wait 15 minutes." });
const tradeRateLimit = rateLimit({ windowMs: 60 * 1000, max: 20,
  message: "Too many trading requests. Please wait one minute." });
const rewardRateLimit = rateLimit({ windowMs: 60 * 1000, max: 10,
  message: "Too many rewards requests. Please wait one minute." });

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: false }
    : undefined
});

const STARTING_BALANCE = "10000.000000000000";
const MINING_DURATION_HOURS = 24;
const MINING_REWARD_PER_HOUR = "1.000000000000"; // 24 demo VLT points per completed session

// -------------------- DATABASE --------------------

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS portfolio (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      coin_id VARCHAR(100) NOT NULL,
      symbol VARCHAR(20) NOT NULL,
      name VARCHAR(100) NOT NULL,
      quantity NUMERIC(38,18) NOT NULL CHECK (quantity > 0),
      average_buy_price NUMERIC(30,12) NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, coin_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS watchlist (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      coin_id VARCHAR(100) NOT NULL,
      symbol VARCHAR(20) NOT NULL,
      name VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, coin_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS trading_wallets (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      balance NUMERIC(30,12) NOT NULL DEFAULT 10000 CHECK (balance >= 0),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS trading_positions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      coin_id VARCHAR(100) NOT NULL,
      symbol VARCHAR(20) NOT NULL,
      name VARCHAR(100) NOT NULL,
      quantity NUMERIC(38,18) NOT NULL CHECK (quantity > 0),
      average_buy_price NUMERIC(30,12) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, coin_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS trading_transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      coin_id VARCHAR(100) NOT NULL,
      symbol VARCHAR(20) NOT NULL,
      name VARCHAR(100) NOT NULL,
      transaction_type VARCHAR(10) NOT NULL CHECK (transaction_type IN ('BUY','SELL')),
      quantity NUMERIC(38,18) NOT NULL,
      price NUMERIC(30,12) NOT NULL,
      total NUMERIC(30,12) NOT NULL,
      realized_profit NUMERIC(30,12) NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // VLT is initially an in-app demo reward point balance, not a transferable token.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reward_wallets (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      balance NUMERIC(30,12) NOT NULL DEFAULT 0 CHECK (balance >= 0),
      lifetime_earned NUMERIC(30,12) NOT NULL DEFAULT 0 CHECK (lifetime_earned >= 0),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS mining_sessions (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      ends_at TIMESTAMP NOT NULL,
      claimed_at TIMESTAMP,
      reward NUMERIC(30,12) NOT NULL DEFAULT 24,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS mining_sessions_user_started_idx
    ON mining_sessions(user_id, started_at DESC)
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS reward_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      transaction_type VARCHAR(30) NOT NULL,
      amount NUMERIC(30,12) NOT NULL CHECK (amount > 0),
      description VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create wallets for existing users without changing existing balances.
  await pool.query(`
    INSERT INTO trading_wallets (user_id, balance)
    SELECT id, $1::numeric FROM users
    ON CONFLICT (user_id) DO NOTHING
  `, [STARTING_BALANCE]);

  await pool.query(`
    INSERT INTO reward_wallets (user_id)
    SELECT id FROM users
    ON CONFLICT (user_id) DO NOTHING
  `);

  // Admin, premium subscriptions and weekly simulated-trading tournaments.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS veltro_admins (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      role VARCHAR(20) NOT NULL DEFAULT 'owner' CHECK (role IN ('owner','shareholder','admin')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  // Account ID 1 is the original VELTRO owner. Future shareholders can be added explicitly.
  await pool.query(`
    INSERT INTO veltro_admins (user_id, role)
    SELECT 1, 'owner' WHERE EXISTS (SELECT 1 FROM users WHERE id=1)
    ON CONFLICT (user_id) DO NOTHING
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS premium_subscriptions (
      id BIGSERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      plan VARCHAR(30) NOT NULL CHECK (plan IN ('monthly','yearly')),
      status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','expired','cancelled')),
      starts_at TIMESTAMP, ends_at TIMESTAMP, payment_reference VARCHAR(120),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS trading_tournaments (
      id BIGSERIAL PRIMARY KEY, title VARCHAR(120) NOT NULL, description TEXT DEFAULT '',
      starts_at TIMESTAMP NOT NULL, ends_at TIMESTAMP NOT NULL, prize_amount NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (prize_amount >= 0),
      prize_currency VARCHAR(12) NOT NULL DEFAULT 'USD', status VARCHAR(20) NOT NULL DEFAULT 'scheduled'
        CHECK (status IN ('scheduled','active','completed','cancelled')),
      winner_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, prize_paid BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, CHECK (ends_at > starts_at)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tournament_entries (
      tournament_id BIGINT NOT NULL REFERENCES trading_tournaments(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(tournament_id,user_id)
    )
  `);

  console.log("VELTRO database ready.");
}

// -------------------- COMMON HELPERS --------------------

function authenticateToken(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Please log in to continue." });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired session." });
  }
}

function validCoinId(value) {
  return typeof value === "string" && /^[a-z0-9-]{1,100}$/.test(value);
}
function validText(value, max) {
  return typeof value === "string" && value.trim().length > 0 && value.trim().length <= max;
}
function validPositiveNumber(value) {
  return (typeof value === "number" || typeof value === "string") &&
    String(value).length <= 40 &&
    /^\d+(\.\d{1,18})?$/.test(String(value)) &&
    Number.isFinite(Number(value)) && Number(value) > 0;
}
function validNonNegativeNumber(value) {
  return (typeof value === "number" || typeof value === "string") &&
    String(value).length <= 40 &&
    /^\d+(\.\d{1,18})?$/.test(String(value)) &&
    Number.isFinite(Number(value)) && Number(value) >= 0;
}
function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}
async function getCoinPrice(coinId) {
  if (!API_KEY) throw new Error("CoinGecko API key is not configured.");
  const response = await fetch(
    "https://api.coingecko.com/api/v3/simple/price?ids=" +
    encodeURIComponent(coinId) + "&vs_currencies=usd",
    { headers: { "x-cg-demo-api-key": API_KEY } }
  );
  if (!response.ok) throw new Error("Unable to retrieve current cryptocurrency price.");
  const data = await response.json();
  const price = data[coinId]?.usd;
  if (typeof price !== "number" || !Number.isFinite(price) || price <= 0) {
    throw new Error("Cryptocurrency price is unavailable.");
  }
  const formatted = price.toFixed(12);
  if (Number(formatted) <= 0) throw new Error("Cryptocurrency price precision is insufficient.");
  return formatted;
}
async function getCoinDetails(coinId) {
  let name = coinId;
  let symbol = coinId.toUpperCase();
  if (!API_KEY) return { name, symbol };
  try {
    const response = await fetch(
      "https://api.coingecko.com/api/v3/coins/" + encodeURIComponent(coinId) +
      "?localization=false&tickers=false&market_data=false&community_data=false&developer_data=false&sparkline=false",
      { headers: { "x-cg-demo-api-key": API_KEY } }
    );
    if (response.ok) {
      const data = await response.json();
      name = data.name || name;
      symbol = data.symbol || symbol;
    }
  } catch (error) {
    console.warn("Coin metadata lookup failed:", error.message);
  }
  return { name, symbol: String(symbol).toUpperCase() };
}
function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

// -------------------- BASIC --------------------

app.get("/", (req, res) => {
  res.json({ message: "VELTRO Crypto API is running!", status: "online" });
});
app.get("/api/health", (req, res) => {
  res.json({ status: "healthy", service: "VELTRO API" });
});

// -------------------- AUTH --------------------

app.post("/api/auth/register", authRateLimit, asyncRoute(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (typeof name !== "string" || typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Please provide valid registration details." });
  }
  const cleanName = name.trim();
  const cleanEmail = email.trim().toLowerCase();
  if (cleanName.length < 2 || cleanName.length > 100) {
    return res.status(400).json({ error: "Name must contain 2 to 100 characters." });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) || cleanEmail.length > 255) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }
  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({ error: "Password must contain 8 to 72 characters." });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const client = await pool.connect();
  let user;
  try {
    await client.query("BEGIN");
    const result = await client.query(
      `INSERT INTO users (name,email,password_hash)
       VALUES ($1,$2,$3) RETURNING id,name,email,created_at`,
      [cleanName, cleanEmail, passwordHash]
    );
    user = result.rows[0];
    await client.query("INSERT INTO trading_wallets (user_id,balance) VALUES ($1,$2)", [user.id, STARTING_BALANCE]);
    await client.query("INSERT INTO reward_wallets (user_id) VALUES ($1)", [user.id]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "23505") return res.status(409).json({ error: "An account with this email already exists." });
    throw error;
  } finally {
    client.release();
  }
  res.status(201).json({ message: "VELTRO account created successfully!", token: signToken(user), user });
}));

app.post("/api/auth/login", authRateLimit, asyncRoute(async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string" || email.length > 255 || password.length > 72) {
    return res.status(400).json({ error: "Please provide a valid email and password." });
  }
  const result = await pool.query("SELECT * FROM users WHERE email=$1", [email.trim().toLowerCase()]);
  if (!result.rows.length || !(await bcrypt.compare(password, result.rows[0].password_hash))) {
    return res.status(401).json({ error: "Incorrect email or password." });
  }
  const user = result.rows[0];
  await pool.query("INSERT INTO trading_wallets (user_id,balance) VALUES ($1,$2) ON CONFLICT (user_id) DO NOTHING", [user.id, STARTING_BALANCE]);
  await pool.query("INSERT INTO reward_wallets (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING", [user.id]);
  res.json({
    message: "Login successful!",
    token: signToken(user),
    user: { id: user.id, name: user.name, email: user.email, created_at: user.created_at }
  });
}));

app.get("/api/auth/me", authenticateToken, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT id,name,email,created_at FROM users WHERE id=$1", [req.user.id]
  );
  if (!result.rows.length) return res.status(404).json({ error: "User account not found." });
  res.json({ user: result.rows[0] });
}));

// -------------------- PORTFOLIO --------------------

app.get("/api/portfolio", authenticateToken, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id,coin_id,symbol,name,quantity,average_buy_price,created_at,updated_at
     FROM portfolio WHERE user_id=$1 ORDER BY created_at DESC`, [req.user.id]
  );
  res.json({ portfolio: result.rows });
}));

app.post("/api/portfolio", authenticateToken, asyncRoute(async (req, res) => {
  const { coin_id, symbol, name, quantity, average_buy_price } = req.body || {};
  if (!validCoinId(coin_id) || !validText(symbol,20) || !validText(name,100) ||
      !validPositiveNumber(quantity) || !validNonNegativeNumber(average_buy_price)) {
    return res.status(400).json({ error: "Please provide valid coin and holding details." });
  }
  const result = await pool.query(
    `INSERT INTO portfolio (user_id,coin_id,symbol,name,quantity,average_buy_price)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (user_id,coin_id) DO UPDATE SET
       symbol=EXCLUDED.symbol,name=EXCLUDED.name,quantity=EXCLUDED.quantity,
       average_buy_price=EXCLUDED.average_buy_price,updated_at=CURRENT_TIMESTAMP
     RETURNING *`,
    [req.user.id,coin_id,symbol.trim().toUpperCase(),name.trim(),String(quantity),String(average_buy_price)]
  );
  res.json({ message: "Portfolio holding saved successfully.", holding: result.rows[0] });
}));

app.delete("/api/portfolio/:coinId", authenticateToken, asyncRoute(async (req, res) => {
  if (!validCoinId(req.params.coinId)) return res.status(400).json({ error: "Invalid coin ID." });
  const result = await pool.query(
    "DELETE FROM portfolio WHERE user_id=$1 AND coin_id=$2 RETURNING id", [req.user.id,req.params.coinId]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Portfolio holding not found." });
  res.json({ message: "Portfolio holding removed." });
}));

// -------------------- WATCHLIST --------------------

app.get("/api/watchlist", authenticateToken, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT id,coin_id,symbol,name,created_at FROM watchlist WHERE user_id=$1 ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json({ watchlist: result.rows });
}));

app.post("/api/watchlist", authenticateToken, asyncRoute(async (req, res) => {
  const { coin_id, symbol, name } = req.body || {};
  if (!validCoinId(coin_id) || !validText(symbol,20) || !validText(name,100)) {
    return res.status(400).json({ error: "Please provide valid coin details." });
  }
  const result = await pool.query(
    `INSERT INTO watchlist (user_id,coin_id,symbol,name) VALUES ($1,$2,$3,$4)
     ON CONFLICT (user_id,coin_id) DO NOTHING RETURNING *`,
    [req.user.id,coin_id,symbol.trim().toUpperCase(),name.trim()]
  );
  res.json({
    message: result.rowCount ? "Coin added to your watchlist." : "Coin is already in your watchlist.",
    coin: result.rows[0] || null
  });
}));

app.delete("/api/watchlist/:coinId", authenticateToken, asyncRoute(async (req, res) => {
  if (!validCoinId(req.params.coinId)) return res.status(400).json({ error: "Invalid coin ID." });
  const result = await pool.query(
    "DELETE FROM watchlist WHERE user_id=$1 AND coin_id=$2 RETURNING id", [req.user.id,req.params.coinId]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Coin not found in your watchlist." });
  res.json({ message: "Coin removed from watchlist." });
}));

// -------------------- SIMULATED TRADING WALLET --------------------

app.get("/api/trading/wallet", authenticateToken, asyncRoute(async (req, res) => {
  await pool.query(
    "INSERT INTO trading_wallets (user_id,balance) VALUES ($1,$2) ON CONFLICT (user_id) DO NOTHING",
    [req.user.id,STARTING_BALANCE]
  );
  const result = await pool.query(
    "SELECT balance,created_at,updated_at FROM trading_wallets WHERE user_id=$1", [req.user.id]
  );
  res.json({ wallet: result.rows[0], currency: "USD", trading_mode: "SIMULATED" });
}));

app.get("/api/trading/positions", authenticateToken, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id,coin_id,symbol,name,quantity,average_buy_price,created_at,updated_at
     FROM trading_positions WHERE user_id=$1 ORDER BY created_at DESC`, [req.user.id]
  );
  res.json({ positions: result.rows });
}));

// -------------------- BUY --------------------

app.post("/api/trading/buy", tradeRateLimit, authenticateToken, asyncRoute(async (req, res) => {
  const { coin_id, quantity } = req.body || {};
  if (!validCoinId(coin_id) || !validPositiveNumber(quantity)) {
    return res.status(400).json({ error: "Please provide a valid coin ID and quantity." });
  }
  const price = await getCoinPrice(coin_id);
  const { name, symbol } = await getCoinDetails(coin_id);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "INSERT INTO trading_wallets (user_id,balance) VALUES ($1,$2) ON CONFLICT (user_id) DO NOTHING",
      [req.user.id,STARTING_BALANCE]
    );
    const cost = await client.query(
      "SELECT ROUND($1::numeric*$2::numeric,12) AS total", [String(quantity),price]
    );
    const total = cost.rows[0].total;
    if (Number(total) <= 0) throw new Error("Order value is too small.");
    const wallet = await client.query(
      `UPDATE trading_wallets SET balance=balance-$2::numeric,updated_at=CURRENT_TIMESTAMP
       WHERE user_id=$1 AND balance >= $2::numeric RETURNING balance`,
      [req.user.id,total]
    );
    if (!wallet.rowCount) throw new Error("Insufficient virtual USD balance.");

    const position = await client.query(
      `INSERT INTO trading_positions (user_id,coin_id,symbol,name,quantity,average_buy_price)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (user_id,coin_id) DO UPDATE SET
         average_buy_price=ROUND(
           (trading_positions.quantity*trading_positions.average_buy_price+
            EXCLUDED.quantity*EXCLUDED.average_buy_price)/
           (trading_positions.quantity+EXCLUDED.quantity),12),
         quantity=trading_positions.quantity+EXCLUDED.quantity,
         updated_at=CURRENT_TIMESTAMP
       RETURNING *`,
      [req.user.id,coin_id,symbol,name,String(quantity),price]
    );
    const transaction = await client.query(
      `INSERT INTO trading_transactions
       (user_id,coin_id,symbol,name,transaction_type,quantity,price,total)
       VALUES ($1,$2,$3,$4,'BUY',$5,$6,$7) RETURNING *`,
      [req.user.id,coin_id,symbol,name,String(quantity),price,total]
    );
    await client.query("COMMIT");
    res.json({
      message: "Simulated BUY order completed.", trading_mode: "SIMULATED",
      transaction: transaction.rows[0], position: position.rows[0], wallet_balance: wallet.rows[0].balance
    });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: error.message || "Unable to complete simulated buy." });
  } finally {
    client.release();
  }
}));

// -------------------- SELL (FIXED) --------------------

app.post("/api/trading/sell", tradeRateLimit, authenticateToken, asyncRoute(async (req, res) => {
  const { coin_id, quantity } = req.body || {};
  if (!validCoinId(coin_id) || !validPositiveNumber(quantity)) {
    return res.status(400).json({ error: "Please provide a valid coin ID and quantity." });
  }
  const price = await getCoinPrice(coin_id);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const positionResult = await client.query(
      `SELECT * FROM trading_positions WHERE user_id=$1 AND coin_id=$2 FOR UPDATE`,
      [req.user.id,coin_id]
    );
    if (!positionResult.rowCount) throw new Error("You do not own this coin in simulated trading.");
    const position = positionResult.rows[0];

    // Compare decimal quantities in PostgreSQL, not JavaScript floating-point numbers.
    const check = await client.query(
      `SELECT ($1::numeric <= quantity) AS enough,
              ($1::numeric = quantity) AS sell_all
       FROM trading_positions WHERE user_id=$2 AND coin_id=$3`,
      [String(quantity),req.user.id,coin_id]
    );
    if (!check.rows[0].enough) throw new Error("Insufficient coin quantity to sell.");

    const totals = await client.query(
      `SELECT ROUND($1::numeric*$2::numeric,12) AS total,
              ROUND(($2::numeric-$3::numeric)*$1::numeric,12) AS realized_profit`,
      [String(quantity),price,position.average_buy_price]
    );
    const total = totals.rows[0].total;
    const realizedProfit = totals.rows[0].realized_profit;
    if (Number(total) <= 0) throw new Error("Order value is too small.");

    let remainingQuantity = "0";
    if (check.rows[0].sell_all) {
      // Delete directly: quantity has a CHECK(quantity > 0) constraint.
      await client.query(
        "DELETE FROM trading_positions WHERE user_id=$1 AND coin_id=$2",
        [req.user.id,coin_id]
      );
    } else {
      const update = await client.query(
        `UPDATE trading_positions SET quantity=quantity-$3::numeric,updated_at=CURRENT_TIMESTAMP
         WHERE user_id=$1 AND coin_id=$2 AND quantity>$3::numeric RETURNING quantity`,
        [req.user.id,coin_id,String(quantity)]
      );
      if (!update.rowCount) throw new Error("Unable to update simulated position.");
      remainingQuantity = update.rows[0].quantity;
    }

    const wallet = await client.query(
      `UPDATE trading_wallets SET balance=balance+$2::numeric,updated_at=CURRENT_TIMESTAMP
       WHERE user_id=$1 RETURNING balance`,
      [req.user.id,total]
    );
    if (!wallet.rowCount) throw new Error("Trading wallet not found.");

    const transaction = await client.query(
      `INSERT INTO trading_transactions
       (user_id,coin_id,symbol,name,transaction_type,quantity,price,total,realized_profit)
       VALUES ($1,$2,$3,$4,'SELL',$5,$6,$7,$8) RETURNING *`,
      [req.user.id,coin_id,position.symbol,position.name,String(quantity),price,total,realizedProfit]
    );
    await client.query("COMMIT");
    res.json({
      message: "Simulated SELL order completed.", trading_mode: "SIMULATED",
      transaction: transaction.rows[0], wallet_balance: wallet.rows[0].balance,
      remaining_quantity: remainingQuantity, realized_profit: realizedProfit
    });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: error.message || "Unable to complete simulated sell." });
  } finally {
    client.release();
  }
}));

app.get("/api/trading/transactions", authenticateToken, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id,coin_id,symbol,name,transaction_type,quantity,price,total,realized_profit,created_at
     FROM trading_transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
    [req.user.id]
  );
  res.json({ transactions: result.rows });
}));

app.get("/api/trading/summary", authenticateToken, asyncRoute(async (req, res) => {
  const wallet = await pool.query("SELECT balance FROM trading_wallets WHERE user_id=$1", [req.user.id]);
  const positions = await pool.query("SELECT COUNT(*) AS total_positions FROM trading_positions WHERE user_id=$1", [req.user.id]);
  const profits = await pool.query(
    `SELECT COALESCE(SUM(realized_profit),0) AS realized_profit,
      COUNT(*) FILTER (WHERE transaction_type='BUY') AS total_buys,
      COUNT(*) FILTER (WHERE transaction_type='SELL') AS total_sells
     FROM trading_transactions WHERE user_id=$1`, [req.user.id]
  );
  res.json({
    trading_mode: "SIMULATED", wallet_balance: wallet.rows[0]?.balance || "0",
    open_positions: Number(positions.rows[0].total_positions),
    realized_profit: profits.rows[0].realized_profit,
    total_buys: Number(profits.rows[0].total_buys),
    total_sells: Number(profits.rows[0].total_sells)
  });
}));

// -------------------- VLT REWARDS / DAILY MINING FOUNDATION --------------------

// Status is informational. A user must explicitly start a session.
// Rewards are demo points only, not cash or transferable cryptocurrency.
app.get("/api/rewards/status", authenticateToken, asyncRoute(async (req, res) => {
  await pool.query(
    "INSERT INTO reward_wallets (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING",
    [req.user.id]
  );
  const wallet = await pool.query(
    "SELECT balance,lifetime_earned FROM reward_wallets WHERE user_id=$1", [req.user.id]
  );
  const session = await pool.query(
    `SELECT id,started_at,ends_at,claimed_at,reward,
       (claimed_at IS NULL AND ends_at <= CURRENT_TIMESTAMP) AS claimable,
       (claimed_at IS NULL AND ends_at > CURRENT_TIMESTAMP) AS active
     FROM mining_sessions WHERE user_id=$1
     ORDER BY started_at DESC LIMIT 1`, [req.user.id]
  );
  res.json({
    reward_unit: "VLT demo points",
    cash_value: null,
    transferable: false,
    mining_duration_hours: MINING_DURATION_HOURS,
    reward_per_session: "24.000000000000",
    wallet: wallet.rows[0],
    session: session.rows[0] || null
  });
}));

app.post("/api/rewards/start", rewardRateLimit, authenticateToken, asyncRoute(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Protect the first session too: there may be no row available to lock yet.
    await client.query("SELECT pg_advisory_xact_lock($1::bigint)", [req.user.id]);
    const latest = await client.query(
      `SELECT id,ends_at,claimed_at FROM mining_sessions
       WHERE user_id=$1 ORDER BY started_at DESC LIMIT 1 FOR UPDATE`,
      [req.user.id]
    );
    if (latest.rowCount) {
      const previous = latest.rows[0];
      if (!previous.claimed_at && new Date(previous.ends_at).getTime() > Date.now()) {
        throw new Error("Your mining session is already active.");
      }
      if (!previous.claimed_at && new Date(previous.ends_at).getTime() <= Date.now()) {
        throw new Error("Your previous session is ready to claim before starting another.");
      }
    }
    const created = await client.query(
      `INSERT INTO mining_sessions (user_id,ends_at,reward)
       VALUES ($1,CURRENT_TIMESTAMP + INTERVAL '24 hours',24)
       RETURNING id,started_at,ends_at,reward`,
      [req.user.id]
    );
    await client.query("COMMIT");
    res.status(201).json({
      message: "Your 24-hour VLT demo rewards session has started.",
      session: created.rows[0],
      reward_unit: "VLT demo points",
      transferable: false
    });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
}));

app.post("/api/rewards/claim", rewardRateLimit, authenticateToken, asyncRoute(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const sessionResult = await client.query(
      `SELECT * FROM mining_sessions
       WHERE user_id=$1 AND claimed_at IS NULL
       ORDER BY started_at DESC LIMIT 1 FOR UPDATE`,
      [req.user.id]
    );
    if (!sessionResult.rowCount) throw new Error("There is no unclaimed mining session.");
    const session = sessionResult.rows[0];
    const ready = await client.query(
      "SELECT (ends_at <= CURRENT_TIMESTAMP) AS ready FROM mining_sessions WHERE id=$1",
      [session.id]
    );
    if (!ready.rows[0].ready) throw new Error("Your mining session is not finished yet.");

    await client.query(
      "UPDATE mining_sessions SET claimed_at=CURRENT_TIMESTAMP WHERE id=$1 AND claimed_at IS NULL",
      [session.id]
    );
    const wallet = await client.query(
      `UPDATE reward_wallets SET balance=balance+$2::numeric,
       lifetime_earned=lifetime_earned+$2::numeric,updated_at=CURRENT_TIMESTAMP
       WHERE user_id=$1 RETURNING balance,lifetime_earned`,
      [req.user.id,session.reward]
    );
    await client.query(
      `INSERT INTO reward_transactions (user_id,transaction_type,amount,description)
       VALUES ($1,'MINING_REWARD',$2,'Completed 24-hour VLT demo rewards session')`,
      [req.user.id,session.reward]
    );
    await client.query("COMMIT");
    res.json({
      message: "VLT demo points claimed successfully.",
      reward: session.reward,
      wallet: wallet.rows[0],
      reward_unit: "VLT demo points",
      transferable: false
    });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
}));

app.get("/api/rewards/history", authenticateToken, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id,transaction_type,amount,description,created_at
     FROM reward_transactions WHERE user_id=$1
     ORDER BY created_at DESC LIMIT 100`, [req.user.id]
  );
  res.json({ transactions: result.rows });
}));

// -------------------- LIVE MARKET --------------------

// CoinGecko OHLC data for the frontend candlestick chart.
app.get("/api/chart/:coinId", asyncRoute(async (req, res) => {
  const coinId = req.params.coinId;
  if (!validCoinId(coinId)) {
    return res.status(400).json({ error: "Invalid cryptocurrency ID." });
  }
  if (!API_KEY) {
    return res.status(503).json({ error: "CoinGecko API key is not configured." });
  }

  const allowedDays = new Set(["1", "7", "14", "30"]);
  const days = String(req.query.days || "1");
  if (!allowedDays.has(days)) {
    return res.status(400).json({ error: "Chart period must be 1, 7, 14, or 30 days." });
  }

  const url = "https://api.coingecko.com/api/v3/coins/" +
    encodeURIComponent(coinId) + "/ohlc?vs_currency=usd&days=" + days;
  const response = await fetch(url, {
    headers: { "x-cg-demo-api-key": API_KEY },
    signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) {
    console.error("CoinGecko chart request failed:", response.status);
    const status = response.status === 429 ? 429 :
      (response.status === 404 ? 404 : 502);
    return res.status(status).json({
      error: response.status === 429
        ? "Chart data limit reached. Please wait a moment and try again."
        : response.status === 404
          ? "Chart data is not available for this cryptocurrency."
          : "CoinGecko could not provide chart data right now. Please try again later."
    });
  }

  const rows = await response.json();
  if (!Array.isArray(rows)) {
    return res.status(502).json({ error: "CoinGecko returned an unexpected chart response." });
  }

  const candles = rows
    .filter(row => Array.isArray(row) && row.length >= 5)
    .map(row => ({
      time: Math.floor(Number(row[0]) / 1000),
      open: Number(row[1]),
      high: Number(row[2]),
      low: Number(row[3]),
      close: Number(row[4])
    }))
    .filter(c => Number.isFinite(c.time) && c.time > 0 &&
      Number.isFinite(c.open) && Number.isFinite(c.high) &&
      Number.isFinite(c.low) && Number.isFinite(c.close) &&
      c.open > 0 && c.high >= c.low && c.high >= c.open &&
      c.high >= c.close && c.low <= c.open && c.low <= c.close)
    .sort((a, b) => a.time - b.time);

  if (!candles.length) {
    return res.status(404).json({ error: "No chart data is available for this asset or period." });
  }
  res.setHeader("Cache-Control", "public, max-age=60");
  res.json({ candles });
}));

app.get("/api/coins", asyncRoute(async (req, res) => {
  if (!API_KEY) return res.status(500).json({ error: "CoinGecko API key is not configured." });
  const requestedPage = Number.parseInt(req.query.page, 10);
  const page = Number.isFinite(requestedPage) ? Math.max(1,Math.min(10,requestedPage)) : 1;
  const response = await fetch(
    `https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=250&page=${page}&sparkline=false`,
    { headers: { "x-cg-demo-api-key": API_KEY } }
  );
  if (!response.ok) return res.status(response.status).json({ error: "Unable to retrieve cryptocurrency market data." });
  res.json(await response.json());
}));

// -------------------- ADMIN, PREMIUM AND TOURNAMENTS --------------------

async function requireAdmin(req, res, next) {
  try {
    const result = await pool.query("SELECT role FROM veltro_admins WHERE user_id=$1", [req.user.id]);
    if (!result.rowCount) return res.status(403).json({ error: "Admin access required." });
    req.adminRole = result.rows[0].role;
    next();
  } catch (error) { next(error); }
}

app.get("/api/admin/overview", authenticateToken, requireAdmin, asyncRoute(async (req,res) => {
  const [users, premium, tournaments] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS total FROM users"),
    pool.query("SELECT COUNT(DISTINCT user_id)::int AS active FROM premium_subscriptions WHERE status='active' AND ends_at>NOW()"),
    pool.query("SELECT COUNT(*)::int AS total FROM trading_tournaments")
  ]);
  res.json({ role:req.adminRole, users:users.rows[0].total, activePremium:premium.rows[0].active, tournaments:tournaments.rows[0].total });
}));

app.get("/api/admin/users", authenticateToken, requireAdmin, asyncRoute(async (req,res) => {
  const result = await pool.query(`SELECT u.id,u.name,u.email,u.created_at,
    EXISTS(SELECT 1 FROM premium_subscriptions p WHERE p.user_id=u.id AND p.status='active' AND p.ends_at>NOW()) AS premium
    FROM users u ORDER BY u.created_at DESC LIMIT 200`);
  res.json({ users:result.rows });
}));

app.get("/api/premium/status", authenticateToken, asyncRoute(async (req,res) => {
  const result = await pool.query(`SELECT plan,status,starts_at,ends_at FROM premium_subscriptions
    WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1`, [req.user.id]);
  res.json({ subscription:result.rows[0] || null, plans:[{id:'monthly',durationDays:30},{id:'yearly',durationDays:365}] });
}));

// A subscription remains pending until a verified payment provider or owner activates it.
app.post("/api/premium/request", authenticateToken, asyncRoute(async (req,res) => {
  const plan = req.body && req.body.plan;
  if (!['monthly','yearly'].includes(plan)) return res.status(400).json({error:'Choose a valid premium plan.'});
  const result = await pool.query(`INSERT INTO premium_subscriptions(user_id,plan,status) VALUES($1,$2,'pending') RETURNING id,plan,status,created_at`, [req.user.id,plan]);
  res.status(201).json({subscription:result.rows[0],message:'Request received. Premium activates only after payment is verified.'});
}));

app.get("/api/tournaments", authenticateToken, asyncRoute(async (req,res) => {
  const result = await pool.query(`SELECT t.*,u.name AS winner_name,
    EXISTS(SELECT 1 FROM tournament_entries e WHERE e.tournament_id=t.id AND e.user_id=$1) AS joined
    FROM trading_tournaments t LEFT JOIN users u ON u.id=t.winner_user_id
    ORDER BY t.starts_at DESC LIMIT 30`, [req.user.id]);
  res.json({ tournaments:result.rows, tradingMode:'SIMULATED' });
}));

app.post("/api/tournaments/:id/join", authenticateToken, asyncRoute(async (req,res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id<1) return res.status(400).json({error:'Invalid tournament.'});
  const t = await pool.query("SELECT id,status,starts_at,ends_at FROM trading_tournaments WHERE id=$1",[id]);
  if (!t.rowCount || t.rows[0].status==='completed' || t.rows[0].status==='cancelled' || new Date(t.rows[0].ends_at)<=new Date()) return res.status(400).json({error:'This tournament is not open for joining.'});
  await pool.query("INSERT INTO tournament_entries(tournament_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING",[id,req.user.id]);
  res.json({message:'You joined the simulated trading tournament.'});
}));

app.get("/api/admin/tournaments", authenticateToken, requireAdmin, asyncRoute(async (req,res) => {
  const result = await pool.query(`SELECT t.*,u.name AS winner_name,(SELECT COUNT(*)::int FROM tournament_entries e WHERE e.tournament_id=t.id) AS participants
    FROM trading_tournaments t LEFT JOIN users u ON u.id=t.winner_user_id ORDER BY t.starts_at DESC LIMIT 50`);
  res.json({tournaments:result.rows});
}));

app.post("/api/admin/tournaments", authenticateToken, requireAdmin, asyncRoute(async (req,res) => {
  const {title,description,startsAt,endsAt,prizeAmount,prizeCurrency='USD'} = req.body || {};
  const start = new Date(startsAt), end = new Date(endsAt), prize = Number(prizeAmount);
  if (!validText(title,120) || !Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end<=start || !Number.isFinite(prize) || prize<0 || prize>1000000 || !/^[A-Z]{3,12}$/.test(prizeCurrency)) return res.status(400).json({error:'Check tournament title, dates and prize details.'});
  const result = await pool.query(`INSERT INTO trading_tournaments(title,description,starts_at,ends_at,prize_amount,prize_currency)
    VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,[title.trim(),String(description||'').slice(0,2000),start.toISOString(),end.toISOString(),prize,prizeCurrency]);
  res.status(201).json({tournament:result.rows[0]});
}));

app.post("/api/admin/premium/:subscriptionId/activate", authenticateToken, requireAdmin, asyncRoute(async (req,res) => {
  const id=Number(req.params.subscriptionId);
  if (!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'Invalid subscription.'});
  const result=await pool.query(`UPDATE premium_subscriptions SET status='active',starts_at=NOW(),
    ends_at=NOW()+CASE WHEN plan='yearly' THEN INTERVAL '365 days' ELSE INTERVAL '30 days' END
    WHERE id=$1 AND status='pending' RETURNING id,user_id,plan,status,starts_at,ends_at`,[id]);
  if (!result.rowCount) return res.status(404).json({error:'Pending subscription not found.'});
  res.json({subscription:result.rows[0]});
}));

app.post("/api/admin/tournaments/:id/complete", authenticateToken, requireAdmin, asyncRoute(async (req,res) => {
  const id=Number(req.params.id);
  const winnerId=Number(req.body && req.body.winnerUserId);
  if (!Number.isSafeInteger(id)||id<1||!Number.isSafeInteger(winnerId)||winnerId<1) return res.status(400).json({error:'Select a valid winner.'});
  const result=await pool.query(`UPDATE trading_tournaments t SET status='completed',winner_user_id=$2
    WHERE t.id=$1 AND t.status IN ('active','scheduled') AND t.ends_at<=NOW()
    AND EXISTS(SELECT 1 FROM tournament_entries e WHERE e.tournament_id=t.id AND e.user_id=$2)
    RETURNING t.*`,[id,winnerId]);
  if (!result.rowCount) return res.status(400).json({error:'Tournament must have ended and winner must be a participant.'});
  res.json({tournament:result.rows[0],message:'Winner recorded. Prize payout must be verified and handled separately.'});
}));

// -------------------- ERROR HANDLER --------------------

app.use((error, req, res, next) => {
  console.error("Unhandled API error:", error.message);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: "An unexpected server error occurred." });
});

// -------------------- START --------------------

async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`VELTRO API running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Database startup failed:", error.message);
    process.exit(1);
  }
}

startServer();
