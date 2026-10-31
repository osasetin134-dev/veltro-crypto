const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json({ limit: "10kb" }));

const API_KEY = process.env.COINGECKO_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET;

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

// DATABASE INITIALIZATION
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
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
    );
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
    );
  `);

  console.log("VELTRO database ready.");
}

// AUTHENTICATION
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Please log in to continue."
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired session."
    });
  }
}

// VALIDATION HELPERS
function validCoinId(value) {
  return typeof value === "string" &&
    /^[a-z0-9-]{1,100}$/.test(value);
}

function validText(value, maxLength) {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.trim().length <= maxLength;
}

function validPositiveNumber(value) {
  return (
    (typeof value === "number" || typeof value === "string") &&
    String(value).length <= 40 &&
    /^\d+(\.\d{1,18})?$/.test(String(value)) &&
    Number.isFinite(Number(value)) &&
    Number(value) > 0
  );
}

function validNonNegativeNumber(value) {
  return (
    (typeof value === "number" || typeof value === "string") &&
    String(value).length <= 40 &&
    /^\d+(\.\d{1,18})?$/.test(String(value)) &&
    Number.isFinite(Number(value)) &&
    Number(value) >= 0
  );
}

// HOME
app.get("/", (req, res) => {
  res.json({
    message: "VELTRO Crypto API is running!",
    status: "online"
  });
});

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Please provide valid registration details."
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 100) {
      return res.status(400).json({
        error: "Name must contain 2 to 100 characters."
      });
    }

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) ||
      cleanEmail.length > 255
    ) {
      return res.status(400).json({
        error: "Please enter a valid email address."
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        error: "Password must contain 8 to 72 characters."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, name, email, created_at`,
      [cleanName, cleanEmail, passwordHash]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({
      message: "VELTRO account created successfully!",
      token,
      user
    });

  } catch (error) {
    console.error("Registration error:", error.message);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email.length > 255 ||
      password.length > 72
    ) {
      return res.status(400).json({
        error: "Please provide a valid email and password."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [cleanEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const user = result.rows[0];

    const passwordMatch = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatch) {
      return res.status(401).json({
        error: "Incorrect email or password."
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful!",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        created_at: user.created_at
      }
    });

  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
      error: "Unable to log in."
    });
  }
});

// PERSONAL DASHBOARD
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, created_at
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "User account not found."
      });
    }

    res.json({
      user: result.rows[0]
    });

  } catch (error) {
    console.error("Dashboard error:", error.message);

    res.status(500).json({
      error: "Unable to load dashboard."
    });
  }
});

// ======================================
// VELTRO PORTFOLIO
// ======================================

// GET USER PORTFOLIO
app.get("/api/portfolio", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, coin_id, symbol, name, quantity,
              average_buy_price, created_at, updated_at
       FROM portfolio
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({
      portfolio: result.rows
    });

  } catch (error) {
    console.error("Portfolio error:", error.message);

    res.status(500).json({
      error: "Unable to load portfolio."
    });
  }
});

// ADD OR UPDATE A PORTFOLIO HOLDING
app.post("/api/portfolio", authenticateToken, async (req, res) => {
  try {
    const {
      coin_id,
      symbol,
      name,
      quantity,
      average_buy_price
    } = req.body;

    if (
      !validCoinId(coin_id) ||
      !validText(symbol, 20) ||
      !validText(name, 100) ||
      !validPositiveNumber(quantity) ||
      !validNonNegativeNumber(average_buy_price)
    ) {
      return res.status(400).json({
        error: "Please provide valid coin and holding details."
      });
    }

    const result = await pool.query(
      `INSERT INTO portfolio
       (user_id, coin_id, symbol, name, quantity, average_buy_price)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (user_id, coin_id)
       DO UPDATE SET
         symbol = EXCLUDED.symbol,
         name = EXCLUDED.name,
         quantity = EXCLUDED.quantity,
         average_buy_price = EXCLUDED.average_buy_price,
         updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [
        req.user.id,
        coin_id,
        symbol.trim().toUpperCase(),
        name.trim(),
        String(quantity),
        String(average_buy_price)
      ]
    );

    res.status(200).json({
      message: "Portfolio holding saved successfully.",
      holding: result.rows[0]
    });

  } catch (error) {
    console.error("Save portfolio error:", error.message);

    res.status(500).json({
      error: "Unable to save portfolio holding."
    });
  }
});

// REMOVE PORTFOLIO HOLDING
app.delete(
  "/api/portfolio/:coinId",
  authenticateToken,
  async (req, res) => {
    try {
      if (!validCoinId(req.params.coinId)) {
        return res.status(400).json({
          error: "Invalid coin ID."
        });
      }

      const result = await pool.query(
        `DELETE FROM portfolio
         WHERE user_id = $1 AND coin_id = $2
         RETURNING id`,
        [req.user.id, req.params.coinId]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "Portfolio holding not found."
        });
      }

      res.json({
        message: "Portfolio holding removed."
      });

    } catch (error) {
      console.error("Remove portfolio error:", error.message);

      res.status(500).json({
        error: "Unable to remove portfolio holding."
      });
    }
  }
);

// ======================================
// VELTRO WATCHLIST
// ======================================

// GET USER WATCHLIST
app.get("/api/watchlist", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, coin_id, symbol, name, created_at
       FROM watchlist
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({
      watchlist: result.rows
    });

  } catch (error) {
    console.error("Watchlist error:", error.message);

    res.status(500).json({
      error: "Unable to load watchlist."
    });
  }
});

// ADD COIN TO WATCHLIST
app.post("/api/watchlist", authenticateToken, async (req, res) => {
  try {
    const { coin_id, symbol, name } = req.body;

    if (
      !validCoinId(coin_id) ||
      !validText(symbol, 20) ||
      !validText(name, 100)
    ) {
      return res.status(400).json({
        error: "Please provide valid coin details."
      });
    }

    const result = await pool.query(
      `INSERT INTO watchlist (user_id, coin_id, symbol, name)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, coin_id) DO NOTHING
       RETURNING *`,
      [
        req.user.id,
        coin_id,
        symbol.trim().toUpperCase(),
        name.trim()
      ]
    );

    res.status(200).json({
      message: result.rowCount
        ? "Coin added to your watchlist."
        : "Coin is already in your watchlist.",
      coin: result.rows[0] || null
    });

  } catch (error) {
    console.error("Add watchlist error:", error.message);

    res.status(500).json({
      error: "Unable to add coin to watchlist."
    });
  }
});

// REMOVE COIN FROM WATCHLIST
app.delete(
  "/api/watchlist/:coinId",
  authenticateToken,
  async (req, res) => {
    try {
      if (!validCoinId(req.params.coinId)) {
        return res.status(400).json({
          error: "Invalid coin ID."
        });
      }

      const result = await pool.query(
        `DELETE FROM watchlist
         WHERE user_id = $1 AND coin_id = $2
         RETURNING id`,
        [req.user.id, req.params.coinId]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "Coin not found in your watchlist."
        });
      }

      res.json({
        message: "Coin removed from watchlist."
      });

    } catch (error) {
      console.error("Remove watchlist error:", error.message);

      res.status(500).json({
        error: "Unable to remove coin from watchlist."
      });
    }
  }
);

// ======================================
// LIVE CRYPTOCURRENCY MARKET
// ======================================

app.get("/api/coins", async (req, res) => {
  try {
    if (!API_KEY) {
      return res.status(500).json({
        error: "CoinGecko API key is not configured."
      });
    }

    const page = Math.max(
      1,
      Math.min(10, Number(req.query.page) || 1)
    );

    const response = await fetch(
      `https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=250&page=${page}&sparkline=false`,
      {
        headers: {
          "x-cg-demo-api-key": API_KEY
        }
      }
    );

    if (!response.ok) {
      return res.status(response.status).json({
        error: "Unable to retrieve cryptocurrency market data."
      });
    }

    const coins = await response.json();
    res.json(coins);

  } catch (error) {
    console.error("Market data error:", error.message);

    res.status(500).json({
      error: "Something went wrong while loading market data."
    });
  }
});

// HEALTH CHECK
app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "VELTRO API"
  });
});

// START SERVER
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
