const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

const API_KEY = process.env.COINGECKO_API_KEY;

app.get("/", (req, res) => {
  res.json({
    message: "VELTRO Crypto API is running!",
    status: "online"
  });
});

app.get("/api/coins", async (req, res) => {
  try {
    if (!API_KEY) {
      return res.status(500).json({
        error: "CoinGecko API key is not configured."
      });
    }

    const page = Math.max(1, Math.min(10, Number(req.query.page) || 1));

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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`VELTRO API running on port ${PORT}`);
});
