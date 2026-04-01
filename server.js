import express from "express";
import cors from "cors";
import pkg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Stripe from "stripe";

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("HireMaster backend is running 🚀");
});

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const JWT_SECRET = process.env.JWT_SECRET || "secret123";

// AUTH MIDDLEWARE
const auth = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(401);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    res.sendStatus(403);
  }
};

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { email, password, companyName } = req.body;

    if (!email || !password || !companyName) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const existingUser = await pool.query(
      "SELECT * FROM public.users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hash = await bcrypt.hash(password, 10);

    const customer = await stripe.customers.create({ email });

    const company = await pool.query(
      "INSERT INTO public.companies (name, stripe_customer_id) VALUES ($1, $2) RETURNING *",
      [companyName, customer.id]
    );

    const user = await pool.query(
      "INSERT INTO public.users (email, password, company_id, role) VALUES ($1, $2, $3, $4) RETURNING *",
      [email, hash, company.rows[0].id, "admin"]
    );

    res.status(201).json(user.rows[0]);
  } catch (error) {
    console.error("REGISTER ERROR:", error);
    res.status(500).json({
      error: "Register failed",
      details: error.message
    });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await pool.query(
      "SELECT * FROM public.users WHERE email = $1",
      [email]
    );

    if (!user.rows.length) {
      return res.sendStatus(401);
    }

    const valid = await bcrypt.compare(password, user.rows[0].password);
    if (!valid) {
      return res.sendStatus(401);
    }

    const token = jwt.sign(user.rows[0], JWT_SECRET);
    res.json({ token });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({
      error: "Login failed",
      details: error.message
    });
  }
});

// CREATE POSITION
app.post("/api/positions", auth, async (req, res) => {
  try {
    const { title } = req.body;

    const result = await pool.query(
      "INSERT INTO public.positions (title, company_id) VALUES ($1, $2) RETURNING *",
      [title, req.user.company_id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error("CREATE POSITION ERROR:", error);
    res.status(500).json({
      error: "Create position failed",
      details: error.message
    });
  }
});

// GET POSITIONS
app.get("/api/positions", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM public.positions WHERE company_id = $1",
      [req.user.company_id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("GET POSITIONS ERROR:", error);
    res.status(500).json({
      error: "Get positions failed",
      details: error.message
    });
  }
});

// CREATE CHECKOUT
app.post("/api/create-checkout", auth, async (req, res) => {
  try {
    const company = await pool.query(
      "SELECT * FROM public.companies WHERE id = $1",
      [req.user.company_id]
    );

    if (!company.rows.length) {
      return res.status(404).json({ error: "Company not found" });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "subscription",
      customer: company.rows[0].stripe_customer_id,
      line_items: [
        {
          price: "price_12345",
          quantity: 1
        }
      ],
      success_url: "http://localhost:3000/success",
      cancel_url: "http://localhost:3000/cancel"
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error("CHECKOUT ERROR:", error);
    res.status(500).json({
      error: "Checkout failed",
      details: error.message
    });
  }
});

// DASHBOARD
app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const companyId = req.user.company_id;

    const positions = await pool.query(
      "SELECT COUNT(*) FROM public.positions WHERE company_id = $1",
      [companyId]
    );

    const candidates = await pool.query(
      "SELECT COUNT(*) FROM public.candidates WHERE company_id = $1",
      [companyId]
    );

    res.json({
      positions: positions.rows[0].count,
      candidates: candidates.rows[0].count
    });
  } catch (error) {
    console.error("DASHBOARD ERROR:", error);
    res.status(500).json({
      error: "Dashboard failed",
      details: error.message
    });
  }
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
