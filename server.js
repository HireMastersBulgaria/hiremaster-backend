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

const stripe = new Stripe("sk_test_YOUR_KEY");

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
  } catch {
    res.sendStatus(403);
  }
};

// REGISTER
app.post("/api/register", async (req, res) => {
  const { email, password, companyName } = req.body;
  const hash = await bcrypt.hash(password, 10);

  const customer = await stripe.customers.create({ email });

  const company = await pool.query(
    "INSERT INTO companies(name,stripe_customer_id) VALUES($1,$2) RETURNING *",
    [companyName, customer.id]
  );

  const user = await pool.query(
    "INSERT INTO users(email,password,company_id,role) VALUES($1,$2,$3,$4) RETURNING *",
    [email, hash, company.rows[0].id, "admin"]
  );

  res.json(user.rows[0]);
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (!user.rows.length) return res.sendStatus(401);

  const valid = await bcrypt.compare(password, user.rows[0].password);
  if (!valid) return res.sendStatus(401);

  const token = jwt.sign(user.rows[0], JWT_SECRET);
  res.json({ token });
});

// CREATE POSITION
app.post("/api/positions", auth, async (req, res) => {
  const { title } = req.body;

  const result = await pool.query(
    "INSERT INTO positions(title,company_id) VALUES($1,$2) RETURNING *",
    [title, req.user.company_id]
  );

  res.json(result.rows[0]);
});

// GET POSITIONS
app.get("/api/positions", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM positions WHERE company_id=$1",
    [req.user.company_id]
  );

  res.json(result.rows);
});

// CREATE CHECKOUT
app.post("/api/create-checkout", auth, async (req, res) => {
  const company = await pool.query(
    "SELECT * FROM companies WHERE id=$1",
    [req.user.company_id]
  );

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
});

// DASHBOARD
app.get("/api/dashboard", auth, async (req, res) => {
  const companyId = req.user.company_id;

  const positions = await pool.query(
    "SELECT COUNT(*) FROM positions WHERE company_id=$1",
    [companyId]
  );

  const candidates = await pool.query(
    "SELECT COUNT(*) FROM candidates WHERE company_id=$1",
    [companyId]
  );

  res.json({
    positions: positions.rows[0].count,
    candidates: candidates.rows[0].count
  });
});

app.listen(4000, () => console.log("Server running"));