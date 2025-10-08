// server.js
// Hardened backend for multi-tenant products + orders (Node + Express + Postgres)
// Run: node server.js
// Required env variables (production):
// PG_HOST, PG_PORT, PG_DATABASE, PG_USER, PG_PASSWORD, JWT_SECRET
// Optional: JWT_EXPIRES_IN, CORS_ORIGIN, AZURE_STORAGE_CONNECTION_STRING, AZURE_CONTAINER_NAME, ENABLE_RLS

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { Pool } = require("pg");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { BlobServiceClient } = require("@azure/storage-blob");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());
app.use(helmet());

// CORS origin
const allowedOrigin = process.env.CORS_ORIGIN || "*";
app.use(cors({ origin: allowedOrigin }));

// Enforce required env vars in production
if (!process.env.JWT_SECRET || process.env.JWT_SECRET === "change-me") {
  console.error("FATAL: JWT_SECRET must be set to a secure value in environment.");
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";

// Postgres pool
const pool = new Pool({
  host: process.env.PG_HOST || "localhost",
  port: Number(process.env.PG_PORT || 5432),
  database: process.env.PG_DATABASE || "postgres",
  user: process.env.PG_USER || "postgres",
  password: process.env.PG_PASSWORD || "postgres",
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Azure Blob (optional)
const AZURE_CONN = process.env.AZURE_STORAGE_CONNECTION_STRING;
const AZURE_CONTAINER = process.env.AZURE_CONTAINER_NAME || "product-images";
let containerClient = null;
if (AZURE_CONN) {
  try {
    const blobServiceClient = BlobServiceClient.fromConnectionString(AZURE_CONN);
    containerClient = blobServiceClient.getContainerClient(AZURE_CONTAINER);
  } catch (err) {
    console.warn("Azure Blob init failed:", err.message || err);
    containerClient = null;
  }
}

// Multer config: use disk storage to avoid OOM; validate file types
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safeName = `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, "")}`;
    cb(null, safeName);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 12 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    // Accept common image types only
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed"));
    }
    cb(null, true);
  },
});

// Rate limiters
const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: { message: "Too many requests, slow down" } });

// ------------------- Utilities -------------------
function signToken(user) {
  const payload = { id: user.id, email: user.email, organizationId: user.organizationId };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

async function authenticateJWT(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ message: "Missing authorization" });
    const token = auth.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.id, email: decoded.email, organizationId: decoded.organizationId };
    return next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// Only use transactions for writes. Helper:
async function withTransaction(clientCallback) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const rv = await clientCallback(client);
    await client.query("COMMIT");
    return rv;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

// Convert row keys snake_case -> camelCase
function toCamel(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const out = {};
  for (const k of Object.keys(obj)) {
    const camel = k.replace(/_([a-z])/g, (m, p) => p.toUpperCase());
    out[camel] = obj[k];
  }
  return out;
}

// Standardized internal server error logger + user-safe message
function handleServerError(res, err, context = "") {
  console.error(context || "Server error:", err);
  return res.status(500).json({ message: "Internal server error" });
}

// ------------------- Ensure tables / triggers -------------------
async function ensureTablesAndConstraints() {
  // Use a single client for schema changes
  const client = await pool.connect();
  try {
    // organization_accounts
    await client.query(`
      CREATE TABLE IF NOT EXISTS organization_accounts (
        id SERIAL PRIMARY KEY,
        organization_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        username VARCHAR(50) NOT NULL UNIQUE,
        password TEXT NOT NULL,
        contact_number VARCHAR(32),
        pan_number VARCHAR(32),
        location VARCHAR(255),
        accept_terms BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // login table
    await client.query(`
      CREATE TABLE IF NOT EXISTS login (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password TEXT NOT NULL,
        organization_id INT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // products
    await client.query(`
      CREATE TABLE IF NOT EXISTS products (
        product_id SERIAL PRIMARY KEY,
        owner_id INT REFERENCES organization_accounts(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price NUMERIC(12,2) NOT NULL DEFAULT 0,
        stock INT NOT NULL DEFAULT 0,
        image_url TEXT,
        orders_received INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_products_owner_id ON products(owner_id);`);

    // orders
    await client.query(`
      CREATE TABLE IF NOT EXISTS orders (
        order_id SERIAL PRIMARY KEY,
        owner_id INT REFERENCES organization_accounts(id) ON DELETE CASCADE,
        customer_name VARCHAR(255) NOT NULL,
        purchased_items TEXT,
        order_status VARCHAR(20) NOT NULL DEFAULT 'Pending',
        payment_status VARCHAR(20) NOT NULL DEFAULT 'Unpaid',
        order_date TIMESTAMP,
        delivery_date TIMESTAMP,
        remarks TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_orders_owner_id ON orders(owner_id);`);

    // order_audit with FK to orders
    await client.query(`
      CREATE TABLE IF NOT EXISTS order_audit (
        id SERIAL PRIMARY KEY,
        order_id INT NOT NULL,
        owner_id INT NOT NULL,
        action VARCHAR(50) NOT NULL,
        changed_by_login_id INT,
        old_value JSONB,
        new_value JSONB,
        note TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT fk_order_audit_order FOREIGN KEY (order_id) REFERENCES orders(order_id) ON DELETE CASCADE
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_order_audit_order_id ON order_audit(order_id);`);

    // updated_at trigger function and triggers for tables that have updated_at
    await client.query(`
      CREATE OR REPLACE FUNCTION trigger_set_updated_at()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `);

    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_trigger WHERE tgname = 'products_set_updated_at'
        ) THEN
          CREATE TRIGGER products_set_updated_at
          BEFORE UPDATE ON products
          FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();
        END IF;

        IF NOT EXISTS (
          SELECT 1 FROM pg_trigger WHERE tgname = 'orders_set_updated_at'
        ) THEN
          CREATE TRIGGER orders_set_updated_at
          BEFORE UPDATE ON orders
          FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();
        END IF;
      END $$;
    `);

    // Optional: recommended RLS setup if ENABLE_RLS=true (does nothing if not set)
    if (process.env.ENABLE_RLS === "true") {
      // Note: enabling RLS is irreversible for existing apps unless you carefully manage policies.
      // These policies assume current_setting('app.current_owner') is set per-transaction by the app.
      await client.query(`ALTER TABLE IF EXISTS products ENABLE ROW LEVEL SECURITY;`);
      await client.query(`
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname = 'org_products_policy') THEN
            CREATE POLICY org_products_policy ON products USING (owner_id = current_setting('app.current_owner')::int);
          END IF;
        END $$;
      `);
      await client.query(`ALTER TABLE IF EXISTS orders ENABLE ROW LEVEL SECURITY;`);
      await client.query(`
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname = 'org_orders_policy') THEN
            CREATE POLICY org_orders_policy ON orders USING (owner_id = current_setting('app.current_owner')::int);
          END IF;
        END $$;
      `);
    }

    console.log("✅ Tables & triggers ensured");
  } finally {
    client.release();
  }
}

// ------------------- AUTH ROUTES -------------------

app.get("/api/register", (req, res) => res.status(200).json({ message: "POST /api/register to create an account" }));

app.post("/api/register", authLimiter, async (req, res) => {
  const {
    organizationName,
    email,
    password,
    confirmPassword,
    username,
    contactNumber,
    panNumber,
    location,
    acceptTerms,
  } = req.body || {};

  try {
    // Basic required checks
    if (!organizationName || !email || !password || !confirmPassword || !username || !contactNumber || !panNumber || !location || acceptTerms !== true) {
      return res.status(400).json({ message: "All fields required and terms must be accepted" });
    }
    if (password !== confirmPassword) return res.status(400).json({ message: "Passwords do not match" });

    // Contact number: digits only, min length 7
    if (!/^\d{7,}$/.test(contactNumber)) return res.status(400).json({ message: "Invalid contact number format" });

    // Password policy: min 8 chars, at least 1 uppercase, 1 number
    if (password.length < 8 || !/[A-Z]/.test(password) || !/\d/.test(password)) {
      return res.status(400).json({ message: "Password must be at least 8 characters, include an uppercase letter and a number" });
    }

    const saltRounds = 12;
    const hash = await bcrypt.hash(password, saltRounds);

    const result = await withTransaction(async (client) => {
      const insertOrg = `INSERT INTO organization_accounts (organization_name, email, username, password, contact_number, pan_number, location, accept_terms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id;`;
      const orgRes = await client.query(insertOrg, [organizationName, email, username, hash, contactNumber, panNumber.toUpperCase(), location, acceptTerms]);
      const orgId = orgRes.rows[0].id;

      const insertLogin = `INSERT INTO login (email, password, organization_id) VALUES ($1,$2,$3) RETURNING id, email, organization_id;`;
      const loginRes = await client.query(insertLogin, [email, hash, orgId]);

      return { id: loginRes.rows[0].id, email: loginRes.rows[0].email, organizationId: loginRes.rows[0].organization_id };
    });

    return res.status(201).json({ message: "Registered", user: result });
  } catch (err) {
    // handle unique violation cleanly
    if (err && err.code === "23505") {
      return res.status(409).json({ message: "Duplicate value", detail: err.detail || null });
    }
    return handleServerError(res, err, "Register error:");
  }
});


// Require authenticateJWT middleware and return a consistent object
app.get("/api/details", authenticateJWT, async (req, res) => {
  try {
    const orgId = Number(req.user?.organizationId || 0);
    if (!orgId) return res.status(401).json({ message: "Unauthorized (missing organization)" });

    const query = `
      SELECT
        id,
        organization_name,
        username,
        email,
        contact_number,
        pan_number
      FROM organization_accounts
      WHERE id = $1
      LIMIT 1
    `;
    const result = await pool.query(query, [orgId]);

    if (result.rows.length === 0) return res.status(404).json({ message: "Organization not found" });

    const row = result.rows[0];

    // map to front-end shape (choose names front expects)
    const out = {
      fullName: row.organization_name, // if you want a different mapping change on frontend
      username: row.username,
      companyName: row.organization_name,
      email: row.email,
      contactNumber: row.contact_number,
      panNumber: row.pan_number,
      accountCreatedDate: row.created_at,
    };

    return res.json(out);
  } catch (err) {
    console.error("Error fetching details:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});


app.post("/api/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: "Email and password required" });

  try {
    const result = await pool.query("SELECT id, email, password, organization_id FROM login WHERE email = $1", [email]);
    if (result.rows.length === 0) return res.status(401).json({ message: "Invalid email or password" });

    const row = result.rows[0];
    const stored = row.password;
    let passwordMatches = false;
    let needsRehash = false;

    if (typeof stored === "string" && stored.startsWith("$2")) {
      passwordMatches = await bcrypt.compare(password, stored);
    } else {
      // legacy plaintext (shouldn't happen, but support rehash)
      if (password === stored) {
        passwordMatches = true;
        needsRehash = true;
      }
    }
    if (!passwordMatches) return res.status(401).json({ message: "Invalid email or password" });

    if (needsRehash) {
      try {
        const newHash = await bcrypt.hash(password, 12);
        await pool.query("UPDATE login SET password = $1 WHERE id = $2", [newHash, row.id]);
        await pool.query("UPDATE organization_accounts SET password = $1 WHERE id = $2", [newHash, row.organization_id]).catch(() => {});
      } catch (e) {
        console.warn("Rehash failed:", e);
      }
    }

    const user = { id: row.id, email: row.email, organizationId: row.organization_id };
    const token = signToken(user);
    return res.status(200).json({ user, token });
  } catch (err) {
    return handleServerError(res, err, "Login error:");
  }
});

// ------------------- PRODUCTS -------------------

// List products (simple read, no transaction overhead)
app.get("/api/products", authenticateJWT, async (req, res) => {
  const ownerId = Number(req.user.organizationId || 0);
  if (!ownerId) return res.status(400).json({ message: "Invalid organization" });

  try {
    const q = `
      SELECT product_id, owner_id, name, description, price, stock, image_url, orders_received, created_at, updated_at
      FROM products WHERE owner_id = $1 ORDER BY created_at DESC;
    `;
    const result = await pool.query(q, [ownerId]);
    const rows = result.rows.map((r) => {
      const c = toCamel(r);
      // normalize types
      c.id = String(r.product_id);
      c.price = Number(r.price);
      c.stock = Number(r.stock || 0);
      c.ordersReceived = Number(r.orders_received || 0);
      return c;
    });
    return res.json(rows);
  } catch (err) {
    return handleServerError(res, err, "GET /api/products error:");
  }
});

// POST product (multipart) - writes use transaction and set local owner for RLS if enabled
app.post("/api/products", authenticateJWT, upload.single("image"), async (req, res) => {
  const ownerId = Number(req.user.organizationId || 0);
  if (!ownerId) return res.status(400).json({ message: "Invalid organization" });

  const { name, description = "", price = "0", stock = "0" } = req.body || {};
  if (!name || price == null || stock == null) return res.status(400).json({ message: "name, price, stock required" });

  try {
    // If uploaded to disk and Azure is configured, push to blob and remove local file
    let imageUrl = null;
    if (req.file) {
      if (containerClient) {
        // upload and then delete local file
        const safeName = `${ownerId}/${Date.now()}-${req.file.filename}`;
        const blockBlobClient = containerClient.getBlockBlobClient(safeName);
        const buffer = fs.readFileSync(req.file.path);
        await blockBlobClient.uploadData(buffer, { blobHTTPHeaders: { blobContentType: req.file.mimetype || "application/octet-stream" } });
        imageUrl = blockBlobClient.url;
        // remove local file
        fs.unlink(req.file.path, () => {});
      } else {
        // fallback: keep a local static path (not recommended for prod)
        imageUrl = `/uploads/${req.file.filename}`;
      }
    }

    const created = await withTransaction(async (client) => {
      // If RLS enabled on DB, set local app.current_owner for policy evaluation
      try {
        await client.query(`SET LOCAL app.current_owner = '${ownerId}'`);
      } catch (_) {}

      const insertQ = `INSERT INTO products (owner_id, name, description, price, stock, image_url) VALUES ($1,$2,$3,$4,$5,$6) RETURNING product_id, owner_id, name, description, price, stock, image_url, orders_received, created_at, updated_at;`;
      const vals = [ownerId, name, description, price, stock, imageUrl];
      const r = (await client.query(insertQ, vals)).rows[0];
      const out = toCamel(r);
      out.id = String(r.product_id);
      out.price = Number(r.price);
      out.stock = Number(r.stock);
      out.ordersReceived = Number(r.orders_received || 0);
      return out;
    });

    return res.status(201).json(created);
  } catch (err) {
    return handleServerError(res, err, "POST /api/products error:");
  }
});

// PATCH stock (decrement) - transactional
app.patch("/api/products/:id/stock", authenticateJWT, async (req, res) => {
  const ownerId = Number(req.user.organizationId || 0);
  if (!ownerId) return res.status(400).json({ message: "Invalid organization" });
  const productId = Number(req.params.id);
  const { quantity } = req.body || {};
  const qty = Number(quantity || 1);
  if (!productId || qty <= 0) return res.status(400).json({ message: "Invalid product id or quantity" });

  try {
    const updated = await withTransaction(async (client) => {
      await client.query(`SET LOCAL app.current_owner = '${ownerId}'`).catch(() => {});
      const check = await client.query("SELECT stock, orders_received FROM products WHERE product_id = $1 AND owner_id = $2 FOR UPDATE", [productId, ownerId]);
      if (check.rows.length === 0) throw { status: 404, message: "Product not found" };
      const currentStock = Number(check.rows[0].stock || 0);
      const newStock = currentStock - qty;
      if (newStock < 0) throw { status: 400, message: "Insufficient stock" };
      const upd = await client.query("UPDATE products SET stock = $1, orders_received = COALESCE(orders_received,0)+$2 WHERE product_id = $3 AND owner_id = $4 RETURNING product_id, stock, orders_received;", [newStock, qty, productId, ownerId]);
      const r = upd.rows[0];
      return { id: String(r.product_id), stock: Number(r.stock), ordersReceived: Number(r.orders_received || 0) };
    });
    return res.json(updated);
  } catch (err) {
    if (err && err.status) return res.status(err.status).json({ message: err.message });
    return handleServerError(res, err, "PATCH /api/products/:id/stock error:");
  }
});

// ------------------- ORDERS -------------------

// GET orders (reads)
app.get("/api/orders", authenticateJWT, async (req, res) => {
  const ownerId = Number(req.user.organizationId || 0);
  if (!ownerId) return res.status(400).json({ message: "Invalid organization" });

  try {
    const q = `SELECT order_id, owner_id, customer_name, purchased_items, order_status, payment_status, order_date, delivery_date, remarks, created_at, updated_at FROM orders WHERE owner_id = $1 ORDER BY created_at DESC;`;
    const result = await pool.query(q, [ownerId]);
    const rows = result.rows.map((r) => {
      const c = toCamel(r);
      c.id = String(r.order_id);
      return c;
    });
    return res.json(rows);
  } catch (err) {
    return handleServerError(res, err, "GET /api/orders error:");
  }
});

// POST order (create + audit)
app.post("/api/orders", authenticateJWT, async (req, res) => {
  const ownerId = Number(req.user.organizationId || 0);
  const loginId = Number(req.user.id || 0);
  if (!ownerId) return res.status(400).json({ message: "Invalid organization" });

  const {
    customerName,
    purchasedItems = "",
    orderStatus = "Pending",
    paymentStatus = "Unpaid",
    orderDate = null,
    deliveryDate = null,
    remarks = "",
  } = req.body || {};

  if (!customerName) return res.status(400).json({ message: "customerName required" });

  const allowedOrderStatuses = ["Delivered", "Pending", "Cancelled"];
  const allowedPaymentStatuses = ["Paid", "Unpaid", "Refunded"];
  if (!allowedOrderStatuses.includes(orderStatus)) return res.status(400).json({ message: "Invalid orderStatus" });
  if (!allowedPaymentStatuses.includes(paymentStatus)) return res.status(400).json({ message: "Invalid paymentStatus" });

  try {
    const created = await withTransaction(async (client) => {
      await client.query(`SET LOCAL app.current_owner = '${ownerId}'`).catch(() => {});
      const q = `INSERT INTO orders (owner_id, customer_name, purchased_items, order_status, payment_status, order_date, delivery_date, remarks) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING order_id, owner_id, customer_name, purchased_items, order_status, payment_status, order_date, delivery_date, remarks, created_at, updated_at;`;
      const vals = [ownerId, customerName, purchasedItems, orderStatus, paymentStatus, orderDate, deliveryDate, remarks];
      const r = (await client.query(q, vals)).rows[0];

      const auditQ = `INSERT INTO order_audit (order_id, owner_id, action, changed_by_login_id, old_value, new_value, note) VALUES ($1,$2,$3,$4,$5,$6,$7)`;
      await client.query(auditQ, [r.order_id, ownerId, "create", loginId, null, JSON.stringify(r), `Created by login ${loginId}`]);

      const out = toCamel(r);
      out.id = String(r.order_id);
      return out;
    });

    return res.status(201).json(created);
  } catch (err) {
    return handleServerError(res, err, "POST /api/orders error:");
  }
});

// PATCH order status
app.patch("/api/orders/:id/status", authenticateJWT, async (req, res) => {
  const ownerId = Number(req.user.organizationId || 0);
  const loginId = Number(req.user.id || 0);
  const orderId = Number(req.params.id);
  const { orderStatus } = req.body || {};
  if (!ownerId) return res.status(400).json({ message: "Invalid organization" });
  if (!orderId || !orderStatus) return res.status(400).json({ message: "orderId and orderStatus required" });

  const allowedOrderStatuses = ["Delivered", "Pending", "Cancelled"];
  if (!allowedOrderStatuses.includes(orderStatus)) return res.status(400).json({ message: "Invalid orderStatus" });

  try {
    const updated = await withTransaction(async (client) => {
      await client.query(`SET LOCAL app.current_owner = '${ownerId}'`).catch(() => {});
      const check = await client.query("SELECT order_status FROM orders WHERE order_id = $1 AND owner_id = $2 FOR UPDATE", [orderId, ownerId]);
      if (check.rows.length === 0) throw { status: 404, message: "Order not found" };
      const oldStatus = check.rows[0].order_status;
      if (oldStatus === orderStatus) return { id: String(orderId), orderStatus: oldStatus };

      const upd = await client.query("UPDATE orders SET order_status = $1 WHERE order_id = $2 AND owner_id = $3 RETURNING order_id, order_status, updated_at", [orderStatus, orderId, ownerId]);
      const r = upd.rows[0];

      const auditQ = `INSERT INTO order_audit (order_id, owner_id, action, changed_by_login_id, old_value, new_value, note) VALUES ($1,$2,$3,$4,$5,$6,$7)`;
      await client.query(auditQ, [orderId, ownerId, "update_status", loginId, JSON.stringify({ order_status: oldStatus }), JSON.stringify({ order_status: r.order_status }), `Status changed ${oldStatus} -> ${r.order_status} by login ${loginId}`]);

      return { id: String(r.order_id), orderStatus: r.order_status, updatedAt: r.updated_at };
    });

    return res.json(updated);
  } catch (err) {
    if (err && err.status) return res.status(err.status).json({ message: err.message });
    return handleServerError(res, err, "PATCH /api/orders/:id/status error:");
  }
});

// PATCH payment status
app.patch("/api/orders/:id/payment", authenticateJWT, async (req, res) => {
  const ownerId = Number(req.user.organizationId || 0);
  const loginId = Number(req.user.id || 0);
  const orderId = Number(req.params.id);
  const { paymentStatus } = req.body || {};
  if (!ownerId) return res.status(400).json({ message: "Invalid organization" });
  if (!orderId || !paymentStatus) return res.status(400).json({ message: "orderId and paymentStatus required" });

  const allowedPaymentStatuses = ["Paid", "Unpaid", "Refunded"];
  if (!allowedPaymentStatuses.includes(paymentStatus)) return res.status(400).json({ message: "Invalid paymentStatus" });

  try {
    const updated = await withTransaction(async (client) => {
      await client.query(`SET LOCAL app.current_owner = '${ownerId}'`).catch(() => {});
      const check = await client.query("SELECT payment_status FROM orders WHERE order_id = $1 AND owner_id = $2 FOR UPDATE", [orderId, ownerId]);
      if (check.rows.length === 0) throw { status: 404, message: "Order not found" };
      const oldPayment = check.rows[0].payment_status;
      if (oldPayment === paymentStatus) return { id: String(orderId), paymentStatus: oldPayment };

      const upd = await client.query("UPDATE orders SET payment_status = $1 WHERE order_id = $2 AND owner_id = $3 RETURNING order_id, payment_status, updated_at", [paymentStatus, orderId, ownerId]);
      const r = upd.rows[0];

      const auditQ = `INSERT INTO order_audit (order_id, owner_id, action, changed_by_login_id, old_value, new_value, note) VALUES ($1,$2,$3,$4,$5,$6,$7)`;
      await client.query(auditQ, [orderId, ownerId, "update_payment", loginId, JSON.stringify({ payment_status: oldPayment }), JSON.stringify({ payment_status: r.payment_status }), `Payment changed ${oldPayment} -> ${r.payment_status} by login ${loginId}`]);

      return { id: String(r.order_id), paymentStatus: r.payment_status, updatedAt: r.updated_at };
    });

    return res.json(updated);
  } catch (err) {
    if (err && err.status) return res.status(err.status).json({ message: err.message });
    return handleServerError(res, err, "PATCH /api/orders/:id/payment error:");
  }
});

// GET order audit entries
app.get("/api/order-audit/:orderId", authenticateJWT, async (req, res) => {
  const ownerId = Number(req.user.organizationId || 0);
  const orderId = Number(req.params.orderId);
  if (!ownerId) return res.status(400).json({ message: "Invalid organization" });
  if (!orderId) return res.status(400).json({ message: "Invalid order id" });

  try {
    const q = `SELECT id, order_id, owner_id, action, changed_by_login_id, old_value, new_value, note, created_at FROM order_audit WHERE order_id = $1 AND owner_id = $2 ORDER BY created_at DESC;`;
    const result = await pool.query(q, [orderId, ownerId]);
    return res.json(result.rows.map(toCamel));
  } catch (err) {
    return handleServerError(res, err, "GET /api/order-audit error:");
  }
});

// Health
app.get("/api/health", (req, res) => res.json({ ok: true }));

// ------------------- Init -------------------
async function init() {
  try {
    await pool.connect();
    console.log("✅ PostgreSQL pool connected");
    await ensureTablesAndConstraints();
    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));
  } catch (err) {
    console.error("Fatal init error:", err);
    process.exit(1);
  }
}

init();
