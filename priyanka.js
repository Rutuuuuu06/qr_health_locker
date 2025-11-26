/* ---------------------------------------------------------
   IMPORTS
-----------------------------------------------------------*/
const express = require("express");
const multer = require("multer");
const path = require("path");
const { Pool } = require("pg");
const QRCode = require("qrcode");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const fs = require("fs");
const os = require("os");

const app = express();

/* ---------------------------------------------------------
   HELPER: LOCAL IP (for local testing)
-----------------------------------------------------------*/
function getLocalIP() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === "IPv4" && !net.internal) {
        return net.address;
      }
    }
  }
  return "localhost";
}

/* ---------------------------------------------------------
   HELPER: NICE ERROR / MESSAGE PAGES
-----------------------------------------------------------*/
function renderMessagePage(title, message, backHref, backLabel) {
  return `
    <html>
    <head>
      <meta charset="UTF-8" />
      <title>${title}</title>
      <style>
        body {
          margin: 0;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
          background:#e8f0fe;
        }
        .wrap {
          max-width: 640px;
          margin: 60px auto;
          padding: 0 16px;
        }
        .card {
          background:#ffffff;
          border-radius: 14px;
          box-shadow: 0 10px 30px rgba(15, 35, 52, 0.18);
          padding: 22px 22px 20px;
        }
        h2 {
          margin:0 0 8px 0;
          color:#c62828;
          font-size:22px;
        }
        p {
          margin:6px 0;
          color:#455a64;
          font-size:14px;
        }
        .btn {
          display:inline-block;
          margin-top:14px;
          padding:9px 16px;
          border-radius:999px;
          background:#1565c0;
          color:#fff;
          text-decoration:none;
          font-size:14px;
        }
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="card">
          <h2>${title}</h2>
          <p>${message}</p>
          <a href="${backHref}" class="btn">${backLabel}</a>
        </div>
      </div>
    </body>
    </html>
  `;
}

/* ---------------------------------------------------------
   DATABASE: POSTGRES (NEON)
   DATA HERE IS PERMANENT (not deleted on Render restart)
-----------------------------------------------------------*/
if (!process.env.DATABASE_URL) {
  console.warn("WARNING: DATABASE_URL is not set. Set it on Render.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // required by Neon on most Node clients
  },
});

async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        phone TEXT,
        dob TEXT,
        blood_group TEXT,
        address TEXT
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT,
        description TEXT,
        file_name TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        qr_path TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    console.log("Postgres tables ensured.");
  } finally {
    client.release();
  }
}

initDb().catch((err) => {
  console.error("Error initialising DB:", err);
});

/* ---------------------------------------------------------
   STATIC FILES & MIDDLEWARE
-----------------------------------------------------------*/
app.use(express.static("public"));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/qrs", express.static(path.join(__dirname, "qrs")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());

const UPLOAD_DIR = path.join(__dirname, "uploads");
const QR_DIR = path.join(__dirname, "qrs");

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
if (!fs.existsSync(QR_DIR)) fs.mkdirSync(QR_DIR);

/* ---------------------------------------------------------
   MULTER: PDF-ONLY
-----------------------------------------------------------*/
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (req, file, cb) {
    const safeName =
      Date.now() + "_" + file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, "_");
    cb(null, safeName);
  },
});

const upload = multer({
  storage,
  fileFilter: function (req, file, cb) {
    const isPdfMime = file.mimetype === "application/pdf";
    const isPdfExt = file.originalname.toLowerCase().endsWith(".pdf");
    if (isPdfMime || isPdfExt) {
      cb(null, true);
    } else {
      cb(null, false);
    }
  },
});

/* ---------------------------------------------------------
   FRONTEND ROUTES
-----------------------------------------------------------*/
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});
app.get("/upload", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "uplode.html"));
});

/* ---------------------------------------------------------
   AUTH: REGISTER  (POST /register)
-----------------------------------------------------------*/
app.post("/register", async (req, res) => {
  const { name, email, password, phone, dob, blood_group, address } = req.body;

  if (!name || !email || !password) {
    return res.send(
      renderMessagePage(
        "Registration failed",
        "Name, email and password are required.",
        "/register",
        "Back to registration"
      )
    );
  }

  const hashed = bcrypt.hashSync(password, 10);

  const text = `
    INSERT INTO users (name, email, password, phone, dob, blood_group, address)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    RETURNING id;
  `;
  const values = [
    name,
    email,
    hashed,
    phone || null,
    dob || null,
    blood_group || null,
    address || null,
  ];

  try {
    const result = await pool.query(text, values);
    const userId = result.rows[0].id;

    res.send(`
      <html>
      <head>
        <meta charset="UTF-8" />
        <title>Registration Successful</title>
      </head>
      <body style="font-family:Arial; background:#e8f0fe; margin:0;">
        <div style="max-width:640px;margin:40px auto;background:white;padding:22px 24px;border-radius:14px;box-shadow:0 10px 30px rgba(15,35,52,0.18);">
          <h2 style="color:#1565c0;margin-top:0;">Registration Successful</h2>
          <p>Your patient account has been created.</p>
          <p>Your <b>Patient ID</b> is: <b>${userId}</b></p>
          <p>Please note this ID. It is required when uploading medical PDFs.</p>
          <a href="/login" style="display:inline-block;margin-top:12px;padding:9px 16px;border-radius:999px;background:#1565c0;color:white;text-decoration:none;">Go to Login</a>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error("Register error:", err);
    if (err.code === "23505") {
      // unique_violation on email
      return res.send(
        renderMessagePage(
          "Registration failed",
          "This email is already registered. Try logging in or use another email.",
          "/register",
          "Back to registration"
        )
      );
    }
    return res.send(
      renderMessagePage(
        "Registration failed",
        "Unexpected error while saving your details.",
        "/register",
        "Back to registration"
      )
    );
  }
});

/* ---------------------------------------------------------
   AUTH: LOGIN  (POST /login)
-----------------------------------------------------------*/
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.send(
      renderMessagePage(
        "Login failed",
        "Email and password are required.",
        "/login",
        "Back to login"
      )
    );
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1 LIMIT 1",
      [email]
    );
    const user = result.rows[0];

    if (!user) {
      return res.send(
        renderMessagePage(
          "Login failed",
          "No user found with this email. Please check the email or register as a new patient.",
          "/login",
          "Back to login"
        )
      );
    }

    const ok = bcrypt.compareSync(password, user.password);
    if (!ok) {
      return res.send(
        renderMessagePage(
          "Login failed",
          "The password you entered is incorrect. Please try again.",
          "/login",
          "Back to login"
        )
      );
    }

    res.send(`
      <html>
      <head>
        <meta charset="UTF-8" />
        <title>Patient Dashboard</title>
        <style>
          body { font-family: Arial, sans-serif; background:#e8f1fa; margin:0; }
          .wrap { max-width: 960px; margin:40px auto; padding:20px; }
          .card {
            background:white; padding:24px; border-radius:12px;
            box-shadow:0 4px 12px rgba(0,0,0,0.08);
          }
          h2 { margin-top:0; color:#1565c0; }
          .info { margin-bottom:16px; color:#455a64; }
          .btn-row { margin-top:10px; display:flex; flex-wrap:wrap; gap:10px; }
          .btn {
            background:#1565c0; color:white; padding:10px 18px;
            border-radius:999px; text-decoration:none; font-size:14px;
            display:inline-block;
          }
          .btn.secondary { background:#78909c; }
        </style>
      </head>
      <body>
        <div class="wrap">
          <div class="card">
            <h2>Welcome, ${user.name} 👋</h2>
            <p class="info">
              You are now logged in to the Health Locker hospital document system.<br>
              Your unique Patient ID is <b>${user.id}</b>. Use this ID when uploading reports.
            </p>

            <div class="btn-row">
              <a class="btn" href="/upload?userId=${user.id}">➕ Upload New Medical File</a>
              <a class="btn secondary" href="/documents/${user.id}">📁 View My Documents</a>
              <a class="btn secondary" href="/">🏠 Home</a>
            </div>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error("Login error:", err);
    return res.send(
      renderMessagePage(
        "Login failed",
        "Something went wrong while checking your account. Please try again.",
        "/login",
        "Back to login"
      )
    );
  }
});

/* ---------------------------------------------------------
   UPLOAD PDF & CREATE QR  (POST /upload)
-----------------------------------------------------------*/
app.post("/upload", upload.single("file"), async (req, res) => {
  const { userId, title, description } = req.body;

  if (!userId) {
    return res.send(
      renderMessagePage(
        "Upload failed",
        "Patient User ID is required. Please open the upload page from your dashboard or enter the correct ID.",
        "/upload",
        "Back to upload"
      )
    );
  }

  try {
    const uResult = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [userId]
    );
    const user = uResult.rows[0];
    if (!user) {
      return res.send(
        renderMessagePage(
          "Upload failed",
          "The provided Patient User ID is not valid. Please login again and use the ID shown on your dashboard.",
          "/upload",
          "Back to upload"
        )
      );
    }

    if (!req.file) {
      return res.send(
        renderMessagePage(
          "Upload failed",
          "Only PDF files are allowed. Please select a .pdf report and try again.",
          `/upload?userId=${userId}`,
          "Back to upload"
        )
      );
    }

    const token =
      Date.now().toString(36) + Math.random().toString(36).slice(2);
    const qrFileName = token + "_qr.png";
    const qrOutputPath = path.join(QR_DIR, qrFileName);
    const publicAccessURL = `${req.protocol}://${req.get("host")}/record/${token}`;

    await QRCode.toFile(qrOutputPath, publicAccessURL, {});

    const dResult = await pool.query(
      `
      INSERT INTO documents (user_id, title, description, file_name, token, qr_path)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING id;
    `,
      [
        userId,
        title || null,
        description || null,
        req.file.filename,
        token,
        qrFileName,
      ]
    );

    res.send(`
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Upload Successful</title>
      </head>
      <body style="background:#e8f0fe;font-family:Arial;">
        <div style="max-width:640px;margin:40px auto;padding:22px 24px;background:white;border-radius:14px;box-shadow:0 10px 30px rgba(15,35,52,0.18);">
          <h2 style="color:#1565c0;">Upload Successful</h2>
          <p>Your medical PDF has been uploaded and linked to your patient profile.</p>

          <p><b>Secure Access Link:</b></p>
          <p><a href="/record/${token}" target="_blank">${publicAccessURL}</a></p>

          <p><b>Scan QR Code:</b></p>
          <img src="/qrs/${qrFileName}" width="180" style="border-radius:8px;border:1px solid #e0e0e0;">

          <p style="margin-top:10px;">Share this QR or link with your doctor. They must enter your password to view the report.</p>

          <a href="/documents/${userId}" style="display:inline-block;margin-top:12px;padding:9px 16px;border-radius:999px;background:#1565c0;color:white;text-decoration:none;">Go to My Documents</a>
          <br><br>
          <a href="/" style="font-size:13px;">Back to home</a>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error("Upload error:", err);
    return res.send(
      renderMessagePage(
        "Upload failed",
        "Unexpected error while saving your document.",
        `/upload?userId=${userId || ""}`,
        "Back to upload"
      )
    );
  }
});

/* ---------------------------------------------------------
   MY DOCUMENTS  (GET /documents/:userId)
-----------------------------------------------------------*/
app.get("/documents/:userId", async (req, res) => {
  const userId = req.params.userId;
  try {
    const result = await pool.query(
      `
      SELECT * FROM documents 
      WHERE user_id = $1
      ORDER BY created_at DESC
    `,
      [userId]
    );
    const docs = result.rows;

    const listHtml =
      docs.length === 0
        ? "<p>No documents uploaded yet.</p>"
        : docs
            .map(
              (d) => `
          <div class="doc-card">
            <div class="doc-main">
              <div>
                <div class="doc-title">${d.title || "Medical Document"}</div>
                <div class="doc-meta">
                  Uploaded on ${d.created_at || "-"}<br>
                  ${d.description ? d.description : ""}
                </div>
              </div>
              <div class="doc-actions">
                <a class="btn" href="/files/${d.token}" target="_blank">View PDF</a>
                <a class="btn outline" href="/record/${d.token}" target="_blank">Open Protected Link</a>
              </div>
            </div>
            <div class="doc-qr">
              <div class="doc-qr-label">QR for this document</div>
              <img src="/qrs/${d.qr_path}" alt="QR" class="qr-img">
            </div>
          </div>
        `
            )
            .join("");

    res.send(`
      <html>
      <head>
        <title>My Documents</title>
        <style>
          body { font-family: Arial, sans-serif; background:#f1f6fb; margin:0; }
          .wrap { max-width: 1100px; margin:30px auto; padding:0 16px 30px; }
          h2 { color:#1565c0; margin-bottom:4px; }
          .subtitle { color:#607d8b; margin-bottom:20px; }
          .doc-card {
            background:white; padding:16px 18px; margin:12px 0;
            border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,0.06);
          }
          .doc-main {
            display:flex; align-items:flex-start; justify-content:space-between; gap:16px;
          }
          .doc-title { font-weight:bold; color:#0d47a1; margin-bottom:4px; }
          .doc-meta { font-size:13px; color:#546e7a; }
          .doc-actions { display:flex; flex-wrap:wrap; gap:8px; }
          .btn {
            background:#1565c0; color:#fff; padding:8px 14px;
            border-radius:999px; text-decoration:none; font-size:13px;
          }
          .btn.outline {
            background:white; color:#1565c0; border:1px solid #1565c0;
          }
          .doc-qr { margin-top:10px; display:flex; align-items:center; gap:10px; }
          .doc-qr-label { font-size:13px; color:#455a64; }
          .qr-img { height:80px; border-radius:6px; border:1px solid #e0e0e0; background:white; }
          .top-bar { display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; }
          .chip { font-size:12px; background:#e3f2fd; padding:4px 10px; border-radius:999px; color:#1565c0; }
          .nav-links a { font-size:13px; color:#1565c0; text-decoration:none; margin-left:12px; }
          .nav-links a:hover { text-decoration:underline; }
          @media (max-width:700px) {
            .doc-main { flex-direction:column; }
          }
        </style>
      </head>
      <body>
        <div class="wrap">
          <div class="top-bar">
            <div>
              <h2>My Medical Documents</h2>
              <div class="subtitle">Patient ID: <b>${userId}</b></div>
            </div>
            <div class="nav-links">
              <span class="chip">Health Locker</span>
              <a href="/upload?userId=${userId}">Upload New</a>
              <a href="/">Home</a>
            </div>
          </div>
          ${listHtml}
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error("Documents error:", err);
    return res.send(
      renderMessagePage(
        "Error",
        "Could not load documents.",
        "/",
        "Go to home"
      )
    );
  }
});

/* ---------------------------------------------------------
   ACCESS VIA QR: SHOW PASSWORD FORM
-----------------------------------------------------------*/
app.get("/record/:token", async (req, res) => {
  const token = req.params.token;

  try {
    const result = await pool.query(
      `
      SELECT d.*, u.name AS user_name, u.email AS user_email
      FROM documents d
      JOIN users u ON d.user_id = u.id
      WHERE d.token = $1
    `,
      [token]
    );
    const doc = result.rows[0];

    if (!doc) {
      return res.status(404).send(
        renderMessagePage(
          "Record not found",
          "This QR code does not match any stored medical document. It might be old or deleted.",
          "/",
          "Go to home"
        )
      );
    }

    res.send(`
      <html>
      <head>
        <title>Access Patient Record</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
          body {
            margin:0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            background:#e8f0fe;
          }
          .wrap {
            max-width: 520px;
            margin:40px auto;
            padding:0 16px;
          }
          .card {
            background:#ffffff;
            border-radius:14px;
            box-shadow:0 10px 30px rgba(15,35,52,0.18);
            padding:22px 20px 20px;
          }
          h2 {
            margin:0 0 8px 0;
            color:#0d47a1;
            font-size:20px;
          }
          p {
            margin:6px 0;
            color:#455a64;
            font-size:14px;
          }
          label {
            font-size:13px;
            color:#455a64;
          }
          input {
            width:100%;
            padding:7px 9px;
            margin-top:4px;
            border-radius:8px;
            border:1px solid #cfd8dc;
            font-size:14px;
            box-sizing:border-box;
          }
          .field { margin:10px 0; }
          button {
            margin-top:14px;
            padding:9px 18px;
            border-radius:999px;
            border:none;
            background:linear-gradient(135deg,#1565c0,#1e88e5);
            color:#fff;
            font-size:14px;
            cursor:pointer;
          }
          .hint { font-size:11px; color:#78909c; margin-top:8px; }
        </style>
      </head>
      <body>
        <div class="wrap">
          <div class="card">
            <h2>Access Patient Record</h2>
            <p>Patient: <b>${doc.user_name}</b></p>
            <p>Enter the patient's registered email and password to open this report.</p>

            <form method="POST" action="/record/${token}">
              <div class="field">
                <label>Email (registered with Health Locker)</label>
                <input type="email" name="email" required>
              </div>

              <div class="field">
                <label>Password</label>
                <input type="password" name="password" required>
              </div>

              <button type="submit">Unlock Record</button>
              <p class="hint">
                This screen is optimised for mobiles. Only authorised persons who know the patient's password
                should unlock the report.
              </p>
            </form>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error("GET /record error:", err);
    return res.send(
      renderMessagePage(
        "Error",
        "Could not load this record.",
        "/",
        "Go to home"
      )
    );
  }
});

/* ---------------------------------------------------------
   ACCESS VIA QR: VERIFY PASSWORD & SHOW RECORD
-----------------------------------------------------------*/
app.post("/record/:token", async (req, res) => {
  const token = req.params.token;
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      `
      SELECT d.*, u.name AS user_name, u.email AS user_email, u.password AS user_password,
             u.phone, u.dob, u.blood_group, u.address
      FROM documents d
      JOIN users u ON d.user_id = u.id
      WHERE d.token = $1
    `,
      [token]
    );
    const doc = result.rows[0];

    if (!doc) {
      return res.status(404).send(
        renderMessagePage(
          "Record not found",
          "This QR code does not match any stored medical document. It might be old or deleted.",
          "/",
          "Go to home"
        )
      );
    }

    if (email !== doc.user_email) {
      return res.send(
        renderMessagePage(
          "Access denied",
          "The email you entered does not match the email registered for this patient.",
          "/record/" + token,
          "Try again"
        )
      );
    }

    const ok = bcrypt.compareSync(password, doc.user_password);
    if (!ok) {
      return res.send(
        renderMessagePage(
          "Access denied",
          "The password you entered is incorrect. Please try again.",
          "/record/" + token,
          "Try again"
        )
      );
    }

    const fileUrl = `/files/${token}`;

    res.send(`
      <html>
      <head>
        <title>Patient Record</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
          body {
            margin:0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            background:#e8f0fe;
          }
          .wrap {
            max-width: 960px;
            margin:20px auto 30px;
            padding:0 16px;
          }
          .grid {
            display:grid;
            grid-template-columns: minmax(0, 1.4fr) minmax(0, 2fr);
            gap:16px;
          }
          .card {
            background:#ffffff;
            border-radius:14px;
            box-shadow:0 10px 30px rgba(15,35,52,0.18);
            padding:18px 18px 16px;
          }
          h2 {
            margin:0 0 8px 0;
            color:#0d47a1;
            font-size:20px;
          }
          h3 {
            margin:0 0 8px 0;
            color:#1565c0;
            font-size:16px;
          }
          p, li {
            margin:4px 0;
            color:#455a64;
            font-size:13px;
          }
          .label { font-weight:600; }
          .btn-link {
            display:inline-block;
            margin:6px 0;
            padding:7px 14px;
            border-radius:999px;
            background:#1565c0;
            color:#fff;
            text-decoration:none;
            font-size:13px;
          }
          iframe {
            width:100%;
            height:480px;
            border:1px solid #cfd8dc;
            border-radius:10px;
            background:white;
          }
          @media (max-width:800px) {
            .grid { grid-template-columns:minmax(0,1fr); }
            iframe { height:420px; }
          }
        </style>
      </head>
      <body>
        <div class="wrap">
          <div class="grid">
            <section class="card">
              <h2>Patient Details</h2>
              <p><span class="label">Name:</span> ${doc.user_name}</p>
              <p><span class="label">Email:</span> ${doc.user_email}</p>
              <p><span class="label">Phone:</span> ${doc.phone || "-"}</p>
              <p><span class="label">Date of Birth:</span> ${doc.dob || "-"}</p>
              <p><span class="label">Blood Group:</span> ${doc.blood_group || "-"}</p>
              <p><span class="label">Address:</span> ${doc.address || "-"}</p>

              <h3 style="margin-top:14px;">Document Info</h3>
              <p><span class="label">Title:</span> ${doc.title || "Medical Document"}</p>
              <p><span class="label">Description:</span> ${doc.description || "-"}</p>
              <p><span class="label">File name:</span> ${doc.file_name}</p>
              <p><span class="label">Uploaded:</span> ${doc.created_at}</p>

              <a class="btn-link" href="${fileUrl}" target="_blank">⬇ Download PDF</a>
            </section>

            <section class="card">
              <h3>Report Preview (PDF)</h3>
              <iframe src="${fileUrl}" title="Medical report PDF"></iframe>
            </section>
          </div>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error("POST /record error:", err);
    return res.send(
      renderMessagePage(
        "Error",
        "Could not verify or show this record.",
        "/",
        "Go to home"
      )
    );
  }
});

/* ---------------------------------------------------------
   FILE SERVE: /files/:token  (uses token, not filename)
-----------------------------------------------------------*/
app.get("/files/:token", async (req, res) => {
  const token = req.params.token;

  try {
    const result = await pool.query(
      "SELECT file_name FROM documents WHERE token = $1",
      [token]
    );
    const row = result.rows[0];
    if (!row) {
      return res.status(404).send(
        renderMessagePage(
          "File not found",
          "We could not locate this file on the server. It may have been removed.",
          "/",
          "Go to home"
        )
      );
    }

    const filePath = path.join(UPLOAD_DIR, row.file_name);
    if (!fs.existsSync(filePath)) {
      return res.status(404).send(
        renderMessagePage(
          "File not found",
          "The database record exists but the physical file is missing on the server.",
          "/",
          "Go to home"
        )
      );
    }

    res.sendFile(filePath);
  } catch (err) {
    console.error("GET /files error:", err);
    return res.status(500).send(
      renderMessagePage(
        "Error",
        "Unexpected error while serving this file.",
        "/",
        "Go to home"
      )
    );
  }
});

/* ---------------------------------------------------------
   START SERVER
-----------------------------------------------------------*/
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("=====================================");
  console.log(`SERVER RUNNING on port ${PORT}`);
  console.log("=====================================");
});
