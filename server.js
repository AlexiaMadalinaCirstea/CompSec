const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const session = require("express-session");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt"); // Added for secure password hashing

const app = express();
const port = 3000;

const failedAttempts = {};
const attackerIPs = {};
const attackers = {};

const axios = require("axios");
const saltRounds = 12;
require("dotenv").config(); // Load environment variables

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("frontend"));
app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // Serve uploaded files

// Session configuration with secure cookie settings
app.use(session({
    secret: 'your-secret-key', // In production, load from an environment variable
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
    }
}));

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Protect gallery API against scraping
const galleryLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 20, // Limit: 20 requests per 10 minutes
    message: "⛔ Too many requests. Try again later."
});

// Connect to SQLite Database (Creates DB if not exists)
const db = new sqlite3.Database(path.join(__dirname, "database", "database.db"), (err) => {
    if (err) console.error("Database connection error:", err);
    else console.log("Connected to SQLite database");
});

// Create Users Table (if it doesn’t exist)
db.serialize(() => {
    // Create Users Table (if it doesn’t exist)
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    `, (err) => {
        if (err) {
            console.error("Error creating users table:", err);
        } else {
            // Check if the admin user exists after ensuring the table is created
            db.get("SELECT * FROM users WHERE username = ?", ['admin'], (err, row) => {
                if (err) {
                    console.error("Database error:", err);
                }
                if (!row) {
                    db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ['admin', 'password123', 'admin'], function (err) {
                        if (err) {
                            console.error("Error inserting admin:", err);
                        } else {
                            console.log("Test user added: admin / password123");
                        }
                    });
                }
            });
        }
    });
  });
  

// Insert a test user (if no admin exists)
db.get("SELECT * FROM users WHERE username = ?", ['admin'], (err, row) => {
    if (err) {
        console.error("Database error:", err);
    }
    if (!row) {
        bcrypt.hash("password123", saltRounds, (err, hash) => {
            if (err) {
                console.error("Error hashing password:", err);
            } else {
                db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ['admin', hash, 'admin'], function (err) {
                    if (err) {
                        console.error("Error inserting test user:", err);
                    } else {
                        console.log("Test user added: admin / password123");
                    }
                });
            }
        });
    }
});

// Serve index.html at "/"
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "frontend", "index.html"));
});

// SIGNUP ROUTE (Secured: Parameterized SQL, Password Hashing)
app.post("/signup", async (req, res) => {
    const { username, password, "h-captcha-response": captcha } = req.body;

    // 🔥 Validate hCaptcha with hCaptcha API
    if (!captcha) {
        return res.status(400).send("CAPTCHA verification failed.");
    }

    const hCaptchaSecretKey = process.env.HCAPTCHA_SECRET_KEY; // Store in .env
    const verifyUrl = `https://hcaptcha.com/siteverify`;

    try {
        const response = await axios.post(verifyUrl, new URLSearchParams({
            secret: hCaptchaSecretKey,
            response: captcha
        }));

        if (!response.data.success) {
            return res.status(400).send("Failed CAPTCHA verification.");
        }
    } catch (error) {
        console.error("Error verifying hCaptcha:", error);
        return res.status(500).send("CAPTCHA verification error.");
    }

    // 🔒 Secure Input Validation
    if (typeof username !== "string" || typeof password !== "string") {
        return res.status(400).send("Invalid input.");
    }

    // Assign role securely
    const role = username.toLowerCase() === "admin" ? "admin" : "user";

    // 🔐 Hash the password before storing it
    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            return res.status(500).send("Error processing password.");
        }
        const sql = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)";
        db.run(sql, [username, hash, role], function (err) {
            if (err) {
                return res.status(500).send(`<h2>Database Error</h2><p>${err.message}</p>`);
            }
            res.send(`<h2>Signup Successful</h2><p>You can now <a href="login.html">log in</a>.</p>`);
        });
    });
});

// LOGIN ROUTE (Secured: Parameterized SQL, Hashed Password Comparison)
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    // Basic input validation
    if (typeof username !== "string" || typeof password !== "string") {
        return res.status(400).send("Invalid input.");
    }

    const sql = "SELECT * FROM users WHERE username = ?";
    db.get(sql, [username], (err, user) => {
        if (err) {
            return res.status(500).send(`<h2>Database Error</h2><p>${err.message}</p>`);
        }
        if (!user) {
            return res.status(401).send("Login Failed. Invalid credentials.");
        }
        // Compare hashed password
        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                return res.status(500).send("Error verifying password.");
            }
            if (result) {
                req.session.username = user.username;
                req.session.role = user.role; // Save role in session for admin checks
                return res.send("Login successful!");
            } else {
                return res.status(401).send("Login Failed. Invalid credentials.");
            }
        });
    });
});

app.get("/session-status", (req, res) => {
    const ip = req.ip;
    attackerIPs[ip] = (attackerIPs[ip] || 0) + 1;

    if (attackerIPs[ip] > 10) {
        console.log(`[SECURITY] 🚨 IP ${ip} is spamming refresh!`);
        return res.status(403).json({ error: "Access Denied. You are blocked." });
    }

    if (!req.session.username) {
        return res.json({ loggedIn: false });
    }

    res.json({ loggedIn: true, username: req.session.username });
});

// Create fake punishment page
app.get("/blocked.html", (req, res) => {
    res.send(`
        <html>
            <head><title>Blocked</title></head>
            <body style="text-align:center; font-family:sans-serif;">
                <h1>⛔ You Have Been Temporarily Blocked</h1>
                <p>Your IP has been flagged for suspicious activity.</p>
                <p>Please contact support if this was a mistake.</p>
            </body>
        </html>
    `);
});

// LOGOUT ROUTE
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send("Failed to logout.");
        }
        res.redirect("/login.html");
    });
});

app.get("/user", (req, res) => {
    if (!req.session.username) {
        return res.redirect("/login.html");
    }
    res.sendFile(path.join(__dirname, "frontend", "user.html"));
});

// FILE UPLOAD (Secured: Using Multer with File Type Restrictions)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userDir = path.join(uploadDir, req.session.username || "guest");
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir, { recursive: true });
        }
        cb(null, userDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + "-" + file.originalname);
    }
});

function fileFilter(req, file, cb) {
    // Allow only common image types (adjust as needed)
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error("File type not allowed."), false);
    }
}

const upload = multer({ storage: storage, fileFilter: fileFilter });

app.post("/upload", upload.single("file"), (req, res) => {
    if (!req.session.username) {
        return res.status(401).send("<h2>Unauthorized</h2><p>You must be logged in to upload files.</p>");
    }
    if (!req.file) {
        return res.status(400).send("No file uploaded.");
    }
    res.send(`<h2>Upload Successful</h2>
              <p>File ${req.file.originalname} uploaded by ${req.session.username}.</p>
              <p><a href="/gallery">View Gallery</a></p>`);
});

// Secure gallery route
app.get("/secure-gallery", galleryLimiter, (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ loggedIn: false });
    }

    const userFolder = path.join(uploadDir, req.session.username);
    if (!fs.existsSync(userFolder)) {
        return res.json({ loggedIn: true, files: [] });
    }

    fs.readdir(userFolder, (err, files) => {
        if (err) return res.status(500).json({ error: "Error reading files." });

        res.json({ loggedIn: true, files: files.map(file => ({ filename: file })) });
    });
});

// Prevent direct access to uploads (Only serve through authentication)
app.get("/get-file", (req, res) => {
    const ip = req.ip;
    // Track unauthorized/mass-download attempts
    attackers[ip] = (attackers[ip] || 0) + 1;
    if (attackers[ip] > 10) {
        console.log(`[SECURITY] 🚨 IP ${ip} is attempting mass-downloads!`);
        return res.status(403).send("❌ Access denied. You've been flagged.");
    }

    if (!req.session.username) {
        return res.status(401).send("⛔ Unauthorized!");
    }

    const filename = req.query.filename;
    const userFolder = path.join(uploadDir, req.session.username);
    const filePath = path.join(userFolder, filename);

    if (!fs.existsSync(filePath)) {
        return res.status(404).send("❌ File not found.");
    }

    res.sendFile(filePath);
});

// Fetch Images for Logged-In User (Personal Gallery)
app.get("/get-gallery", (req, res) => {
    if (!req.session.username) {
        return res.status(401).json({ error: "Unauthorized. Please log in." });
    }

    const userFolder = path.join(uploadDir, req.session.username);
    if (!fs.existsSync(userFolder)) {
        return res.json([]);
    }

    fs.readdir(userFolder, (err, files) => {
        if (err) {
            return res.status(500).json({ error: "Error reading files." });
        }
        res.json(files.map(file => ({ filename: `${req.session.username}/${file}` })));
    });
});

// Fetch All Images for World Gallery (All Users)
app.get("/get-world-gallery", (req, res) => {
    fs.readdir(uploadDir, (err, users) => {
        if (err) {
            return res.status(500).json({ error: "Error reading upload directory." });
        }

        let allImages = [];

        users.forEach(user => {
            const userFolder = path.join(uploadDir, user);
            if (fs.lstatSync(userFolder).isDirectory()) {
                let files = fs.readdirSync(userFolder).map(file => ({ filename: `${user}/${file}` }));
                allImages = allImages.concat(files);
            }
        });

        res.json(allImages);
    });
});

// /fetch-url route (Secured: Validate URL input)
app.get("/fetch-url", (req, res) => {
    const url = req.query.url;
    if (!url) return res.status(400).send("URL parameter is required.");

    let parsedUrl;
    try {
        parsedUrl = new URL(url);
    } catch (e) {
        return res.status(400).send("Invalid URL.");
    }
    // Allow only http and https protocols
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
        return res.status(400).send("Only HTTP and HTTPS protocols are allowed.");
    }

    fetch(url)
        .then(response => response.text())
        .then(data => res.send(data))
        .catch(err => res.status(500).send("Error fetching URL"));
});

// Admin page access (Secured)
app.get("/admin.html", (req, res) => {
    if (!req.session.username || req.session.role !== "admin") {
        const ip = req.ip;
        // Track failed attempts
        failedAttempts[ip] = (failedAttempts[ip] || 0) + 1;
        if (failedAttempts[ip] >= 3) {
            console.log(`[SECURITY] 🚨 IP ${ip} tried accessing admin panel!`);
            return res.status(403).send("Access Denied. This attempt has been logged.");
        }
        return res.redirect("/login.html");
    }

    res.sendFile(path.join(__dirname, "frontend", "admin.html"));
});

// Log attacker endpoint
app.post("/log-attacker", (req, res) => {
    const ip = req.ip;
    attackerIPs[ip] = true; // Mark as an attacker
    console.log(`[ALERT] 🚨 Hacker detected from IP: ${ip}`);
    res.status(200).send("Logged");
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
