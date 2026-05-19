const rateLimit = require("express-rate-limit");
require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");
const bodyParser = require("body-parser");
const path = require("path");
const helmet = require("helmet");
const csrf = require("csurf");
const https = require("https");
const fs = require("fs");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");


const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));


// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "secure_app"
});

db.connect(err => {
    if (err) throw err;
    console.log("MySQL Connected");
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SESSION_SECRET || "change-this-development-secret",
    resave: false,
    saveUninitialized: false,
   cookie: {
         httpOnly: true,
         secure: true,
        sameSite: "strict",
        maxAge: 15 * 60 * 1000 // 15 minutes
    }
}));

// Login rate limiter
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login attempts
    message: "Too many login attempts. Try again later."
});

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            imgSrc: ["'self'", "data:"]
        }
    }
}));

// CSRF protection
const csrfProtection = csrf();
app.use(csrfProtection);


// Routes
app.get("/", (req, res) => {
    res.render("login", { csrfToken: req.csrfToken() });
});



app.get("/signup", (req, res) => {
    res.render("signup", { csrfToken: req.csrfToken() });
});



// Validation functions
function isValidEmail(email) {
    const emailPattern = /^[^ ]+@[^ ]+\.[a-z]{2,3}$/;
    return emailPattern.test(email);
}

function isValidPassword(password) {
    return password.length >= 8 && password.length <= 50;
}

function isValidUsername(username) {
    return username.length >= 3 && username.length <= 30;
}

function completeLogin(req, res, userId) {
    req.session.regenerate((err) => {
        if (err) {
            return res.send("Session error.");
        }

        req.session.user = userId;
        res.redirect("/dashboard");
    });
}


// Signup
app.post("/signup", async (req, res) => {
    let { username, email, password } = req.body;

    // Trim spaces
    username = username.trim();
    email = email.trim();

    // Basic checks
    if (!username || !email || !password) {
        return res.send("All fields are required.");
    }

    // Server-side validation
    if (!isValidUsername(username)) {
        return res.send("Username must be 3-30 characters.");
    }

    if (!isValidEmail(email)) {
        return res.send("Invalid email format.");
    }

    if (!isValidPassword(password)) {
        return res.send("Password must be 8-50 characters.");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
        db.query(sql, [username, email, hashedPassword], (err) => {
            if (err) {
                return res.send("User already exists or invalid data.");
            }
            res.redirect("/");
        });
    } catch (error) {
        res.send("Server error.");
    }
});


// Login
app.post("/login", loginLimiter, (req, res) => {
    let { email, password } = req.body;

    email = email.trim();

    if (!email || !password) {
        return res.send("All fields are required.");
    }

    if (!isValidEmail(email)) {
        return res.send("Invalid email format.");
    }

    const sql = "SELECT * FROM users WHERE email = ?";
    db.query(sql, [email], async (err, results) => {
        if (err || results.length === 0) {
            return res.send("Invalid login.");
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.send("Invalid login.");
        }

        if (!user.two_factor_enabled) {
            req.session.pending2FASetupUser = user.id;
            return res.redirect("/setup-2fa");
        }

        req.session.pending2FAUser = user.id;
        res.redirect("/verify-2fa");
    });
});

// Set up authenticator app 2FA
app.get("/setup-2fa", (req, res) => {
    const userId = req.session.pending2FASetupUser || req.session.user;

    if (!userId) {
        return res.redirect("/");
    }

    const sql = "SELECT id, email, two_factor_enabled FROM users WHERE id = ?";
    db.query(sql, [userId], async (err, results) => {
        if (err) {
            console.error("2FA setup database error:", err);
            return res.send("Database error while setting up 2FA. Make sure the two_factor_secret and two_factor_enabled columns exist.");
        }

        if (results.length === 0) {
            return res.send("User not found.");
        }

        const user = results[0];

        if (user.two_factor_enabled) {
            return res.redirect("/dashboard");
        }

        const secret = speakeasy.generateSecret({
            name: `Secure Login System (${user.email})`
        });

        req.session.pending2FASecret = secret.base32;

        try {
            const qrCode = await QRCode.toDataURL(secret.otpauth_url);
            res.render("setup-2fa", {
                qrCode,
                manualKey: secret.base32,
                csrfToken: req.csrfToken()
            });
        } catch (error) {
            res.send("Could not generate 2FA QR code.");
        }
    });
});

app.post("/setup-2fa", (req, res) => {
    const userId = req.session.pending2FASetupUser || req.session.user;
    const secret = req.session.pending2FASecret;
    const token = req.body.token;

    if (!userId || !secret) {
        return res.redirect("/");
    }

    const verified = speakeasy.totp.verify({
        secret,
        encoding: "base32",
        token,
        window: 1
    });

    if (!verified) {
        return res.send("Invalid 2FA code. Go back and try again.");
    }

    const sql = "UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE id = ?";
    db.query(sql, [secret, userId], (err) => {
        if (err) {
            console.error("2FA enable database error:", err);
            return res.send("Could not enable 2FA.");
        }

        delete req.session.pending2FASetupUser;
        delete req.session.pending2FASecret;
        completeLogin(req, res, userId);
    });
});

// Verify authenticator app 2FA during login
app.get("/verify-2fa", (req, res) => {
    if (!req.session.pending2FAUser) {
        return res.redirect("/");
    }

    res.render("verify-2fa", { csrfToken: req.csrfToken() });
});

app.post("/verify-2fa", (req, res) => {
    const userId = req.session.pending2FAUser;
    const token = req.body.token;

    if (!userId) {
        return res.redirect("/");
    }

    const sql = "SELECT two_factor_secret FROM users WHERE id = ?";
    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error("2FA verification database error:", err);
            return res.send("Database error while verifying 2FA.");
        }

        if (results.length === 0) {
            return res.send("User not found.");
        }

        const verified = speakeasy.totp.verify({
            secret: results[0].two_factor_secret,
            encoding: "base32",
            token,
            window: 1
        });

        if (!verified) {
            return res.send("Invalid 2FA code.");
        }

        delete req.session.pending2FAUser;
        completeLogin(req, res, userId);
    });
});


// Dashboard
app.get("/dashboard", (req, res) => {
    if (!req.session.user) {
        return res.redirect("/");
    }
    res.render("dashboard");

});

// Logout
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

const sslOptions = {
    key: fs.readFileSync("./ssl/server.key"),
    cert: fs.readFileSync("./ssl/server.cert")
};

https.createServer(sslOptions, app).listen(3000, () => {
    console.log("Server running on https://localhost:3000");
});

