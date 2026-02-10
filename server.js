const rateLimit = require("express-rate-limit");
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


const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));


// Database connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Govardhan@2009",
    database: "secure_app"
});

db.connect(err => {
    if (err) throw err;
    console.log("MySQL Connected");
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: "secureSecretKey",
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
app.use(helmet());

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
        return res.send("Username must be 3–30 characters.");
    }

    if (!isValidEmail(email)) {
        return res.send("Invalid email format.");
    }

    if (!isValidPassword(password)) {
        return res.send("Password must be 8–50 characters.");
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

        if (match) {
            req.session.user = user.id;
            res.redirect("/dashboard");
        } else {
            res.send("Invalid login.");
        }
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

