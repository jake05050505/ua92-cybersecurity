// #region configs
// set environment type (test/prod)
DEV_MODE = process.env.NODE_ENV !== "production"; // This should use NODE_ENV - fixed in commit a87dadb

const express   = require("express");
const path      = require("path");
const session   = require("express-session");
const rateLimit = require("express-rate-limit");
const bcrypt    = require("bcrypt");
const mysql     = require("mysql2");

const app = express();
const PORT = 3000;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const signup_limiter = rateLimit({
    windowMs: 15 * 1000 * 60, // 15 mins
    limit: 10, // 10 signup attempts

    standardHeaders: true,
    legacyHeaders: false,

    handler: (req, res) => {
        const rateLimitTime = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000 / 60);
        res.status(429).send(`Too many signup attempts. Try again in ${rateLimitTime} minutes.`);
    }
});

const login_limiter = rateLimit({
    windowMs: 15 * 1000 * 60, // 15 mins
    limit: 10, // 10 login attempts

    standardHeaders: true,
    legacyHeaders: false,

    handler: (req, res) => {
        const rateLimitTime = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000);
        res.status(429).send(`Too many login attempts. Try again in ${rateLimitTime} seconds.`);
    }
});

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "password", // in a production environment (not localhost) this should be a strong password to prevent brute force attacks. This will remain unsafe, including in the secure branch (should be origin/master).
    database: "secure"
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "static")));
app.use(session({
    secret: "secret password", // Not safe - easily guessable, users can forge cookies and sessions if they know this, such as by setting req.session.username = "admin"
    saveUninitialized: true,
    resave: false,
    cookie: {
        maxAge: 1000 * 60 * 30, // 1 hour
        secure: false
    }
}));
// #endregion

// #region GET Routes
app.get("/index", (req, res) => {
    req.session.username = (req.session.username || 0);
    if (devMode == true) { return res.render("index", { devMode, viewcount: req.session.viewcount }); }
    else { return res.redirect("/"); }
});

app.get("/signup", (req, res) => {
    req.session.viewcount = (req.session.viewcount || 0) + 1;
    return res.render("signup", { devMode, viewcount: req.session.viewcount });
});

function render_login(req, res) {
    req.session.viewcount = (req.session.viewcount || 0) + 1;
    return res.render("login", { devMode, viewcount: req.session.viewcount });
}

app.get('/', render_login);
app.get("/login", render_login);

app.get("/dashboard", (req, res) => {
    req.session.viewcount = (req.session.viewcount || 0) + 1;
    const username = req.session.username || undefined; // if req.session.username is undefined, user should be redirected to login page
    if (typeof username === "undefined") {
        return res.redirect("/login");
    }
    return res.render("dashboard", { username, devMode, viewcount: req.session.viewcount });
});

app.get("/logout", (req, res) => {
    delete req.session.username; // potentially unsafe - only deletes username and not password
    res.redirect("/login");
});
// #endregion

// #region POST Routes
app.post("/signup", signup_limiter, (req, res) => {
    const { email, username, password } = req.body;

    // Backend validation
    if (!email || !username || !password) {
        return res.status(400).render("signup", { error: "Please fill all fields", devMode, viewcount: req.session.viewcount });
    }
    if (email.length > 64 || username.length > 32 || password.length > 32) {
        return res.status(400).render("signup", { error: "Email/Username/Password too long, please try again", devMode, viewcount: req.session.viewcount }); // Should only be possible if the user edits the html to remove the maxlength attribute
    }
    if (!email.includes('@') || !email.includes('.')) {
        return res.status(400).render("signup", { error: "Email is not a valid format (user@example.com)", devMode, viewcount: req.session.viewcount });
    }

    bcrypt.hash(password, 10, (err, hashed_password) => {
        if (err) { throw err; }

        const insertUserQuery = "INSERT INTO `users` (`email`, `username`, `password`) VALUES (?,?,?)";

        db.query(insertUserQuery, [email, username, hashed_password], (err) => {
            // tried to insert username/email which already exists
            if (err && err.code === "ER_DUP_ENTRY") {
                return res.status(400).render("signup", { error: "A user with this username/email already exists", devMode, viewcount: req.session.viewcount });
            } else if (err) { throw err; }

            req.session.username = username;
            return res.status(200).redirect(`/dashboard`);
        });
    });

});

app.post("/login", login_limiter, (req, res) => {
    let username = req.body.username;
    const password = req.body.password;

    if (!username || !password) {
        return res.status(400).render("login", { error: "Please fill all fields", devMode, viewcount: req.session.viewcount });
    }

    const checkUserQuery = "select username, password from users where username = ?;";

    db.query(checkUserQuery, username, (err, result) => {
        if (err && err.code == "ER_PARSE_ERROR") {
            return res.status(500).render("login", { error: "Internal Server Error", devMode, viewcount: req.session.viewcount });
        } else if (err) { throw err; }

        if (result.length == 0) {
            return res.status(401).render("login", { error: "Invalid username or password", devMode, viewcount: req.session.viewcount });
        }

        username = result[0].username;
        hashed_password = result[0].password;

        bcrypt.compare(password, hashed_password, (err, result) => {
            if (err) { throw err; }

            if (result) {
                req.session.username = username;
                return res.redirect("/dashboard");
            }
            else {
                return res.status(401).render("login", { error: "Invalid username or password", devMode, viewcount: req.session.viewcount });
            }
        });
    });

});
// #endregion

// #region Connections
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Running in ${"Production" ? !DEV_MODE : "Development" } mode`);
    if (devMode == true) console.log("Debugging enabled");
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed: " + err.stack);
        return;
    }
    console.log("Connected to the MySQL database.");
});
// #endregion
