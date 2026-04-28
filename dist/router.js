import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import bcrypt from "bcrypt";
import { users } from "./db.js";
import "dotenv";
const authRateLimit = rateLimit({
    windowMs: 10 * 1000 * 60,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        const rateLimitTimer = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000);
        res.send(`Too many login attempts. Try again in ${rateLimitTimer} seconds.`);
    }
});
const { NODE_ENV } = process.env;
if (!NODE_ENV)
    throw new Error("NODE_ENV is missing!\nCheck your package.json scripts and make sure that `cross-env NODE_ENV={value}` is set. (NODE_ENV=\"production\" for production environments)");
const DEV_MODE = process.env.NODE_ENV !== "production";
export const router = Router();
function meta(req) {
    if (!req.session.viewCount)
        req.session.viewCount = 0;
    ++req.session.viewCount;
    return { DEV_MODE, viewCount: req.session.viewCount };
}
function isUserAuthenticated(req) {
    return typeof req.session.username !== "undefined";
}
// login/dashboard route
router.route("/")
    .get((req, res) => {
    if (isUserAuthenticated(req)) {
        const { username, role } = req.session;
        return res.render("dashboard", { username, role, ...meta(req) });
    }
    else
        return res.render("login", meta(req));
})
    .post(authRateLimit, async (req, res) => {
    const { username, password } = req.body;
    const storedUser = await users.findOne({ username: username });
    if (storedUser === null)
        return res.render("login", { err: "Invalid Username or Password.", ...meta(req) });
    const storedHash = storedUser.password;
    bcrypt.compare(password, storedHash, (err, result) => {
        if (err)
            throw err;
        if (!result)
            return res.render("login", { err: "Invalid Username or Password.", ...meta(req) });
        else {
            req.session.username = storedUser.username;
            req.session.role = storedUser.role;
            meta(req);
            return res.redirect("/");
        }
    });
});
router.route("/signup")
    .get((req, res) => {
    if (isUserAuthenticated(req))
        return res.redirect("/");
    return res.render("signup", meta(req));
})
    .post(authRateLimit, async (req, res) => {
    const { email, username, password } = req.body;
    const userExists = await users.countDocuments({
        $or: [{ username: username }, { email: email }]
    }) !== 0;
    if (userExists)
        return res.render("signup", { err: "A user already exists with this email or username.", ...meta(req) });
    await users.insertOne({
        email: email,
        username: username,
        password: await bcrypt.hash(password, 10),
        role: "user"
    }).then(() => {
        req.session.username = username;
        req.session.role = "user";
        meta(req);
        return res.redirect("/");
    });
});
router.route("/logout")
    .get((req, res) => {
    req.session.destroy(err => {
        if (err)
            throw err;
        return res.redirect("/");
    });
});
