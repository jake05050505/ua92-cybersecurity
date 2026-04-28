import { Router } from "express";
import "dotenv";
import bcrypt from "bcrypt";
import "express-session";
import { users } from "./db.js";
const { NODE_ENV } = process.env;
if (!NODE_ENV)
    throw new Error("NODE_ENV is missing!\nCheck your package.json scripts and make sure that `cross-env NODE_ENV={value}` is set. (NODE_ENV=\"production\" for production environments)");
const DEV_MODE = process.env.NODE_ENV !== 'production';
export const router = Router();
function meta(req) {
    function incrementViewCount() {
        if (!req.session.viewCount)
            req.session.viewCount = 0;
        return ++req.session.viewCount;
    }
    return { DEV_MODE, viewCount: incrementViewCount() };
}
function IsUserAuthenticated(req) {
    return typeof req.session.username !== "undefined";
}
;
router.route("/")
    .get((req, res) => {
    if (IsUserAuthenticated(req))
        return res.render("dashboard", { username: req.session.username, ...meta(req) });
    else
        return res.render("login", meta(req));
})
    .post(async (req, res) => {
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
            meta(req);
            return res.redirect("/");
        }
    });
});
router.route("/signup")
    .get((req, res) => {
    if (IsUserAuthenticated(req))
        return res.redirect("/");
    return res.render("signup", meta(req));
})
    .post(async (req, res) => {
    const { email, username, password } = req.body;
    const userExists = await users.countDocuments({
        $or: [{ username: username }, { email: email }]
    }) !== 0;
    if (userExists)
        return res.render("signup", { err: "A user already exists with this email or username.", ...meta(req) });
    await users.insertOne({
        email: email,
        username: username,
        password: await bcrypt.hash(password, 10)
    }).then(() => {
        req.session.username = username;
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
