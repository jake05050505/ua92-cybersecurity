import { Router, type Request, type Response } from "express";
import "dotenv";
import bcrypt from "bcrypt";
import "express-session";
import { type WithId } from "mongodb";
import { users, type User }  from "./db.ts";

declare module "express-session" {
    interface SessionData {
        username: string;
        viewCount: number;
    }
}

const {NODE_ENV} = process.env;
if (!NODE_ENV) throw new Error("NODE_ENV is missing!\nCheck your package.json scripts and make sure that `cross-env NODE_ENV={value}` is set. (NODE_ENV=\"production\" for production environments)");

const DEV_MODE: boolean = process.env.NODE_ENV !== 'production';
export const router = Router();

function meta(req: Request): Record<any, any> {
    function incrementViewCount(): number {
        if (!req.session.viewCount) req.session.viewCount = 0;
        return ++req.session.viewCount;
    }
    return { DEV_MODE, viewCount: incrementViewCount() };
}

function IsUserAuthenticated(req: Request): boolean {
    return typeof req.session.username !== "undefined";
};

router.route("/")
    .get((req: Request, res: Response) => {
        if (IsUserAuthenticated(req)) return res.render("dashboard", { username: req.session.username, ...meta(req) });
        else return res.render("login", meta(req));
    })
    .post(async (req: Request, res: Response) => {
        const { username, password }: { username: string, password: string } = req.body;

        const storedUser: WithId<User> | null = await users.findOne<WithId<User>>({ username: username });
        if (storedUser === null) return res.render("login", { err: "Invalid Username or Password.", ...meta(req) });

        const storedHash = storedUser.password;
        bcrypt.compare(password, storedHash, (err, result) => {
            if (err) throw err;
            if (!result) return res.render("login", { err: "Invalid Username or Password.", ...meta(req) });
            else {
                req.session.username = storedUser.username;
                meta(req);

                return res.redirect("/");
            }
        });
    });

router.route("/signup")
    .get((req: Request, res: Response) => {
        if (IsUserAuthenticated(req)) return res.redirect("/");
        return res.render("signup", meta(req));
    })
    .post(async (req: Request, res: Response,) => {
        const { email, username, password }: { email: string, username: string, password: string } = req.body;

        const userExists: boolean = await users.countDocuments({
            $or: [{username: username}, {email: email}]
        }) !== 0;

        if (userExists) return res.render("signup", { err: "A user already exists with this email or username.", ...meta(req)});
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
            if (err) throw err;
            return res.redirect("/");
        });
    });