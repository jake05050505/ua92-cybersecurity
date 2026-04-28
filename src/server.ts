import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import session from "express-session";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { router } from "./router.ts";
import config from "../config.json" with { type: "json" };

dotenv.config();
const { NODE_ENV, SESSION_SECRET } = process.env;
const { hostname, port } = config.Server;
const DEV_MODE = NODE_ENV !== "production";

// .env file variables
if (!SESSION_SECRET) {
    if (!SESSION_SECRET) console.error("SESSION_SECRET is missing!");
    throw new Error("One or more environment variables could not be found, check your environment variables.");
}

const __filename: string = fileURLToPath(import.meta.url);
const __dirname: string = path.dirname(__filename);

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "../views"));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "../static")));
app.use(session({
    secret: SESSION_SECRET,
    saveUninitialized: true,
    resave: false,
    cookie: {
        maxAge: 60 * 1000 * 60, // 1 hour
        secure: false
    }
}));
app.use(router);

app.listen(port, () => {
    console.log(`Server running on http://${hostname}:${port}`);
    console.log(`Running in ${DEV_MODE ? "development" : "production"} mode${DEV_MODE ? ", debugging enabled" : ""}.`);
});