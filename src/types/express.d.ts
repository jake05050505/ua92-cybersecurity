import "express-session";
import "express-serve-static-core";

// #region router.ts
declare module "express-session" {
    interface SessionData {
        viewCount?: number;
        username?: string;
        role?: string;
        err?: string;
    }
}

declare module "express-serve-static-core" {
    interface Request {
        rateLimit: Record<string, number>;
    }
}
// #endregion