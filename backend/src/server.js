
import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import session from "express-session";
import MongoStore from "connect-mongo";
import bcrypt from "bcryptjs";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "node:crypto";

import { User, Report, Audit } from "./models.js";
import { PRODUCTS } from "./products.js";

const app = express();
const PORT = Number(process.env.PORT || 4000);

// Add your exact deployed frontend URL here if it changes.
const ALLOWED_ORIGINS = [
  "https://dailyproductionr.netlify.app",
  "http://localhost:5173",
];

const IS_PRODUCTION =
  process.env.NODE_ENV === "production" ||
  process.env.SESSION_COOKIE_SECURE === "true";

const COOKIE_SECURE = IS_PRODUCTION;
const COOKIE_SAME_SITE = IS_PRODUCTION ? "none" : "lax";

// Validate required environment variables.
if (!process.env.MONGODB_URI) {
  throw new Error("MONGODB_URI is required.");
}

if (
  !process.env.SESSION_SECRET ||
  process.env.SESSION_SECRET.length < 32
) {
  throw new Error(
    "SESSION_SECRET must be at least 32 characters."
  );
}

// Trust the hosting platform's HTTPS reverse proxy.
app.set("trust proxy", 1);

// Security headers.
app.use(helmet());

// CORS must be configured before API routes.
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }

      return callback(
        new Error("Origin not allowed by CORS")
      );
    },
    credentials: true,
    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
    ],
  })
);

// Parse JSON request bodies.
app.use(express.json({ limit: "100kb" }));

// General API rate limiter.
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Persistent sessions stored in MongoDB.
app.use(
  session({
    name: "dpr.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: "sessions",
      ttl: 8 * 60 * 60,
    }),
    cookie: {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAME_SITE,
      maxAge: 8 * 60 * 60 * 1000,
      path: "/",
    },
  })
);

// Authentication rate limiter.
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many attempts. Please wait a minute.",
  },
});

// Helper: save a session before sending the response.
function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

// Helper: regenerate the session after successful login.
function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

// General helpers.
const normalize = (value) =>
  String(value ?? "").trim().toLowerCase();

const safe = (value, max = 500) =>
  String(value ?? "").trim().slice(0, max);

const usernameValid = (value) =>
  /^[a-zA-Z0-9_.-]{3,40}$/.test(String(value ?? ""));

const passwordValid = (value) =>
  typeof value === "string" &&
  value.length >= 12 &&
  value.length <= 128;

const makeRecoveryCode = () =>
  crypto
    .randomBytes(18)
    .toString("base64url")
    .slice(0, 24)
    .toUpperCase();

const publicUser = (user) => ({
  id: String(user._id),
  username: user.username,
  role: user.role,
  active: user.active,
});

// Authentication middleware.
const isLoggedIn = (req, res, next) => {
  if (!req.session?.user) {
    return res.status(401).json({
      error: "Please sign in first.",
    });
  }

  next();
};

const isAdmin = (req, res, next) => {
  if (!req.session?.user) {
    return res.status(401).json({
      error: "Please sign in first.",
    });
  }

  if (req.session.user.role !== "admin") {
    return res.status(403).json({
      error: "Administrator permission required.",
    });
  }

  next();
};

// Audit logging.
async function audit(req, action, details = {}) {
  try {
    await Audit.create({
      actor: req.session?.user?.username || "anonymous",
      action: safe(action, 80),
      details: safe(JSON.stringify(details), 1000),
    });
  } catch (err) {
    // Audit failure should not break the main request.
    console.error("Audit write failed:", err.message);
  }
}

// Validate report fields and calculate closing stock.
function validateReport(body = {}) {
  const date = safe(body.date, 10);

  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    throw new Error("Choose a valid report date.");
  }

  const parsedDate = new Date(`${date}T00:00:00.000Z`);

  if (
    Number.isNaN(parsedDate.getTime()) ||
    parsedDate.toISOString().slice(0, 10) !== date
  ) {
    throw new Error("Choose a valid report date.");
  }

  const product = safe(body.product, 100);

  if (!PRODUCTS.includes(product)) {
    throw new Error(
      "Select a valid product from the DPR product list."
    );
  }

  const values = {};

  for (const field of [
    "opening",
    "production",
    "returns",
    "dispatch",
  ]) {
    const value = Number(body[field]);

    if (
      !Number.isSafeInteger(value) ||
      value < 0 ||
      value > 1_000_000_000
    ) {
      throw new Error(
        `${field} must be a whole number from 0 to 1,000,000,000.`
      );
    }

    values[field] = value;
  }

  const available =
    values.opening +
    values.production +
    values.returns;

  if (
    !Number.isSafeInteger(available) ||
    values.dispatch > available
  ) {
    throw new Error(
      "Dispatch cannot exceed opening stock + production + returns."
    );
  }

  return {
    date,
    product,
    notes: safe(body.notes, 500),
    ...values,
    closing: available - values.dispatch,
  };
}

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    message: "DPR API is running.",
  });
});

// --------------------------------------------------
// AUTHENTICATION STATUS
// --------------------------------------------------

app.get("/api/auth/status", async (_req, res, next) => {
  try {
    const userCount = await User.countDocuments();

    res.json({
      setupRequired: userCount === 0,
    });
  } catch (err) {
    next(err);
  }
});

// --------------------------------------------------
// INITIAL ADMIN SETUP
// --------------------------------------------------

app.post(
  "/api/auth/setup",
  authLimiter,
  async (req, res, next) => {
    try {
      // Only allow setup when no users exist.
      if ((await User.countDocuments()) > 0) {
        return res.status(409).json({
          error: "Initial setup has already been completed.",
        });
      }

      const username = safe(req.body.username, 40);
      const password = req.body.password;

      if (!usernameValid(username)) {
        return res.status(400).json({
          error:
            "Username must be 3–40 letters, numbers, dots, underscores or hyphens.",
        });
      }

      if (!passwordValid(password)) {
        return res.status(400).json({
          error: "Password must be 12–128 characters.",
        });
      }

      if (password !== req.body.password2) {
        return res.status(400).json({
          error: "Passwords do not match.",
        });
      }

      const recoveryCode = makeRecoveryCode();

      const user = await User.create({
        username,
        usernameKey: normalize(username),
        role: "admin",
        active: true,
        passwordHash: await bcrypt.hash(password, 12),
        recoveryHash: await bcrypt.hash(recoveryCode, 12),
      });

      req.session.user = publicUser(user);

      // Critical: persist the session before returning it.
      await saveSession(req);

      await audit(req, "initial_admin_created", {
        username,
      });

      return res.status(201).json({
        user: publicUser(user),
        recoveryCode,
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post(
  "/api/auth/login",
  authLimiter,
  async (req, res, next) => {
    try {
      const usernameKey = normalize(req.body.username);
      const password = String(req.body.password ?? "");

      const user = await User.findOne({ usernameKey });

      if (
        !user ||
        !user.active ||
        !(await bcrypt.compare(
          password,
          user.passwordHash
        ))
      ) {
        await audit(req, "login_failed", {
          username: usernameKey,
        });

        return res.status(401).json({
          error:
            "Invalid username or password, or the account is disabled.",
        });
      }

      // Prevent session fixation and discard the old session.
      await regenerateSession(req);

      req.session.user = publicUser(user);

      // Wait for MongoDB session storage to complete.
      await saveSession(req);

      await audit(req, "login_success", {});

      return res.json({
        user: publicUser(user),
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// CURRENT USER
// --------------------------------------------------

app.get(
  "/api/auth/me",
  isLoggedIn,
  async (req, res, next) => {
    try {
      const user = await User.findById(
        req.session.user.id
      );

      if (!user || !user.active) {
        return req.session.destroy(() => {
          res.clearCookie("dpr.sid", {
            httpOnly: true,
            sameSite: COOKIE_SAME_SITE,
            secure: COOKIE_SECURE,
            path: "/",
          });

          res.status(401).json({
            error: "Account is no longer active.",
          });
        });
      }

      req.session.user = publicUser(user);

      await saveSession(req);

      return res.json({
        user: publicUser(user),
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// LOGOUT
// --------------------------------------------------

app.post(
  "/api/auth/logout",
  isLoggedIn,
  async (req, res, next) => {
    try {
      await audit(req, "logout", {});

      req.session.destroy((err) => {
        if (err) return next(err);

        res.clearCookie("dpr.sid", {
          httpOnly: true,
          sameSite: COOKIE_SAME_SITE,
          secure: COOKIE_SECURE,
          path: "/",
        });

        return res.json({
          message: "Logged out.",
        });
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// PASSWORD RECOVERY
// --------------------------------------------------

app.post(
  "/api/auth/reset",
  authLimiter,
  async (req, res, next) => {
    try {
      const usernameKey = normalize(req.body.username);
      const code = safe(
        req.body.recoveryCode,
        100
      ).toUpperCase();

      const password = req.body.password;

      if (!passwordValid(password)) {
        return res.status(400).json({
          error: "Password must be 12–128 characters.",
        });
      }

      if (password !== req.body.password2) {
        return res.status(400).json({
          error: "Passwords do not match.",
        });
      }

      const user = await User.findOne({
        usernameKey,
        active: true,
      });

      if (
        !user ||
        !(await bcrypt.compare(
          code,
          user.recoveryHash
        ))
      ) {
        await audit(req, "password_reset_failed", {
          username: usernameKey,
        });

        return res.status(400).json({
          error: "Invalid username or recovery code.",
        });
      }

      const newRecoveryCode = makeRecoveryCode();

      user.passwordHash = await bcrypt.hash(
        password,
        12
      );
      user.recoveryHash = await bcrypt.hash(
        newRecoveryCode,
        12
      );
      user.passwordChangedAt = new Date();

      await user.save();

      await audit(req, "password_reset_success", {
        username: usernameKey,
      });

      return res.json({
        message: "Password reset successfully.",
        recoveryCode: newRecoveryCode,
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// PRODUCTS
// --------------------------------------------------

app.get(
  "/api/products",
  isLoggedIn,
  (_req, res) => {
    res.json({
      products: PRODUCTS,
    });
  }
);

// --------------------------------------------------
// LIST REPORTS
// --------------------------------------------------

app.get(
  "/api/reports",
  isLoggedIn,
  async (req, res, next) => {
    try {
      const query = {};

      // Ordinary users see only their own reports.
      if (req.session.user.role !== "admin") {
        query.ownerId = req.session.user.id;
      }

      if (req.query.date !== undefined) {
        const date = String(req.query.date);

        if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
          return res.status(400).json({
            error: "Invalid report date.",
          });
        }

        query.date = date;
      }

      const reports = await Report.find(query)
        .sort({ date: -1, updatedAt: -1 })
        .limit(10000)
        .lean();

      return res.json({
        reports: reports.map((report) => ({
          ...report,
          id: String(report._id),
          ownerId: String(report.ownerId),
        })),
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// CREATE REPORT
// --------------------------------------------------

app.post(
  "/api/reports",
  isLoggedIn,
  async (req, res, next) => {
    try {
      const values = validateReport(req.body);

      const duplicate = await Report.findOne({
        ownerId: req.session.user.id,
        date: values.date,
        product: values.product,
      });

      if (duplicate && !req.body.allowDuplicate) {
        return res.status(409).json({
          error:
            "A report for this product and date already exists.",
          duplicate: true,
        });
      }

      const report = await Report.create({
        ...values,
        ownerId: req.session.user.id,
        ownerName: req.session.user.username,
        status: "Pending",
        updatedBy: req.session.user.username,
      });

      await audit(req, "report_created", {
        reportId: String(report._id),
        date: values.date,
        product: values.product,
      });

      return res.status(201).json({
        report: {
          ...report.toObject(),
          id: String(report._id),
          ownerId: String(report.ownerId),
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// UPDATE REPORT
// --------------------------------------------------

app.put(
  "/api/reports/:id",
  isLoggedIn,
  async (req, res, next) => {
    try {
      const report = await Report.findById(
        req.params.id
      );

      if (!report) {
        return res.status(404).json({
          error: "Report not found.",
        });
      }

      const admin =
        req.session.user.role === "admin";

      if (
        !admin &&
        String(report.ownerId) !==
          req.session.user.id
      ) {
        return res.status(403).json({
          error: "You cannot edit another user's report.",
        });
      }

      if (!admin && report.status === "Approved") {
        return res.status(403).json({
          error:
            "Approved reports are locked. Ask an administrator.",
        });
      }

      const values = validateReport(req.body);

      Object.assign(report, values, {
        status: "Pending",
        updatedBy: req.session.user.username,
        reviewedBy: undefined,
        reviewedAt: undefined,
        ...(admin ? { adminCorrection: true } : {}),
      });

      await report.save();

      await audit(req, "report_updated", {
        reportId: String(report._id),
        date: values.date,
        product: values.product,
      });

      return res.json({
        report: {
          ...report.toObject(),
          id: String(report._id),
          ownerId: String(report.ownerId),
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// APPROVE REPORT (ADMIN ONLY)
// --------------------------------------------------

app.post(
  "/api/reports/:id/approve",
  isAdmin,
  async (req, res, next) => {
    try {
      const report = await Report.findById(
        req.params.id
      );

      if (!report) {
        return res.status(404).json({
          error: "Report not found.",
        });
      }

      report.status = "Approved";
      report.reviewedBy = req.session.user.username;
      report.reviewedAt = new Date();
      report.updatedBy = req.session.user.username;

      await report.save();

      await audit(req, "report_approved", {
        reportId: String(report._id),
        owner: report.ownerName,
      });

      return res.json({
        message: "Report approved.",
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// DELETE REPORT (ADMIN ONLY)
// --------------------------------------------------

app.delete(
  "/api/reports/:id",
  isAdmin,
  async (req, res, next) => {
    try {
      const report = await Report.findByIdAndDelete(
        req.params.id
      );

      if (!report) {
        return res.status(404).json({
          error: "Report not found.",
        });
      }

      await audit(req, "report_deleted", {
        reportId: req.params.id,
        owner: report.ownerName,
        date: report.date,
      });

      return res.json({
        message: "Report deleted.",
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// LIST USERS (ADMIN ONLY)
// --------------------------------------------------

app.get(
  "/api/users",
  isAdmin,
  async (_req, res, next) => {
    try {
      const users = await User.find()
        .sort({ createdAt: 1 })
        .lean();

      return res.json({
        users: users.map(publicUser),
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// CREATE USER (ADMIN ONLY)
// --------------------------------------------------

app.post(
  "/api/users",
  isAdmin,
  async (req, res, next) => {
    try {
      const username = safe(req.body.username, 40);
      const password = req.body.password;

      if (!usernameValid(username)) {
        return res.status(400).json({
          error:
            "Use 3–40 letters, numbers, dots, underscores or hyphens.",
        });
      }

      if (!passwordValid(password)) {
        return res.status(400).json({
          error: "Password must be 12–128 characters.",
        });
      }

      const usernameKey = normalize(username);

      if (await User.exists({ usernameKey })) {
        return res.status(409).json({
          error: "That username already exists.",
        });
      }

      const recoveryCode = makeRecoveryCode();

      const user = await User.create({
        username,
        usernameKey,
        role: "user",
        active: true,
        passwordHash: await bcrypt.hash(
          password,
          12
        ),
        recoveryHash: await bcrypt.hash(
          recoveryCode,
          12
        ),
      });

      await audit(req, "user_created", {
        username,
      });

      return res.status(201).json({
        user: publicUser(user),
        recoveryCode,
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// ENABLE / DISABLE USER (ADMIN ONLY)
// --------------------------------------------------

app.patch(
  "/api/users/:id/toggle",
  isAdmin,
  async (req, res, next) => {
    try {
      const user = await User.findById(
        req.params.id
      );

      if (!user || user.role === "admin") {
        return res.status(400).json({
          error: "This account cannot be changed here.",
        });
      }

      user.active = !user.active;

      await user.save();

      await audit(
        req,
        user.active ? "user_enabled" : "user_disabled",
        { username: user.username }
      );

      return res.json({
        user: publicUser(user),
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// DELETE USER (ADMIN ONLY)
// --------------------------------------------------

app.delete(
  "/api/users/:id",
  isAdmin,
  async (req, res, next) => {
    try {
      const user = await User.findById(
        req.params.id
      );

      if (
        !user ||
        user.role === "admin" ||
        String(user._id) === req.session.user.id
      ) {
        return res.status(400).json({
          error: "This account cannot be deleted here.",
        });
      }

      await user.deleteOne();

      await audit(req, "user_deleted", {
        username: user.username,
      });

      return res.json({
        message:
          "User deleted. Existing reports are retained.",
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// AUDIT HISTORY (ADMIN ONLY)
// --------------------------------------------------

app.get(
  "/api/audit",
  isAdmin,
  async (_req, res, next) => {
    try {
      const rows = await Audit.find()
        .sort({ at: -1 })
        .limit(5000)
        .lean();

      return res.json({
        audit: rows,
      });
    } catch (err) {
      next(err);
    }
  }
);

// --------------------------------------------------
// NOT FOUND
// --------------------------------------------------

app.use("/api", (_req, res) => {
  res.status(404).json({
    error: "API endpoint not found.",
  });
});

// --------------------------------------------------
// ERROR HANDLER
// --------------------------------------------------

app.use((err, _req, res, _next) => {
  console.error("API error:", err);

  if (err?.code === 11000) {
    return res.status(409).json({
      error: "That username already exists.",
    });
  }

  if (err?.name === "CastError") {
    return res.status(400).json({
      error: "Invalid ID.",
    });
  }

  if (err?.name === "ValidationError") {
    return res.status(400).json({
      error: "Invalid data submitted.",
    });
  }

  if (err?.message === "Origin not allowed by CORS") {
    return res.status(403).json({
      error: "Origin not allowed by CORS.",
    });
  }

  return res.status(500).json({
    error: "Server error. Check backend logs for details.",
  });
});

// --------------------------------------------------
// CONNECT TO MONGODB AND START SERVER
// --------------------------------------------------

async function startServer() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);

    console.log("MongoDB connected successfully.");

    app.listen(PORT, () => {
      console.log(`DPR API running on port ${PORT}`);
      console.log(
        `Production cookies enabled: ${COOKIE_SECURE}`
      );
    });
  } catch (err) {
    console.error(
      "Server startup failed:",
      err.message
    );

    process.exit(1);
  }
}

startServer();
