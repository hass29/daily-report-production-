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
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";

if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is required.");
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters.");
}

app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({ origin: CLIENT_URL, credentials: true }));
app.use(express.json({ limit: "100kb" }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));
app.use(session({
  name: "dpr.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI, collectionName: "sessions", ttl: 60 * 60 * 8 }),
  cookie: {
    httpOnly: true, sameSite: "lax", secure: process.env.SESSION_COOKIE_SECURE === "true",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const authLimiter = rateLimit({ windowMs: 60 * 1000, limit: 10, message: { error: "Too many attempts. Please wait a minute." } });
const normalize = value => String(value ?? "").trim().toLowerCase();
const safe = (value, max = 500) => String(value ?? "").trim().slice(0, max);
const usernameValid = value => /^[a-zA-Z0-9_.-]{3,40}$/.test(String(value ?? ""));
const passwordValid = value => typeof value === "string" && value.length >= 12 && value.length <= 128;
const makeRecoveryCode = () => crypto.randomBytes(18).toString("base64url").slice(0, 24).toUpperCase();
const publicUser = user => ({ id: String(user._id), username: user.username, role: user.role, active: user.active });
const isAdmin = (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: "Please sign in first." });
  if (req.session.user.role !== "admin") return res.status(403).json({ error: "Administrator permission required." });
  next();
};
const isLoggedIn = (req, res, next) => req.session.user ? next() : res.status(401).json({ error: "Please sign in first." });

async function audit(req, action, details = {}) {
  try {
    await Audit.create({
      actor: req.session?.user?.username || "anonymous",
      action: safe(action, 80),
      details: safe(JSON.stringify(details), 1000)
    });
  } catch (e) { console.error("Audit write failed:", e.message); }
}

function validateReport(body) {
  const date = safe(body.date, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || new Date(`${date}T00:00:00Z`).toISOString().slice(0, 10) !== date) {
    throw new Error("Choose a valid report date.");
  }
  const product = safe(body.product, 100);
  if (!PRODUCTS.includes(product)) throw new Error("Select a valid product from the DPR product list.");
  const values = {};
  for (const field of ["opening", "production", "returns", "dispatch"]) {
    const n = Number(body[field]);
    if (!Number.isSafeInteger(n) || n < 0 || n > 1000000000) {
      throw new Error(`${field} must be a whole number from 0 to 1,000,000,000.`);
    }
    values[field] = n;
  }
  const available = values.opening + values.production + values.returns;
  if (!Number.isSafeInteger(available) || values.dispatch > available) {
    throw new Error("Dispatch cannot exceed opening stock + production + returns.");
  }
  return { date, product, notes: safe(body.notes, 500), ...values, closing: available - values.dispatch };
}

app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

app.get("/api/auth/status", async (_req, res, next) => {
  try {
    res.json({ setupRequired: (await User.countDocuments()) === 0 });
  } catch (e) { next(e); }
});

app.post("/api/auth/setup", authLimiter, async (req, res, next) => {
  try {
    if (await User.countDocuments()) return res.status(409).json({ error: "Initial setup has already been completed." });
    const username = safe(req.body.username, 40);
    const password = req.body.password;
    if (!usernameValid(username)) return res.status(400).json({ error: "Username must be 3–40 letters, numbers, dots, underscores or hyphens." });
    if (!passwordValid(password)) return res.status(400).json({ error: "Password must be 12–128 characters." });
    if (password !== req.body.password2) return res.status(400).json({ error: "Passwords do not match." });
    const recoveryCode = makeRecoveryCode();
    const user = await User.create({
      username, usernameKey: normalize(username), role: "admin", active: true,
      passwordHash: await bcrypt.hash(password, 12), recoveryHash: await bcrypt.hash(recoveryCode, 12)
    });
    req.session.user = publicUser(user);
    await audit(req, "initial_admin_created", { username });
    res.status(201).json({ user: publicUser(user), recoveryCode });
  } catch (e) { next(e); }
});

app.post("/api/auth/login", authLimiter, async (req, res, next) => {
  try {
    const usernameKey = normalize(req.body.username);
    const user = await User.findOne({ usernameKey });
    if (!user || !user.active || !(await bcrypt.compare(String(req.body.password ?? ""), user.passwordHash))) {
      await audit(req, "login_failed", { username: usernameKey });
      return res.status(401).json({ error: "Invalid username or password, or the account is disabled." });
    }
    req.session.regenerate(async err => {
      if (err) return next(err);
      req.session.user = publicUser(user);
      await audit(req, "login_success", {});
      res.json({ user: publicUser(user) });
    });
  } catch (e) { next(e); }
});

app.get("/api/auth/me", isLoggedIn, async (req, res) => {
  const user = await User.findById(req.session.user.id);
  if (!user || !user.active) {
    return req.session.destroy(() => res.status(401).json({ error: "Account is no longer active." }));
  }
  req.session.user = publicUser(user);
  res.json({ user: publicUser(user) });
});

app.post("/api/auth/logout", isLoggedIn, async (req, res) => {
  await audit(req, "logout", {});
  req.session.destroy(() => {
    res.clearCookie("dpr.sid", { httpOnly: true, sameSite: "lax", secure: process.env.SESSION_COOKIE_SECURE === "true" });
    res.json({ message: "Logged out." });
  });
});

app.post("/api/auth/reset", authLimiter, async (req, res, next) => {
  try {
    const usernameKey = normalize(req.body.username);
    const code = safe(req.body.recoveryCode, 100).toUpperCase();
    const password = req.body.password;
    if (!passwordValid(password)) return res.status(400).json({ error: "Password must be 12–128 characters." });
    if (password !== req.body.password2) return res.status(400).json({ error: "Passwords do not match." });
    const user = await User.findOne({ usernameKey, active: true });
    if (!user || !(await bcrypt.compare(code, user.recoveryHash))) {
      await audit(req, "password_reset_failed", { username: usernameKey });
      return res.status(400).json({ error: "Invalid username or recovery code." });
    }
    const newRecoveryCode = makeRecoveryCode();
    user.passwordHash = await bcrypt.hash(password, 12);
    user.recoveryHash = await bcrypt.hash(newRecoveryCode, 12);
    user.passwordChangedAt = new Date();
    await user.save();
    await audit(req, "password_reset_success", { username: usernameKey });
    res.json({ message: "Password reset successfully.", recoveryCode: newRecoveryCode });
  } catch (e) { next(e); }
});

app.get("/api/products", isLoggedIn, (_req, res) => res.json({ products: PRODUCTS }));

app.get("/api/reports", isLoggedIn, async (req, res, next) => {
  try {
    const query = {};
    if (req.session.user.role !== "admin") query.ownerId = req.session.user.id;
    if (req.query.date && /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.date))) query.date = req.query.date;
    const reports = await Report.find(query).sort({ date: -1, updatedAt: -1 }).limit(10000).lean();
    res.json({ reports: reports.map(r => ({ ...r, id: String(r._id), ownerId: String(r.ownerId) })) });
  } catch (e) { next(e); }
});

app.post("/api/reports", isLoggedIn, async (req, res, next) => {
  try {
    const values = validateReport(req.body);
    const duplicate = await Report.findOne({ ownerId: req.session.user.id, date: values.date, product: values.product });
    if (duplicate && !req.body.allowDuplicate) return res.status(409).json({ error: "A report for this product and date already exists.", duplicate: true });
    const report = await Report.create({
      ...values, ownerId: req.session.user.id, ownerName: req.session.user.username,
      status: "Pending", updatedBy: req.session.user.username
    });
    await audit(req, "report_created", { reportId: report.id, date: values.date, product: values.product });
    res.status(201).json({ report: { ...report.toObject(), id: String(report._id), ownerId: String(report.ownerId) } });
  } catch (e) { next(e); }
});

app.put("/api/reports/:id", isLoggedIn, async (req, res, next) => {
  try {
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ error: "Report not found." });
    const admin = req.session.user.role === "admin";
    if (!admin && String(report.ownerId) !== req.session.user.id) return res.status(403).json({ error: "You cannot edit another user's report." });
    if (!admin && report.status === "Approved") return res.status(403).json({ error: "Approved reports are locked. Ask an administrator." });
    const values = validateReport(req.body);
    Object.assign(report, values, {
      status: "Pending", updatedBy: req.session.user.username,
      reviewedBy: undefined, reviewedAt: undefined,
      ...(admin ? { adminCorrection: true } : {})
    });
    await report.save();
    await audit(req, "report_updated", { reportId: report.id, date: values.date, product: values.product });
    res.json({ report: { ...report.toObject(), id: String(report._id), ownerId: String(report.ownerId) } });
  } catch (e) { next(e); }
});

app.post("/api/reports/:id/approve", isAdmin, async (req, res, next) => {
  try {
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ error: "Report not found." });
    report.status = "Approved";
    report.reviewedBy = req.session.user.username;
    report.reviewedAt = new Date();
    report.updatedBy = req.session.user.username;
    await report.save();
    await audit(req, "report_approved", { reportId: report.id, owner: report.ownerName });
    res.json({ message: "Report approved." });
  } catch (e) { next(e); }
});

app.delete("/api/reports/:id", isAdmin, async (req, res, next) => {
  try {
    const report = await Report.findByIdAndDelete(req.params.id);
    if (!report) return res.status(404).json({ error: "Report not found." });
    await audit(req, "report_deleted", { reportId: req.params.id, owner: report.ownerName, date: report.date });
    res.json({ message: "Report deleted." });
  } catch (e) { next(e); }
});

app.get("/api/users", isAdmin, async (_req, res, next) => {
  try {
    const users = await User.find().sort({ createdAt: 1 }).lean();
    res.json({ users: users.map(publicUser) });
  } catch (e) { next(e); }
});

app.post("/api/users", isAdmin, async (req, res, next) => {
  try {
    const username = safe(req.body.username, 40);
    const password = req.body.password;
    if (!usernameValid(username)) return res.status(400).json({ error: "Use 3–40 letters, numbers, dots, underscores or hyphens." });
    if (!passwordValid(password)) return res.status(400).json({ error: "Password must be 12–128 characters." });
    if (await User.exists({ usernameKey: normalize(username) })) return res.status(409).json({ error: "That username already exists." });
    const recoveryCode = makeRecoveryCode();
    const user = await User.create({
      username, usernameKey: normalize(username), role: "user", active: true,
      passwordHash: await bcrypt.hash(password, 12), recoveryHash: await bcrypt.hash(recoveryCode, 12)
    });
    await audit(req, "user_created", { username });
    res.status(201).json({ user: publicUser(user), recoveryCode });
  } catch (e) { next(e); }
});

app.patch("/api/users/:id/toggle", isAdmin, async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role === "admin") return res.status(400).json({ error: "This account cannot be changed here." });
    user.active = !user.active;
    await user.save();
    await audit(req, user.active ? "user_enabled" : "user_disabled", { username: user.username });
    res.json({ user: publicUser(user) });
  } catch (e) { next(e); }
});

app.delete("/api/users/:id", isAdmin, async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role === "admin" || user.id === req.session.user.id) {
      return res.status(400).json({ error: "This account cannot be deleted here." });
    }
    await user.deleteOne();
    await audit(req, "user_deleted", { username: user.username });
    res.json({ message: "User deleted. Existing reports are retained." });
  } catch (e) { next(e); }
});

app.get("/api/audit", isAdmin, async (_req, res, next) => {
  try {
    const rows = await Audit.find().sort({ at: -1 }).limit(5000).lean();
    res.json({ audit: rows });
  } catch (e) { next(e); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  if (err?.code === 11000) return res.status(409).json({ error: "That username already exists." });
  if (err?.name === "CastError") return res.status(400).json({ error: "Invalid ID." });
  if (err?.name === "ValidationError") return res.status(400).json({ error: "Invalid data submitted." });
  res.status(500).json({ error: "Server error. Check backend logs for details." });
});

mongoose.connect(process.env.MONGODB_URI)
  .then(() => app.listen(PORT, () => console.log(`DPR API running at http://localhost:${PORT}`)))
  .catch(err => { console.error("MongoDB connection failed:", err.message); process.exit(1); });
