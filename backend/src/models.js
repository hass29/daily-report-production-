import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, trim: true, minlength: 3, maxlength: 40 },
  usernameKey: { type: String, required: true, unique: true, index: true },
  role: { type: String, enum: ["admin", "user"], default: "user", required: true },
  active: { type: Boolean, default: true },
  passwordHash: { type: String, required: true },
  recoveryHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  passwordChangedAt: Date
}, { timestamps: true });

const reportSchema = new mongoose.Schema({
  date: { type: String, required: true, match: /^\d{4}-\d{2}-\d{2}$/ },
  product: { type: String, required: true, maxlength: 100 },
  notes: { type: String, maxlength: 500, default: "" },
  opening: { type: Number, required: true, min: 0, max: 1000000000 },
  production: { type: Number, required: true, min: 0, max: 1000000000 },
  returns: { type: Number, required: true, min: 0, max: 1000000000 },
  dispatch: { type: Number, required: true, min: 0, max: 1000000000 },
  closing: { type: Number, required: true, min: 0 },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  ownerName: { type: String, required: true },
  status: { type: String, enum: ["Pending", "Approved"], default: "Pending" },
  updatedBy: String,
  reviewedBy: String,
  reviewedAt: Date,
  adminCorrection: { type: Boolean, default: false }
}, { timestamps: true });

const auditSchema = new mongoose.Schema({
  at: { type: Date, default: Date.now, index: true },
  actor: { type: String, default: "anonymous" },
  action: { type: String, required: true, maxlength: 80 },
  details: { type: String, maxlength: 1000, default: "" }
});

export const User = mongoose.model("User", userSchema);
export const Report = mongoose.model("Report", reportSchema);
export const Audit = mongoose.model("Audit", auditSchema);
