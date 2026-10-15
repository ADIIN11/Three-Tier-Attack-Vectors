const mongoose = require("mongoose")

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  createdAt: String,
  verification: Boolean,
  profileImg: String,
  profileImgPubId: String,
  myCart: Array,
  myOrders: Array,
  address: Object,
  reviewsWritten: Array,
  sellerVerification: Boolean,
  productListed: Array,
  role: String,
  id: Number,
  // Tier 2 Mitigation Fields (Brute Force Lockout)
  failedLoginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Number, default: 0 }
}, { versionKey: false })

module.exports = mongoose.models.User || mongoose.model("User", userSchema, "users")