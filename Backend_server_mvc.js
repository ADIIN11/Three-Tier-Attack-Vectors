const express = require("express")
const path = require("path")
const axios = require("axios")
const rateLimit = require("express-rate-limit")

require("dotenv").config({ quiet: true })

// ============================================================================
// MASTER VULNERABILITY / MITIGATION SWITCH
// false = RED TEAM MODE (Vulnerable) | true = BLUE TEAM MODE (Mitigated)
// ============================================================================
global.SECURITY_MITIGATIONS = {
  TIER_1_DOS: false,
  TIER_2_BRUTE_FORCE: false,
  TIER_3_SESSION_HIJACK: false
}

const { productsList, userList } = require("./data")
const mongoose = require("mongoose")
const { exit } = require("process")

mongoose.connect(process.env.MONGO_DB_URL)
  .then(() => console.log("MongoDB Connected Successfully :)"))
  .catch(err => console.log("MongoDB Connection Error :", err))

const authRoutes = require("./routes/authRoutes")
const commonRoutes = require("./routes/commonRoutes")
const profileRoutes = require("./routes/profileRoutes")
const categoryRoutes = require("./routes/productRoutes")
const storeRoutes = require("./routes/storeRoutes")

const app = express()

app.use(express.json())

const PORT = process.env.PORT || 5000

// ============================================================================
// TIER 1 MITIGATION: GLOBAL RATE LIMITER (Active only when TIER_1_DOS is true)
// ============================================================================
const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 80,
  skip: () => !global.SECURITY_MITIGATIONS.TIER_1_DOS,
  handler: (req, res) => {
    console.log(`[BLUE TEAM - TIER 1] Rate limit exceeded by IP: ${req.ip}`)
    res.status(429).send("Too many requests from this IP. DoS Protection Active.")
  }
})

app.use(globalLimiter)

// ============================================================================
// LIVE PRESENTATION SWITCH ROUTE (Toggle tiers without restarting server)
// Usage: http://localhost:5000/Security_Switch?tier1=true&tier2=true&tier3=true
// ============================================================================
app.get("/Security_Switch", (req, res) => {
  if (req.query.tier1 !== undefined) {
    global.SECURITY_MITIGATIONS.TIER_1_DOS = req.query.tier1 === "true"
    applyTier1SocketPolicy()
  }
  if (req.query.tier2 !== undefined) {
    global.SECURITY_MITIGATIONS.TIER_2_BRUTE_FORCE = req.query.tier2 === "true"
  }
  if (req.query.tier3 !== undefined) {
    global.SECURITY_MITIGATIONS.TIER_3_SESSION_HIJACK = req.query.tier3 === "true"
  }

  console.log("Updated Security Switch State:", global.SECURITY_MITIGATIONS)
  res.json({
    message: "EstherGate Security Switch Updated",
    activeMitigations: global.SECURITY_MITIGATIONS
  })
})

app.use("/Auth", authRoutes)
app.use("", commonRoutes)
app.use("/Profile", profileRoutes)
app.use("/Product", categoryRoutes)
app.use("/Store", storeRoutes)

app.use(express.static(path.join(__dirname, "public")))

app.get("/Store", (req, res) => {
  res.sendFile(path.join(__dirname, "Store.html"))
})

app.use((req, res) => {
  res.status(404).send("Page Not Found")
})

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log("server is running")
  console.log("welcome to Esther Gate")
  console.log(`Listening on port ${PORT}`)
  console.log("Initial Security Switch State:", global.SECURITY_MITIGATIONS)
})

// ============================================================================
// TIER 1 SOCKET & SLOWLORIS MANAGEMENT
// ============================================================================
const socketsPerIp = new Map()

function applyTier1SocketPolicy() {
  if (global.SECURITY_MITIGATIONS.TIER_1_DOS) {
    // BLUE TEAM: Drop stalled Slowloris headers in 5s and uncap total server pool
    server.maxConnections = 0
    server.keepAliveTimeout = 4000
    server.headersTimeout = 5000
    console.log("[BLUE TEAM - TIER 1] Strict socket timeouts and per-IP connection limits ENABLED")
  } else {
    // RED TEAM: Cap total server sockets to 50 and allow long idle headers so Slowloris freezes the site
    server.maxConnections = 50
    server.keepAliveTimeout = 300000
    server.headersTimeout = 300000
    console.log("[RED TEAM - TIER 1] Server vulnerable to Slowloris (maxConnections: 50, timeouts: 300s)")
  }
}

applyTier1SocketPolicy()

server.on("connection", (socket) => {
  const remoteIp = (socket.remoteAddress || "unknown").replace("::ffff:", "")

  if (global.SECURITY_MITIGATIONS.TIER_1_DOS) {
    const currentCount = socketsPerIp.get(remoteIp) || 0
    if (currentCount >= 15) {
      console.log(`[BLUE TEAM - TIER 1] Dropping excess concurrent socket from ${remoteIp}`)
      socket.destroy()
      return
    }
    socketsPerIp.set(remoteIp, currentCount + 1)

    socket.setTimeout(5000)
    socket.on("timeout", () => {
      console.log(`[BLUE TEAM - TIER 1] Severed stalled Slowloris socket from ${remoteIp}`)
      socket.destroy()
    })

    socket.on("close", () => {
      const updated = (socketsPerIp.get(remoteIp) || 1) - 1
      if (updated <= 0) {
        socketsPerIp.delete(remoteIp)
      } else {
        socketsPerIp.set(remoteIp, updated)
      }
    })
  }
})