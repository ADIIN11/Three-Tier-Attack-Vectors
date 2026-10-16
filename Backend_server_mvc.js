const express = require("express")
const path = require("path")
const os = require("os")
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
const HOST = "0.0.0.0"

// ============================================================================
// TIER 1 MITIGATION: GLOBAL RATE LIMITER (Active only when TIER_1_DOS is true)
// ============================================================================
const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 1000, // per IP per minute; high enough for shared NATs (college Wi-Fi). Use 80 for a single-machine demo.
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

const server = app.listen(PORT, HOST, () => {
  console.log("==================================================")
  console.log("server is running")
  console.log("welcome to Esther Gate")
  console.log(`Listening on ${HOST}:${PORT}`)
  console.log(`Local URL: http://localhost:${PORT}/Store`)

  const interfaces = os.networkInterfaces()
  for (const name of Object.keys(interfaces)) {
    for (const net of interfaces[name]) {
      if (net.family === "IPv4" && !net.internal) {
        console.log(`Network (${name}): http://${net.address}:${PORT}/Store`)
      }
    }
  }
  console.log("==================================================")
  console.log("Initial Security Switch State:", global.SECURITY_MITIGATIONS)
})

// ============================================================================
// TIER 1 SOCKET & SLOWLORIS MANAGEMENT (Live Feed Logging)
// ============================================================================
// Detection is based on STALLED sockets (open > STALL_MS without completing a
// single HTTP request), NOT on total socket count. This keeps shared-IP networks
// (college Wi-Fi, office NAT, mobile carrier CGNAT) with many real users safe.
const STALL_MS = 1000                  // a real client finishes its request well within this
const MAX_STALLED_PER_IP = 15          // stalled sockets from one IP before it's flagged
const QUARANTINE_MS = 30 * 1000        // how long a flagged IP stays throttled
const QUARANTINE_MAX_PENDING = 2       // while quarantined, max unfinished sockets allowed
const SWEEP_INTERVAL_MS = 500

// Set TIER1_INCLUDE_LOCALHOST=true in .env to test the defence from your own machine
const INCLUDE_LOCALHOST = process.env.TIER1_INCLUDE_LOCALHOST === "true"

const socketsPerIp = new Map()      // ip -> Set of live sockets
const genuineCustomers = new Set()  // IPs that completed at least one real HTTP request
const quarantinedIps = new Map()    // ip -> quarantine expiry timestamp

function getSocketIp(socket) {
  return (socket.remoteAddress || "unknown").replace("::ffff:", "")
}

function isLocalIp(ip) {
  if (INCLUDE_LOCALHOST) return false
  return ip === "127.0.0.1" || ip === "::1" || ip === "localhost"
}

function applyTier1SocketPolicy() {
  const active = global.SECURITY_MITIGATIONS.TIER_1_DOS

  if (active) {
    server.maxConnections = 0 // 0 = unlimited; stalled-socket detection does the protecting
    server.keepAliveTimeout = 2000
    server.headersTimeout = 2000
    console.log("[BLUE TEAM - TIER 1] Strict 2s timeouts and stalled-socket detection ENABLED")
  } else {
    server.maxConnections = 20
    server.keepAliveTimeout = 300000
    server.headersTimeout = 300000
    quarantinedIps.clear()
    console.log("[RED TEAM - TIER 1] Server vulnerable to Slowloris (maxConnections: 20, timeouts: 300s)")
  }

  // Apply/remove the idle timeout on connections that are already open,
  // so toggling the switch live takes effect immediately
  for (const sockets of socketsPerIp.values()) {
    for (const s of sockets) s.setTimeout(active ? 2000 : 0)
  }
}

applyTier1SocketPolicy()

function countPending(sockets) {
  let n = 0
  for (const s of sockets) if (!s.requestSeen) n++
  return n
}

server.on("connection", (socket) => {
  const remoteIp = getSocketIp(socket)

  // Local machine testing is whitelisted (unless TIER1_INCLUDE_LOCALHOST=true)
  if (isLocalIp(remoteIp)) return

  const tier1Active = global.SECURITY_MITIGATIONS.TIER_1_DOS

  let sockets = socketsPerIp.get(remoteIp)
  if (!sockets) {
    sockets = new Set()
    socketsPerIp.set(remoteIp, sockets)
  }

  // A quarantined IP isn't blocked outright (it may be a shared network with real
  // users). It just can't hold more than a couple of unfinished sockets at once.
  if (tier1Active && quarantinedIps.has(remoteIp)) {
    if (quarantinedIps.get(remoteIp) <= Date.now()) {
      quarantinedIps.delete(remoteIp)
      console.log(`[BLUE TEAM - TIER 1] Quarantine lifted for IP: ${remoteIp}`)
    } else if (countPending(sockets) >= QUARANTINE_MAX_PENDING) {
      socket.destroy()
      if (sockets.size === 0) socketsPerIp.delete(remoteIp)
      return
    }
  }

  socket.openedAt = Date.now()
  socket.requestSeen = false
  sockets.add(socket)

  if (tier1Active) socket.setTimeout(2000)
  socket.on("timeout", () => {
    if (!global.SECURITY_MITIGATIONS.TIER_1_DOS) return
    console.log(`[BLUE TEAM - TIER 1 DEFENSE] Severed stalled Slowloris socket from IP: ${remoteIp}`)
    socket.destroy()
  })

  socket.on("error", () => socket.destroy()) // avoids crashes on ECONNRESET floods

  socket.on("close", () => {
    sockets.delete(socket)
    if (sockets.size === 0) {
      socketsPerIp.delete(remoteIp)
      genuineCustomers.delete(remoteIp) // they get pinged again on their next visit
    }
  })
})

// A client is "genuine" once it completes a full HTTP request.
// Slowloris sockets never get here because they never finish sending headers.
server.on("request", (req) => {
  req.socket.requestSeen = true

  const ip = getSocketIp(req.socket)
  if (isLocalIp(ip) || genuineCustomers.has(ip)) return

  genuineCustomers.add(ip)
  console.log(`[CUSTOMER FEED @ ${new Date().toLocaleTimeString()}] Genuine customer connected from IP: ${ip}`)
})

// Sweeper: finds IPs holding many stalled sockets and boots ONLY those sockets.
setInterval(() => {
  if (!global.SECURITY_MITIGATIONS.TIER_1_DOS) return
  const now = Date.now()

  for (const [ip, sockets] of socketsPerIp) {
    const stalled = [...sockets].filter(s => !s.requestSeen && now - s.openedAt > STALL_MS)
    if (stalled.length < MAX_STALLED_PER_IP) continue

    const timestamp = new Date().toLocaleTimeString()
    const healthy = sockets.size - stalled.length
    console.log(`[BLUE TEAM - TIER 1 ALERT @ ${timestamp}] IP ${ip} is a POTENTIAL DoS ATTACKER (${stalled.length} stalled sockets that never completed a request).`)
    console.log(`[BLUE TEAM - TIER 1 ACTION] Booting ${stalled.length} stalled sockets from ${ip} for DoS violation. ${healthy} healthy connection(s) from this IP left intact. Quarantined for ${QUARANTINE_MS / 1000}s.`)

    for (const s of stalled) s.destroy()
    quarantinedIps.set(ip, now + QUARANTINE_MS)
  }
}, SWEEP_INTERVAL_MS).unref()