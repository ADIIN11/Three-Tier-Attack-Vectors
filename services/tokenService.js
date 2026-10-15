const jwt = require("jsonwebtoken")
const userModel = require("../models/userModel")

exports.tokenGenerator = async function (userObj, clientIp = "unknown") {
  async function getUserDataDB() {
    try {
      const userByUsername = await userModel.find({ username: userObj.usernameEmail }).select("-_id username role id")
      if (userByUsername && userByUsername.length > 0) {
        return userByUsername
      }
    } catch (err) {
      console.log("did not find username :", err)
    }

    try {
      const userByEmail = await userModel.find({ email: userObj.usernameEmail }).select("-_id username role id")
      return userByEmail
    } catch (err) {
      console.log("did not find email :", err)
    }
  }

  const payloadArrObj = await getUserDataDB()
  const payload = payloadArrObj[0].toObject()

  const secretKey = process.env.JWT_SECRET
  if (!secretKey) {
    throw new Error("JWT_SECRET is not defined in .env")
  }

  const tier3Active = global.SECURITY_MITIGATIONS && global.SECURITY_MITIGATIONS.TIER_3_SESSION_HIJACK

  // Always embed origin IP so we can log Red Team exploits vs Blue Team blocks
  payload.boundIp = clientIp

  // ==========================================================================
  // TIER 3 MITIGATION: SHORT-LIVED (15m) vs LONG-LIVED (30d) JWT
  // ==========================================================================
  const tokenLifespan = tier3Active ? "15m" : "30d"
  const token = jwt.sign(payload, secretKey, { expiresIn: tokenLifespan })

  return token
}

exports.verifyTokenSignIn = async function verifyTokenSignIn(tokenObj) {
  const token = tokenObj.token

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    return decoded
  } catch (err) {
    console.error("Invalid token:", err)
    return false
  }
}

const revokedTokens = new Map()

exports.revokeToken = function (token) {
  revokedTokens.set(token, Date.now())
  console.log(`Token: ${token.substring(0, 20)}... is in the revoked list`)
}

exports.isTokenRevoked = function (token) {
  return revokedTokens.has(token)
}

setInterval(() => {
  const now = Date.now()
  for (const [token, time] of revokedTokens.entries()) {
    if (now - time > 2 * 60 * 60 * 1000) {
      revokedTokens.delete(token)
      console.log(`Token expired from revoked list`)
    }
  }
}, 10 * 60 * 1000)