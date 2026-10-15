const userModel = require("../models/userModel.js")
const bcrypt = require("bcrypt")

const {
  tokenGenerator,
} = require("../services/tokenService")

function getCleanIp(req) {
  const rawIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || req.ip || "unknown"
  return String(rawIp).split(",")[0].trim().replace("::ffff:", "")
}

exports.userSingUp = async (req, res) => {
  const userData = req.body
  console.log(userData)
  const checkUser = await checkUserSignUp(userData)
  if (checkUser) {
    if (checkUser === 1)
      res.json({ exists: 1 })
    else if (checkUser === 2)
      res.json({ exists: 2 })
  } else {
    await createUser(userData)
    res.json({ exists: false })
  }
}

async function checkUserSignUp(userObj) {
  const uniqueUserNameEmailObjArr = await userModel.find().select("-_id username email")
  const uniqueUserNameEmail = [
    ...new Set(uniqueUserNameEmailObjArr.map((objName) => objName.username)),
    ...new Set(uniqueUserNameEmailObjArr.map((objEamil) => objEamil.email))
  ]

  for (const item of uniqueUserNameEmail) {
    if (item === userObj.username)
      return 1
    if (item === userObj.email)
      return 2
  }
  return false
}

async function createUser(userObj) {
  let password = userObj.password
  const saltRounds = 10

  try {
    const hash = await bcrypt.hash(password, saltRounds)
    userObj.password = hash
  } catch (err) {
    console.error("Error hashing password:", err)
  }

  let id = "id"
  userObj[id] = await userModel.countDocuments()
  userObj.failedLoginAttempts = 0
  userObj.lockUntil = 0
  console.log(userObj)
  const newUser = new userModel(userObj)
  await newUser.save()
    .then(() => console.log("New Account Saved"))
    .catch(err => console.log("Saving Error", err))
}

//////////////////////////////////////////////////////////////////////////////////////////////////

exports.userSingIn = async (req, res) => {
  const userData = req.body
  const clientIp = getCleanIp(req)
  const tier2Active = global.SECURITY_MITIGATIONS && global.SECURITY_MITIGATIONS.TIER_2_BRUTE_FORCE

  const userDoc = await userModel.findOne({
    $or: [
      { username: userData.usernameEmail },
      { email: userData.usernameEmail }
    ]
  })

  if (!userDoc) {
    return res.json({ exists: false })
  }

  // ==========================================================================
  // TIER 2 MITIGATION: CHECK ACCOUNT LOCKOUT STATUS
  // ==========================================================================
  if (tier2Active && userDoc.lockUntil && userDoc.lockUntil > Date.now()) {
    const remainingSeconds = Math.ceil((userDoc.lockUntil - Date.now()) / 1000)
    console.log(`[BLUE TEAM - TIER 2] Blocked login to locked account "${userDoc.username}" (${remainingSeconds}s remaining)`)
    return res.json({
      exists: true,
      passwordCorrect: false,
      locked: true,
      message: `Account locked due to brute-force protection. Try again in ${remainingSeconds} seconds.`
    })
  }

  const isPasswordValid = await checkPassword(userData, userDoc)

  if (isPasswordValid) {
    // Reset failed counters upon successful login
    if (userDoc.failedLoginAttempts > 0 || userDoc.lockUntil > 0) {
      await userModel.updateOne(
        { _id: userDoc._id },
        { $set: { failedLoginAttempts: 0, lockUntil: 0 } }
      )
    }

    const token = await tokenGenerator(userData, clientIp)
    console.log(`[AUTH] Issued JWT for "${userDoc.username}" to IP: ${clientIp}`)
    return res.json({ exists: true, passwordCorrect: true, token: token })
  } else {
    // ========================================================================
    // TIER 2 MITIGATION: INCREMENT FAILED ATTEMPTS & LOCK AT 5 FAILURES
    // ========================================================================
    if (tier2Active) {
      const newFailCount = (userDoc.failedLoginAttempts || 0) + 1
      const updateFields = { failedLoginAttempts: newFailCount }

      if (newFailCount >= 5) {
        updateFields.lockUntil = Date.now() + 15 * 60 * 1000
        console.log(`[BLUE TEAM - TIER 2] Account "${userDoc.username}" LOCKED for 15 minutes after 5 failed attempts!`)
      } else {
        console.log(`[BLUE TEAM - TIER 2] Failed login ${newFailCount}/5 for "${userDoc.username}"`)
      }

      await userModel.updateOne({ _id: userDoc._id }, { $set: updateFields })
    } else {
      console.log(`[RED TEAM - TIER 2] Unthrottled failed login attempt on "${userDoc.username}" from ${clientIp}`)
    }

    return res.json({ exists: true, passwordCorrect: false })
  }
}

async function checkPassword(userObj, userDoc) {
  try {
    const isMatch = await bcrypt.compare(userObj.password, userDoc.password)
    return isMatch
  } catch (err) {
    console.error("Error password matching:", err)
    return false
  }
}