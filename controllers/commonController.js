const userModel = require("../models/userModel.js")
const productModel = require("../models/productModel.js")
const {
  verifyTokenSignIn,
  isTokenRevoked,
  revokeToken,
} = require("../services/tokenService")

function getCleanIp(req) {
  const rawIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || req.ip || "unknown"
  return String(rawIp).split(",")[0].trim().replace("::ffff:", "")
}

exports.tokenVerification = async (req, res) => {
  const tokenObj = req.body
  const token = tokenObj.token
  const requestIp = getCleanIp(req)
  const tier3Active = global.SECURITY_MITIGATIONS && global.SECURITY_MITIGATIONS.TIER_3_SESSION_HIJACK

  if (isTokenRevoked(token)) {
    console.log(`[AUTH] Rejected revoked token from IP: ${requestIp}`)
    return res.json({ tokenVerified: false, reason: "Token has been revoked" })
  }

  const userData = await verifyTokenSignIn(tokenObj)

  if (userData) {
    // ========================================================================
    // TIER 3 MITIGATION: ZERO-TRUST IP BINDING & ANOMALY DETECTION
    // ========================================================================
    if (userData.boundIp && userData.boundIp !== requestIp) {
      if (tier3Active) {
        console.log(`[BLUE TEAM - TIER 3 ALERT] Session Hijack Blocked! Token bound to ${userData.boundIp}, but replayed from ${requestIp}`)
        revokeToken(token)
        return res.json({
          tokenVerified: false,
          anomalyDetected: true,
          message: "Session anomaly detected: IP mismatch. Token revoked."
        })
      } else {
        console.log(`[RED TEAM - TIER 3 EXPLOIT] Stolen token for user "${userData.username}" (Origin IP: ${userData.boundIp}) successfully replayed from Attacker IP: ${requestIp}`)
      }
    }

    const id = userData.id
    res.json({
      tokenVerified: true,
      id: id,
      username: userData.username
    })
  } else {
    res.json({ tokenVerified: false })
  }
}

exports.userSignOut = (req, res) => {
  const tokenObj = req.body
  const token = tokenObj.token
  revokeToken(token)
  res.json({ message: "Token revoked" })
}

exports.getProfileImage = async (req, res) => {
  try {
    const profileImg = await getProfileImg(req.body)
    const ProfileUsername = await getProfileUsername(req.body)
    const myCart = await getProfileCart(req.body)
    const myCartTotal = myCart.reduce((sum, currentItem) => {
      return sum + currentItem.quantity
    }, 0)
    res.json({
      profileImg: profileImg,
      username: ProfileUsername,
      myCartItemNo: myCartTotal
    })
  } catch (err) {
    console.log("error while sending profileimg:", err)
  }
}

async function getProfileImgDB(userObj) {
  try {
    const profileImg = await userModel.find({ id: userObj.id }).select("-_id profileImg")
    return profileImg
  } catch (err) {
    console.log("did not find profileImg :", err)
  }
}

async function getProfileImg(userObj) {
  let profileImg = await getProfileImgDB(userObj)
  profileImg = profileImg[0].profileImg
  return profileImg
}

async function getProfileCartDB(userObj) {
  try {
    const myCart = await userModel.find({ id: userObj.id }).select("-_id myCart")
    return myCart
  } catch (err) {
    console.log("did not find myCart :", err)
  }
}

async function getProfileCart(userObj) {
  let myCart = await getProfileCartDB(userObj)
  myCart = myCart[0].myCart
  return myCart
}

async function getProfileUsernameDB(userObj) {
  try {
    const profileUsername = await userModel.find({ id: userObj.id }).select("-_id username")
    return profileUsername
  } catch (err) {
    console.log("did not find profile username :", err)
  }
}

async function getProfileUsername(userObj) {
  let profileUsername = await getProfileUsernameDB(userObj)
  profileUsername = profileUsername[0].username
  return profileUsername
}

exports.addProductToCart = async (req, res) => {
  const userId = req.body.userId
  const productId = req.body.productId
  try {
    const result = await userModel.updateOne(
      { id: userId, "myCart.productId": productId },
      { $inc: { "myCart.$.quantity": 1 } }
    )
    if (result.matchedCount === 0) {
      await userModel.updateOne(
        { id: userId },
        { $push: { myCart: { productId: productId, quantity: 1 } } }
      )
    }
    res.json({ message: "product successfully added to cart" })
  } catch (err) {
    console.log("error while adding product to user cart ")
  }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

exports.searchProducts = async (req, res) => {
  try {
    const searchTerm = req.body.searchTerm || ""

    if (!searchTerm.trim()) {
      return res.json({ products: [] })
    }

    let products = await productModel.find({
      $text: {$search: searchTerm }
    }).limit(20)

    if (products.length === 0) {
      const searchRegex = new RegExp(searchTerm, "i")

      products = await productModel.find({
        $or: [
          { name: { $regex: searchRegex } },
          { sellerName: { $regex: searchRegex } },
          { category: { $regex: searchRegex } },
          { type: { $regex: searchRegex } },
          { tags: { $in: [searchRegex] } }
        ]
      }).limit(20)
    }

    res.json({ products: products })
  } catch (err) {
    console.log("Error searching products:", err)
    res.status(500).json({ error: "Failed to search products" })
  }
}