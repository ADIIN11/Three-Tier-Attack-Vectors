// ==========================================
// CAPTCHA KILL-SWITCH CONFIGURATION
// Set CAPTCHA_ENABLED = false or run setCaptcha(false) in DevTools Console
// ==========================================
let CAPTCHA_ENABLED = localStorage.getItem("captchaDisabled") === "true" ? false : true
let currentCaptchaText = ""

const msgPara = document.getElementById("msg-id")
const passwordInpt = document.getElementById("password-inpt")
const nameEmailInpt = document.getElementById("username-email-inpt")
const captchaInpt = document.getElementById("captcha-inpt")
const captchaImg = document.getElementById("captcha-img")
const captchaBox = document.getElementById("captcha-box")
const reloadCaptchaBtn = document.getElementById("reload-captcha-btn")
const form = document.getElementById("form-id")

function generateCaptcha() {
    if (!CAPTCHA_ENABLED) {
        if (captchaBox) captchaBox.style.display = "none"
        return
    }
    if (captchaBox) captchaBox.style.display = "block"

    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    currentCaptchaText = ""
    for (let i = 0; i < 5; i++) {
        currentCaptchaText += chars.charAt(Math.floor(Math.random() * chars.length))
    }

    const offCanvas = document.createElement("canvas")
    offCanvas.width = 140
    offCanvas.height = 45
    const cCtx = offCanvas.getContext("2d")

    // Background matching EstherGate palette
    cCtx.fillStyle = "#fef4bc"
    cCtx.fillRect(0, 0, offCanvas.width, offCanvas.height)

    // Interference noise lines
    for (let i = 0; i < 5; i++) {
        cCtx.strokeStyle = i % 2 === 0 ? "#e35311" : "#feb60b"
        cCtx.lineWidth = 1.5
        cCtx.beginPath()
        cCtx.moveTo(Math.random() * offCanvas.width, Math.random() * offCanvas.height)
        cCtx.lineTo(Math.random() * offCanvas.width, Math.random() * offCanvas.height)
        cCtx.stroke()
    }

    // Noise dots
    for (let i = 0; i < 30; i++) {
        cCtx.fillStyle = "#ef720a"
        cCtx.beginPath()
        cCtx.arc(Math.random() * offCanvas.width, Math.random() * offCanvas.height, 1, 0, Math.PI * 2)
        cCtx.fill()
    }

    // Draw distorted characters
    cCtx.font = "bold 24px Franklin Gothic Medium, Arial"
    cCtx.fillStyle = "#e35311"
    cCtx.textBaseline = "middle"

    for (let i = 0; i < currentCaptchaText.length; i++) {
        cCtx.save()
        const x = 18 + i * 24
        const y = offCanvas.height / 2 + (Math.random() - 0.5) * 8
        const angle = (Math.random() - 0.5) * 0.45
        cCtx.translate(x, y)
        cCtx.rotate(angle)
        cCtx.fillText(currentCaptchaText[i], 0, 0)
        cCtx.restore()
    }

    captchaImg.src = offCanvas.toDataURL("image/png")
    captchaInpt.value = ""
}

// Console command to disable/enable CAPTCHA anytime
window.setCaptcha = function(state) {
    CAPTCHA_ENABLED = Boolean(state)
    localStorage.setItem("captchaDisabled", !CAPTCHA_ENABLED)
    generateCaptcha()
    console.log(`CAPTCHA is now ${CAPTCHA_ENABLED ? "ENABLED" : "DISABLED"}`)
}

if (reloadCaptchaBtn) {
    reloadCaptchaBtn.addEventListener("click", generateCaptcha)
}

generateCaptcha()

form.addEventListener("submit", submit)

async function submit(event) {
    event.preventDefault()

    if (!nameEmailInpt.value || !passwordInpt.value) {
        msgPara.textContent = "Fill all the box"
        console.log("Fill all the box")
        return
    }

    if (CAPTCHA_ENABLED) {
        if (!captchaInpt.value) {
            msgPara.textContent = "Pls Fill Captcha"
            console.log("Pls Fill Captcha")
            return
        }
        if (captchaInpt.value.trim() !== currentCaptchaText) {
            msgPara.textContent = "Incorrect Captcha, Try Again"
            console.log("Incorrect Captcha")
            generateCaptcha()
            return
        }
    }

    let userData = {
        usernameEmail: nameEmailInpt.value,
        password: passwordInpt.value,
    }

    try {
        const res = await axios.post("/Auth/Sign_In", userData)

        if (!res.data.exists) {
            msgPara.textContent = "Account Does Not Exists, Pls Sign-Up"
            console.log("Account does not exist")
            generateCaptcha()
            return
        } else if (!res.data.passwordCorrect) {
            msgPara.textContent = "Password Incorrect"
            console.log("Password Incorrect")
            generateCaptcha()
            return
        } else {
            console.log(res.data)
            localStorage.setItem("token", res.data.token)
            msgPara.textContent = "Signed In Successfully"
            console.log("Signed In Successfully")
            verifyToken()
            setTimeout(() => {
                window.location.href = '/Home'
            }, 2000)
        }
        form.reset()
        generateCaptcha()
    } catch (err) {
        console.error("Error:", err)
        msgPara.textContent = "Something went wrong, try again"
        generateCaptcha()
    }
}

async function verifyToken() {
    const token = localStorage.getItem("token")
    const tokenObj = {
        token: token
    }

    try {
        const res = await axios.post("/Token_Verification", tokenObj)
        if (res.data.tokenVerified) {
            const id = res.data.id
            localStorage.setItem("currentUserId", id)
            console.log("Token Verified")
        } else {
            console.log("token expired pls login again")
        }
    } catch (err) {
        console.error("Error:", err)
    }
}

// ==========================================
// LEAF PHYSICS ANIMATION
// ==========================================
const canvas = document.getElementById('leaves-canvas')
const ctx = canvas.getContext('2d')

function resizeCanvas() {
    canvas.width = window.innerWidth
    canvas.height = window.innerHeight
}
window.addEventListener('resize', resizeCanvas)
resizeCanvas()

let mouse = { x: -1000, y: -1000 }
window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX
    mouse.y = e.clientY
})

const leafColors = ['#e35311', '#f3a000', '#ef720a', '#feb60b']

class Leaf {
    constructor() { this.reset(true) }

    reset(initial = false) {
        this.x = Math.random() * canvas.width
        this.y = initial ? Math.random() * canvas.height : -50
        this.size = Math.random() * 15 + 10
        this.color = leafColors[Math.floor(Math.random() * leafColors.length)]
        this.baseVy = Math.random() * 1.5 + 1.5
        this.vy = this.baseVy
        this.baseVx = (Math.random() - 0.5) * 1.5
        this.vx = this.baseVx
        this.angle = Math.random() * 360
        this.baseSpin = (Math.random() - 0.5) * 3
        this.spin = this.baseSpin
    }

    update() {
        this.y += this.vy
        this.x += this.vx
        this.angle += this.spin
        this.vx = this.vx * 0.985 + this.baseVx * 0.015
        this.vy = this.vy * 0.95 + this.baseVy * 0.05
        this.spin = this.spin * 0.98 + this.baseSpin * 0.02

        const dx = this.x - mouse.x
        const dy = this.y - mouse.y
        const distance = Math.sqrt(dx * dx + dy * dy)
        if (distance < 180) {
            const force = (180 - distance) / 180
            this.vx += (dx / distance) * force * 0.25
            this.vy -= force * 0.4
            this.spin += (dx / distance) * force * 2
        }

        if (this.y > canvas.height + 50) this.reset(false)
        if (this.x < -100) this.x = canvas.width + 50
        if (this.x > canvas.width + 100) this.x = -50
    }

    draw() {
        ctx.save()
        ctx.translate(this.x, this.y)
        ctx.rotate((this.angle * Math.PI) / 180)
        ctx.fillStyle = this.color
        ctx.beginPath()
        ctx.ellipse(0, 0, this.size, this.size / 2.5, 0, 0, Math.PI * 2)
        ctx.fill()
        ctx.restore()
    }
}

const leaves = []
for (let i = 0; i < 45; i++) leaves.push(new Leaf())

function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height)
    leaves.forEach(leaf => leaf.update())
    leaves.forEach(leaf => leaf.draw())
    requestAnimationFrame(animate)
}
animate()