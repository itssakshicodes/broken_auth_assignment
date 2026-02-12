require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { v4: uuid } = require("uuid");

const app = express();
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";
const OTP_EXPIRY_MS = 5 * 60 * 1000; // 5 min

/**
 * In-memory store:
 * { sessionId: { otp, expiresAt, verified } }
 */
const sessions = {};

/**
 * Generate 6-digit OTP
 */
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

/**
 * /auth/login
 * → returns JSON with loginSessionId
 * → logs OTP to console (no SMS)
 */
app.post("/auth/login", (req, res) => {
  const sessionId = uuid();
  const otp = generateOTP();
  const expiresAt = Date.now() + OTP_EXPIRY_MS;

  sessions[sessionId] = { otp, expiresAt, verified: false };

  console.log(`OTP for session ${sessionId} → ${otp}`);

  res.json({ loginSessionId: sessionId });
});

/**
 * /auth/verify-otp
 * → verify OTP and set cookie
 */
app.post("/auth/verify-otp", (req, res) => {
  const { loginSessionId, otp } = req.body;
  if (!loginSessionId || !otp) {
    return res.status(400).json({ error: "Missing session or OTP" });
  }

  const session = sessions[loginSessionId];
  if (!session) {
    return res.status(404).json({ error: "Invalid session" });
  }
  if (session.expiresAt < Date.now()) {
    return res.status(400).json({ error: "OTP expired" });
  }
  if (session.verified) {
    return res.status(400).json({ error: "OTP already used" });
  }
  if (session.otp !== otp.toString()) {
    return res.status(401).json({ error: "Invalid OTP" });
  }

  session.verified = true;

  // Set session cookie
  res.cookie("session_token", loginSessionId, {
    httpOnly: true,
    sameSite: "strict"
  });

  res.json({ message: "OTP verified" });
});

/**
 * /auth/token
 * → if verified session cookie exists, return JWT
 */
app.post("/auth/token", (req, res) => {
  const sessionId = req.cookies.session_token;
  if (!sessionId) {
    return res.status(401).json({ error: "Missing session cookie" });
  }

  const session = sessions[sessionId];
  if (!session || !session.verified) {
    return res.status(401).json({ error: "Invalid session" });
  }

  const token = jwt.sign({ sessionId }, JWT_SECRET, { expiresIn: "15m" });

  res.json({ token });
});

/**
 * JWT-protected middleware
 */
function requireJwt(req, res, next) {
  const auth = req.headers["authorization"];
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing bearer token" });
  }

  const token = auth.split(" ")[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

/**
 * /protected
 */
app.get("/protected", requireJwt, (req, res) => {
  res.json({ secret: "🎉 You’re inside the protected route!" });
});

app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`)
);
