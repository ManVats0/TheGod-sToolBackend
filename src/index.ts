import express from 'express'
import mongoose from 'mongoose'
import cors from 'cors'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import Razorpay from 'razorpay'
import crypto from 'crypto'
import User from './User'
import { OAuth2Client } from 'google-auth-library'

dotenv.config()

const app = express()
app.use(cors({ origin: '*' }))
app.use(express.json())

mongoose.connect(process.env.MONGODB_URI!)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err))

const JWT_SECRET = process.env.JWT_SECRET!

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID!,
  key_secret: process.env.RAZORPAY_KEY_SECRET!
})

const googleOAuthClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID!,
  process.env.GOOGLE_CLIENT_SECRET!,
  process.env.GOOGLE_REDIRECT_URI!
)

const PLAN_IDS: Record<string, { INR: { monthly: string; yearly: string }; USD: { monthly: string; yearly: string } }> = {
  lite: {
    INR: { monthly: process.env.RAZORPAY_PLAN_LITE_MONTHLY_INR!,       yearly: process.env.RAZORPAY_PLAN_LITE_YEARLY_INR! },
    USD: { monthly: process.env.RAZORPAY_PLAN_LITE_MONTHLY_USD!,   yearly: process.env.RAZORPAY_PLAN_LITE_YEARLY_USD! }
  },
  starter: {
    INR: { monthly: process.env.RAZORPAY_PLAN_STARTER_MONTHLY_INR!,    yearly: process.env.RAZORPAY_PLAN_STARTER_YEARLY_INR! },
    USD: { monthly: process.env.RAZORPAY_PLAN_STARTER_MONTHLY_USD!, yearly: process.env.RAZORPAY_PLAN_STARTER_YEARLY_USD! }
  },
  pro: {
    INR: { monthly: process.env.RAZORPAY_PLAN_PRO_MONTHLY_INR!,        yearly: process.env.RAZORPAY_PLAN_PRO_YEARLY_INR! },
    USD: { monthly: process.env.RAZORPAY_PLAN_PRO_MONTHLY_USD!,    yearly: process.env.RAZORPAY_PLAN_PRO_YEARLY_USD! }
  },
  team: {
    INR: { monthly: process.env.RAZORPAY_PLAN_TEAM_MONTHLY_INR!,       yearly: process.env.RAZORPAY_PLAN_TEAM_YEARLY_INR! },
    USD: { monthly: process.env.RAZORPAY_PLAN_TEAM_MONTHLY_USD!,   yearly: process.env.RAZORPAY_PLAN_TEAM_YEARLY_USD! }
  },
  enterprise: {
    INR: { monthly: process.env.RAZORPAY_PLAN_ENTERPRISE_MONTHLY_INR!, yearly: process.env.RAZORPAY_PLAN_ENTERPRISE_YEARLY_INR! },
    USD: { monthly: process.env.RAZORPAY_PLAN_ENTERPRISE_MONTHLY_USD!, yearly: process.env.RAZORPAY_PLAN_ENTERPRISE_YEARLY_USD! }
  }
}

// Max concurrent logged-in sessions allowed per plan ("User Limit" column)
const PLAN_SESSION_LIMITS: Record<string, number> = {
  none:       1,
  trial:      1,
  lite:       1,
  starter:    1,
  pro:        5,
  team:       15,
  enterprise: 100
}

// Daily AI transform limits per plan
const AI_LIMITS: Record<string, number> = {
  trial:      15,
  lite:       4,
  starter:    35,
  pro:        110,
  team:       150,
  enterprise: 500
}

// Issues a session + JWT, enforcing the plan's concurrent-login limit
async function issueSessionAndToken(user: any, device: string): Promise<{ token?: string; error?: string }> {
  const limit = PLAN_SESSION_LIMITS[user.plan] || 1
  const sessions = user.sessions || []
  if (sessions.length >= limit) {
    return { error: `Login limit reached for your plan (max ${limit} device${limit > 1 ? 's' : ''} signed in at once). Log out on another device or upgrade your plan.` }
  }
  const sessionId = crypto.randomUUID()
  await User.updateOne(
    { _id: user._id },
    { $push: { sessions: { sessionId, device, createdAt: new Date(), lastActive: new Date() } } }
  )
  const token = jwt.sign({ userId: user._id, email: user.email, sessionId }, JWT_SECRET, { expiresIn: '7d' })
  return { token }
}

// Evicts the session that's been inactive the longest, freeing one concurrent-login slot
async function evictOldestSession(userId: any): Promise<void> {
  const user = await User.findById(userId)
  if (!user || !user.sessions || user.sessions.length === 0) return
  const oldest = user.sessions.reduce((a: any, b: any) => (a.lastActive < b.lastActive ? a : b))
  await User.updateOne({ _id: userId }, { $pull: { sessions: { sessionId: oldest.sessionId } } })
}

// Helper: decode JWT from Authorization header
function getUserFromToken(req: express.Request): { userId: string; email: string; sessionId?: string } | null {
  const auth = req.headers.authorization
  if (!auth || !auth.startsWith('Bearer ')) return null
  try {
    return jwt.verify(auth.slice(7), JWT_SECRET) as { userId: string; email: string; sessionId?: string }
  } catch {
    return null
  }
}

app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' })

    const exists = await User.findOne({ email })
    if (exists)
      return res.status(400).json({ error: 'Email already registered' })

    const hashed = await bcrypt.hash(password, 10)
    const user = await User.create({ email, password: hashed })

    const { token, error } = await issueSessionAndToken(user, req.headers['user-agent'] || 'Unknown device')
    if (error) return res.status(429).json({ error })
    res.json({ token, email: user.email })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' })

    const user = await User.findOne({ email })
    if (!user || !user.password)
      return res.status(400).json({ error: 'Invalid credentials' })

    const match = await bcrypt.compare(password, user.password)
    if (!match)
      return res.status(400).json({ error: 'Invalid credentials' })

    if (req.body.forceLogout) {
      await evictOldestSession(user._id)
    }

    const { token, error } = await issueSessionAndToken(user, req.headers['user-agent'] || 'Unknown device')
    if (error) return res.status(429).json({ error })
    res.json({ token, email: user.email })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

app.post('/api/google', async (req, res) => {
  try {
    const { email, googleId, name, forceLogout } = req.body
    console.log('🟢 Google login received:', { email, googleId, name })
    if (!email || !googleId)
      return res.status(400).json({ error: 'Missing Google data' })

    const user = await User.findOneAndUpdate(
      { email },
      { $set: { googleId, name } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    )

    console.log('🟢 User saved/updated:', user)

    if (!user)
      return res.status(500).json({ error: 'Failed to create or update user' })

    if (forceLogout) {
      await evictOldestSession(user._id)
    }

    const { token, error } = await issueSessionAndToken(user, req.headers['user-agent'] || 'Unknown device')
    if (error) return res.status(429).json({ error })
    res.json({ token, email: user.email })
  } catch (err) {
    console.error('🔴 Google route error:', err)
    res.status(500).json({ error: 'Server error' })
  }
})

// ── Google OAuth Redirect Fallback (used when popup/FedCM fails) ───────────
app.get('/api/google/callback', async (req, res) => {
  try {
    const { code } = req.query
    if (!code || typeof code !== 'string') {
      return res.redirect(`${process.env.FRONTEND_URL}/?googleError=missing_code`)
    }

    const { tokens } = await googleOAuthClient.getToken(code)
    const idToken = tokens.id_token
    if (!idToken) {
      return res.redirect(`${process.env.FRONTEND_URL}/?googleError=no_id_token`)
    }

    const ticket = await googleOAuthClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID!
    })
    const payload = ticket.getPayload()
    if (!payload?.email || !payload?.sub) {
      return res.redirect(`${process.env.FRONTEND_URL}/?googleError=invalid_payload`)
    }

    const user = await User.findOneAndUpdate(
      { email: payload.email },
      { $set: { googleId: payload.sub, name: payload.name } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    )

    const { token, error } = await issueSessionAndToken(user, (req.headers['user-agent'] as string) || 'Unknown device')
    if (error) {
      return res.redirect(`${process.env.FRONTEND_URL}/?googleError=${encodeURIComponent(error)}`)
    }

    res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}&email=${encodeURIComponent(user.email)}`)
  } catch (err) {
    console.error('🔴 Google OAuth callback error:', err)
    res.redirect(`${process.env.FRONTEND_URL}/?googleError=server_error`)
  }
})

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body
    if (!email) return res.status(400).json({ error: 'Email required' })

    const user = await User.findOne({ email })
    if (!user) return res.status(400).json({ error: 'No account found with that email' })

    const resetToken = require('crypto').randomBytes(32).toString('hex')
    const resetTokenExpiry = new Date(Date.now() + 1000 * 60 * 60) // 1 hour

    await User.updateOne({ email }, { $set: { resetToken, resetTokenExpiry } })

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`

    const { Resend } = require('resend')
    const resend = new Resend(process.env.RESEND_API_KEY)

    await resend.emails.send({
      from: "The Gods Tool <noreply@thegodstool.com>",
      to: email,
      subject: 'Password Reset Link',
      html: `
        <div style="font-family:Georgia,serif;background:#05080f;color:#e2e8f0;padding:32px;border-radius:8px;">
          <h2 style="color:#a78bfa;">The God's Tool</h2>
          <p>Click the link below to reset your password. This link expires in 1 hour.</p>
          <a href="${resetLink}" style="display:inline-block;margin-top:16px;padding:12px 28px;background:linear-gradient(135deg,#7c3aed,#4f46e5);color:white;border-radius:6px;text-decoration:none;font-weight:700;">Reset Password</a>
          <p style="margin-top:24px;color:#475569;font-size:0.8rem;">If you didn't request this, ignore this email.</p>
        </div>
      `
    })

    res.json({ message: 'Reset link sent' })
  } catch (err) {
    console.error('🔴 Forgot password error:', err)
    res.status(500).json({ error: 'Failed to send reset email' })
  }
})

app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body
    if (!token || !password) return res.status(400).json({ error: 'Token and password required' })

    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: new Date() }
    })

    if (!user) return res.status(400).json({ error: 'Invalid or expired reset link' })

    const hashed = await bcrypt.hash(password, 10)
    await User.updateOne(
      { _id: user._id },
      { $set: { password: hashed }, $unset: { resetToken: '', resetTokenExpiry: '' } }
    )

    res.json({ message: 'Password reset successful' })
  } catch (err) {
    console.error('🔴 Reset password error:', err)
    res.status(500).json({ error: 'Server error' })
  }
})

app.get('/api/health', (_, res) => res.json({ status: 'ok' }))

// ── Logout: frees up one concurrent-login slot ──────────────────────────────
app.post('/api/logout', async (req, res) => {
  const decoded = getUserFromToken(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  await User.updateOne(
    { _id: decoded.userId },
    { $pull: { sessions: { sessionId: decoded.sessionId } } }
  )
  res.json({ success: true })
})

app.post('/api/save-alert-email', async (req, res) => {
  try {
    const { email } = req.body
    if (!email) return res.status(400).json({ error: 'Email required' })

    const { Resend } = require('resend')
    const resend = new Resend(process.env.RESEND_API_KEY)

    await resend.emails.send({
      from: "The Gods Tool <noreply@thegodstool.com>",
      to: email,
      subject: 'Data Alerts Activated — The God\'s Tool',
      html: `
        <div style="font-family:Georgia,serif;background:#05080f;color:#e2e8f0;padding:32px;border-radius:8px;">
          <h2 style="color:#a78bfa;">The God's Tool</h2>
          <p>✅ Your email has been registered for data quality alerts.</p>
          <p style="margin-top:12px;">You'll receive a notification here whenever your uploaded CSV triggers:</p>
          <ul style="color:#94a3b8;margin-top:8px;line-height:1.8;">
            <li>⚠️ Data Staleness</li>
            <li>🔁 Schema Drift</li>
            <li>📊 Anomalies / Imbalance</li>
            <li>❌ Flow Failures</li>
          </ul>
          <p style="margin-top:24px;color:#475569;font-size:0.8rem;">If you didn't set this up, ignore this email.</p>
        </div>
      `
    })

    res.json({ success: true })
  } catch (err) {
    console.error('🔴 Save alert email error:', err)
    res.status(500).json({ error: 'Failed to send confirmation email' })
  }
})

// ── Plan info ───────────────────────────────────────────────────────────────
app.get('/api/plan', async (req, res) => {
  const decoded = getUserFromToken(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const user = await User.findById(decoded.userId)
  if (!user) return res.status(404).json({ error: 'User not found' })

  // Downgrade expired trials to 'none' before responding.
  // Only touches users on 'trial' — never affects paid plans or existing 'none' users.
  if (user.plan === 'trial' && user.planExpiresAt && user.planExpiresAt < new Date()) {
    user.plan = 'none'
    user.planExpiresAt = null
    await user.save()
  }

  res.json({
    plan: user.plan,
    planExpiresAt: user.planExpiresAt,
    aiUsageToday: user.aiUsageToday,
    aiUsageDate: user.aiUsageDate,
    name: user.name || null
  })
})

// ── Create Razorpay subscription ────────────────────────────────────────────
app.post('/api/subscribe', async (req, res) => {
  const decoded = getUserFromToken(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const { planKey, billingCycle, currency } = req.body
  if (!PLAN_IDS[planKey]) return res.status(400).json({ error: 'Invalid plan' })
  if (billingCycle !== 'monthly' && billingCycle !== 'yearly') return res.status(400).json({ error: 'Invalid billing cycle' })
  const selectedCurrency = currency === 'USD' ? 'USD' : 'INR'
  const razorpayPlanId = PLAN_IDS[planKey][selectedCurrency][billingCycle]
  if (!razorpayPlanId) return res.status(400).json({ error: 'Plan not available for this currency' })
  try {
    const subscription = await razorpay.subscriptions.create({
      plan_id: razorpayPlanId,
      customer_notify: 1,
      quantity: 1,
      total_count: billingCycle === 'yearly' ? 1 : 12
    })
    res.json({ subscriptionId: subscription.id, key: process.env.RAZORPAY_KEY_ID })
  } catch (err: any) {
    console.error('🔴 Razorpay subscribe error:', err)
    res.status(500).json({ error: 'Could not create subscription' })
  }
})

// ── Verify payment & activate plan ─────────────────────────────────────────
app.post('/api/verify-payment', async (req, res) => {
  const decoded = getUserFromToken(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const { razorpay_payment_id, razorpay_subscription_id, razorpay_signature, planKey, billingCycle } = req.body
  const body = razorpay_payment_id + '|' + razorpay_subscription_id
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET!)
    .update(body)
    .digest('hex')
  if (expectedSignature !== razorpay_signature) {
    return res.status(400).json({ error: 'Payment verification failed' })
  }
  // Calculate expiry
  const now = new Date()
  const expiresAt: Date = billingCycle === 'yearly'
    ? new Date(now.setFullYear(now.getFullYear() + 1))
    : new Date(now.setMonth(now.getMonth() + 1))
  await User.updateOne(
    { _id: decoded.userId },
    { $set: { plan: planKey, planExpiresAt: expiresAt, razorpaySubscriptionId: razorpay_subscription_id } }
  )
  res.json({ success: true, plan: planKey })
})

// ── Create a one-time custom-amount payment order (NOT a subscription) ─────
// User enters any amount; this creates a Razorpay Order for that exact
// amount. No plan/backend activation happens here or in the verify route
// below — this exists purely to confirm the money reaches your bank account.
app.post('/api/create-custom-order', async (req, res) => {
  const decoded = getUserFromToken(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const { amount, currency } = req.body
  const amountNum = Number(amount)
  if (!amountNum || amountNum <= 0) {
    return res.status(400).json({ error: 'Enter a valid amount greater than 0' })
  }
  const selectedCurrency = currency === 'USD' ? 'USD' : 'INR'
  try {
    const order = await razorpay.orders.create({
      amount: Math.round(amountNum * 100), // Razorpay wants the smallest unit (paise/cents)
      currency: selectedCurrency,
      receipt: `custom_${Date.now()}`,
      payment_capture: true, // auto-capture so funds actually settle, not just authorize
      notes: { userId: decoded.userId, type: 'custom_payment' }
    })
    res.json({ orderId: order.id, amount: order.amount, currency: order.currency, key: process.env.RAZORPAY_KEY_ID })
  } catch (err: any) {
    console.error('🔴 Razorpay create-custom-order error:', err)
    res.status(500).json({ error: 'Could not create payment order' })
  }
})

// ── Verify the one-time custom payment ──────────────────────────────────────
// Order signature formula differs from the Subscription one above:
// HMAC_SHA256(order_id + "|" + payment_id, key_secret). No DB/plan changes —
// this route only confirms the payment is genuine.
app.post('/api/verify-custom-payment', async (req, res) => {
  const decoded = getUserFromToken(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ error: 'Missing payment fields' })
  }
  const body = razorpay_order_id + '|' + razorpay_payment_id
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET!)
    .update(body)
    .digest('hex')
  if (expectedSignature !== razorpay_signature) {
    return res.status(400).json({ success: false, error: 'Payment verification failed' })
  }
  res.json({ success: true })
})

// ── AI usage gate ───────────────────────────────────────────────────────────
app.post('/api/ai-usage', async (req, res) => {
  const decoded = getUserFromToken(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const user = await User.findById(decoded.userId)
  if (!user) return res.status(404).json({ error: 'User not found' })

  const today = new Date().toISOString().slice(0, 10)

  const limit = AI_LIMITS[user.plan]
  if (!limit) {
    return res.status(403).json({ error: 'no_plan', message: 'Upgrade to use AI features' })
  }

  const usageDate = user.aiUsageDate
  const usageCount = usageDate === today ? (user.aiUsageToday || 0) : 0

  if (usageCount >= limit) {
    return res.status(429).json({ error: 'limit_reached', message: `Daily AI limit reached (${limit}/day). Upgrade your plan for more.` })
  }

  await User.updateOne(
    { _id: decoded.userId },
    { $set: { aiUsageDate: today, aiUsageToday: usageCount + 1 } }
  )
  return res.json({ allowed: true, usageToday: usageCount + 1, limit })
})

// ── Razorpay webhook (optional but recommended) ─────────────────────────────
app.post('/api/webhook/razorpay', express.raw({ type: 'application/json' }), (req, res) => {
  const secret = process.env.RAZORPAY_KEY_SECRET!
  const signature = req.headers['x-razorpay-signature'] as string
  const body = req.body
  const digest = crypto.createHmac('sha256', secret).update(body).digest('hex')
  if (digest !== signature) return res.status(400).json({ error: 'Invalid signature' })
  // You can handle subscription cancellation/renewal here later
  res.json({ received: true })
})

const PORT = process.env.PORT || 4000
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`))
