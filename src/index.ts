import express from 'express'
import mongoose from 'mongoose'
import cors from 'cors'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import Razorpay from 'razorpay'
import crypto from 'crypto'
import User from './User'

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

const PLAN_IDS: Record<string, string> = {
  solo:        process.env.RAZORPAY_PLAN_SOLO!,
  starter:     process.env.RAZORPAY_PLAN_STARTER!,
  pro_monthly: process.env.RAZORPAY_PLAN_PRO_MONTHLY!,
  pro_yearly:  process.env.RAZORPAY_PLAN_PRO_YEARLY!
}

// Helper: decode JWT from Authorization header
function getUserFromToken(req: express.Request): { userId: string; email: string } | null {
  const auth = req.headers.authorization
  if (!auth || !auth.startsWith('Bearer ')) return null
  try {
    return jwt.verify(auth.slice(7), JWT_SECRET) as { userId: string; email: string }
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

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' })
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

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' })
    res.json({ token, email: user.email })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

app.post('/api/google', async (req, res) => {
  try {
    const { email, googleId, name } = req.body
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

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' })
    res.json({ token, email: user.email })
  } catch (err) {
    console.error('🔴 Google route error:', err)
    res.status(500).json({ error: 'Server error' })
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

    const resetLink = `http://localhost:5173/reset-password?token=${resetToken}`

    const nodemailer = require('nodemailer')
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    })

    await transporter.sendMail({
      from: `"The God's Tool" <${process.env.EMAIL_USER}>`,
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

// ── Plan info ───────────────────────────────────────────────────────────────
app.get('/api/plan', async (req, res) => {
  const decoded = getUserFromToken(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const user = await User.findById(decoded.userId)
  if (!user) return res.status(404).json({ error: 'User not found' })
  res.json({
    plan: user.plan,
    planExpiresAt: user.planExpiresAt,
    aiUsageToday: user.aiUsageToday,
    aiUsageDate: user.aiUsageDate
  })
})

// ── Create Razorpay subscription ────────────────────────────────────────────
app.post('/api/subscribe', async (req, res) => {
  const decoded = getUserFromToken(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const { planKey } = req.body
  if (!PLAN_IDS[planKey]) return res.status(400).json({ error: 'Invalid plan' })
  try {
    const subscription = await razorpay.subscriptions.create({
      plan_id: PLAN_IDS[planKey],
      customer_notify: 1,
      quantity: 1,
      total_count: planKey.includes('yearly') ? 1 : 12
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
  const { razorpay_payment_id, razorpay_subscription_id, razorpay_signature, planKey } = req.body
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
  let expiresAt: Date
  if (planKey === 'solo') {
    expiresAt = new Date(now.setMonth(now.getMonth() + 1))
  } else if (planKey === 'starter') {
    expiresAt = new Date(now.setFullYear(now.getFullYear() + 1))
  } else if (planKey === 'pro_monthly') {
    expiresAt = new Date(now.setMonth(now.getMonth() + 1))
  } else {
    expiresAt = new Date(now.setFullYear(now.getFullYear() + 1))
  }
  await User.updateOne(
    { _id: decoded.userId },
    { $set: { plan: planKey, planExpiresAt: expiresAt, razorpaySubscriptionId: razorpay_subscription_id } }
  )
  res.json({ success: true, plan: planKey })
})

// ── AI usage gate ───────────────────────────────────────────────────────────
app.post('/api/ai-usage', async (req, res) => {
  const decoded = getUserFromToken(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const user = await User.findById(decoded.userId)
  if (!user) return res.status(404).json({ error: 'User not found' })

  const today = new Date().toISOString().slice(0, 10)

  if (user.plan === 'none') {
    return res.status(403).json({ error: 'no_plan', message: 'Upgrade to use AI features' })
  }
  if (user.plan === 'solo') {
    return res.status(403).json({ error: 'no_plan', message: 'AI not included in Solo plan. Upgrade to Starter or Pro.' })
  }
  if (user.plan === 'starter') {
    const usageDate = user.aiUsageDate
    const usageCount = usageDate === today ? (user.aiUsageToday || 0) : 0
    if (usageCount >= 50) {
      return res.status(429).json({ error: 'limit_reached', message: 'Daily AI limit reached (50/day). Upgrade to Pro for unlimited.' })
    }
    await User.updateOne(
      { _id: decoded.userId },
      { $set: { aiUsageDate: today, aiUsageToday: usageCount + 1 } }
    )
    return res.json({ allowed: true, usageToday: usageCount + 1, limit: 50 })
  }
  // pro_monthly or pro_yearly — unlimited
  return res.json({ allowed: true, usageToday: null, limit: null })
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