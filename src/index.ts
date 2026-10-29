import express from 'express'
import mongoose from 'mongoose'
import cors from 'cors'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import Razorpay from 'razorpay'
import crypto from 'crypto'
import User from './User'
// import Organization from './Organization' // NEW
import { OAuth2Client } from 'google-auth-library'
import rateLimit from 'express-rate-limit'
import { Payment, CreditLedger } from './Payment'
import { creditsForAmount, creditRates, creditLimits, recordPayment, logCredit, sendReceiptEmail, publicPayment, money } from './billing'

dotenv.config()

const app = express()
app.set('trust proxy', 1) // Railway sits behind a proxy; needed for correct client IPs
app.use(cors({ origin: '*' }))

// ── Razorpay webhook ────────────────────────────────────────────────────────
// Must be registered BEFORE express.json(): signature verification needs the raw body.
// Uses its own secret (Razorpay Dashboard → Webhooks → secret), NOT the API key secret.
app.post('/api/webhook/razorpay', express.raw({ type: 'application/json' }), async (req, res) => {
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET
  if (!secret) return res.status(503).json({ error: 'Webhook not configured' })
  const signature = String(req.headers['x-razorpay-signature'] || '')
  const digest = crypto.createHmac('sha256', secret).update(req.body).digest('hex')
  const a = Buffer.from(digest)
  const b = Buffer.from(signature)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(400).json({ error: 'Invalid signature' })
  }
  let event: any
  try { event = JSON.parse(Buffer.from(req.body).toString('utf8')) } catch { return res.status(400).json({ error: 'Bad payload' }) }
  try {
    await handleRazorpayEvent(event)
  } catch (err) {
    console.error('Webhook processing failed:', err)
    return res.status(500).json({ error: 'Webhook processing failed' }) // Razorpay retries on non-2xx
  }
  res.json({ received: true })
})

app.use(express.json())

// Brute-force protection. Only FAILED attempts (status >= 400) count, so normal users are never
// blocked even if many of them share one IP address behind a proxy.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again in a few minutes.' }
})
app.use(['/api/login', '/api/register', '/api/reset-password', '/api/google'], authLimiter)

// Limits reset emails per address (stops email-bombing someone). Always "succeeds", so it counts all requests.
const forgotLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  keyGenerator: (req) => {
    const e = (req.body as any)?.email
    return typeof e === 'string' && e ? 'email:' + e.toLowerCase().slice(0, 254) : 'ip:' + req.ip
  },
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many reset requests. Please try again later.' }
})
app.use('/api/forgot-password', forgotLimiter)

mongoose.connect(process.env.MONGODB_URI!)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err))

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

// Credit pricing (rupees / dollars per credit, min and max top-up) lives in billing.ts.

const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

function isAdminEmail(email?: string | null): boolean {
  const list = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean)
  return !!email && list.includes(email.toLowerCase())
}

// Reads the teams that main.py owns (org_members / organizations).
async function getOrgContext(userId: string): Promise<{ ownerId: string; isMember: boolean; orgUserIds: string[] }> {
  const self = String(userId)
  const fallback = { ownerId: self, isMember: false, orgUserIds: [self] }
  const db = mongoose.connection.db
  if (!db) return fallback
  // A person can belong to several workspaces (their own + invited teams). main.py stores which one
  // they are working in (org_prefs); without a stored choice we use their own personal workspace.
  let membership: any = null
  const pref = await db.collection('org_prefs').findOne({ userId: self })
  if (pref?.activeOrgId) {
    membership = await db.collection('org_members').findOne({ userId: self, orgId: pref.activeOrgId, status: 'active' })
  }
  if (!membership) {
    const all = await db.collection('org_members').find({ userId: self, status: 'active' }).toArray()
    if (all.length === 1) {
      membership = all[0]
    } else if (all.length > 1) {
      const orgs = await db.collection('organizations').find({ _id: { $in: all.map((m: any) => m.orgId) } }).toArray()
      const personal = new Set(
        orgs.filter((o: any) => String(o.slug || '').startsWith('personal-') && String(o.ownerId) === self).map((o: any) => String(o._id))
      )
      membership = all.find((m: any) => personal.has(String(m.orgId))) || all[0]
    }
  }
  if (!membership) return fallback
  const org = await db.collection('organizations').findOne({ _id: membership.orgId })
  const ownerId = String(org?.ownerId || self)
  const rows = await db.collection('org_members').find({ orgId: membership.orgId, status: 'active' }).toArray()
  const ids = new Set<string>([ownerId, self])
  rows.forEach((r: any) => ids.add(String(r.userId)))
  return { ownerId, isMember: membership.roleKey !== 'owner', orgUserIds: Array.from(ids) }
}

// Issues a session + JWT. The login limit is org-wide and uses the OWNER's plan.
async function issueSessionAndToken(user: any, device: string): Promise<{ token?: string; error?: string }> {
  const orgCtx = await getOrgContext(String(user._id))

  // Purge expired (>7 days) sessions across the whole org first.
  await User.updateMany(
    { _id: { $in: orgCtx.orgUserIds } },
    { $pull: { sessions: { createdAt: { $lt: new Date(Date.now() - SESSION_MAX_AGE_MS) } } } } as any
  )

  if (!isAdminEmail(user.email)) {
    const ownerDoc = orgCtx.isMember ? await User.findById(orgCtx.ownerId) : user
    const limit = PLAN_SESSION_LIMITS[(ownerDoc || user).plan] || 1
    const orgUsers = await User.find({ _id: { $in: orgCtx.orgUserIds } }, { sessions: 1 })
    const active = orgUsers.reduce((n: number, u: any) => n + (u.sessions?.length || 0), 0)
    if (active >= limit) {
      return { error: `Login limit reached for your plan (max ${limit} device${limit > 1 ? 's' : ''} signed in at once across your team). Log out on another device or upgrade your plan.` }
    }
  }

  const sessionId = crypto.randomUUID()
  await User.updateOne(
    { _id: user._id },
    { $push: { sessions: { sessionId, device, createdAt: new Date(), lastActive: new Date() } } }
  )
  const token = jwt.sign({ userId: user._id, email: user.email, sessionId }, JWT_SECRET, { expiresIn: '7d' })
  return { token }
}

// Evicts the oldest session across the whole org, freeing one login slot
async function evictOldestSession(userId: any): Promise<void> {
  const orgCtx = await getOrgContext(String(userId))
  const users = await User.find({ _id: { $in: orgCtx.orgUserIds } }, { sessions: 1 })
  let oldest: any = null
  let oldestOwnerId: any = null
  for (const u of users) {
    for (const s of (u.sessions || []) as any[]) {
      if (!oldest || s.lastActive < oldest.lastActive) {
        oldest = s
        oldestOwnerId = u._id
      }
    }
  }
  if (!oldest) return
  await User.updateOne({ _id: oldestOwnerId }, { $pull: { sessions: { sessionId: oldest.sessionId } } })
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

// One row per credited payment — prevents the same payment being credited twice (replay).
const ProcessedPayment = mongoose.model('ProcessedPayment', new mongoose.Schema({
  paymentId: { type: String, required: true, unique: true },
  userId: { type: String },
  createdAt: { type: Date, default: Date.now }
}))

// Like getUserFromToken, but also requires the session to still exist.
// This makes logout / "log out other device" actually invalidate the token.
// Tokens without a sessionId (very old ones) are still accepted.
async function authenticate(req: express.Request): Promise<{ userId: string; email: string; sessionId?: string } | null> {
  const decoded = getUserFromToken(req)
  if (!decoded) return null
  if (decoded.sessionId) {
    const alive = await User.exists({ _id: decoded.userId, 'sessions.sessionId': decoded.sessionId })
    if (!alive) return null
  }
  return decoded
}

const hashToken = (t: string) => crypto.createHash('sha256').update(t).digest('hex')
const isEmail = (e: any) => typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)

// ── NEW: Ensure a user has an organization, creating one if this is their ──
// first time. Called right after a user is created/found in register,
// login-via-Google, and the OAuth callback route. Existing users who
// predate this feature get an org lazily the next time they hit /api/org.
async function ensureOrganization(_user: any): Promise<void> {
  // Teams are owned by the FastAPI service (main.py). Intentionally empty.
}

app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' })
    if (!isEmail(email) || typeof password !== 'string')
      return res.status(400).json({ error: 'Enter a valid email address' })
    if (password.length < 8 || password.length > 128)
      return res.status(400).json({ error: 'Password must be 8–128 characters' })

    const exists = await User.findOne({ email })
    if (exists)
      return res.status(400).json({ error: 'Email already registered' })

    const hashed = await bcrypt.hash(password, 10)
    const user = await User.create({ email, password: hashed })
    await ensureOrganization(user) // NEW

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
    if (typeof email !== 'string' || typeof password !== 'string')
      return res.status(400).json({ error: 'Invalid credentials' })

    const user = await User.findOne({ email })
    if (!user || !user.password)
      return res.status(400).json({ error: 'Invalid credentials' })

    const match = await bcrypt.compare(password, user.password)
    if (!match)
      return res.status(400).json({ error: 'Invalid credentials' })

    if (req.body.forceLogout) {
      await evictOldestSession(user._id)
    }

    await ensureOrganization(user) // NEW — backfills orgs for pre-existing users

    const { token, error } = await issueSessionAndToken(user, req.headers['user-agent'] || 'Unknown device')
    if (error) return res.status(429).json({ error })
    res.json({ token, email: user.email })
  } catch (err) {
    res.status(500).json({ error: 'Server error' })
  }
})

app.post('/api/google', async (req, res) => {
  try {
    const { credential, forceLogout } = req.body
    if (!credential || typeof credential !== 'string')
      return res.status(400).json({ error: 'Missing Google credential' })

    let payload
    try {
      const ticket = await googleOAuthClient.verifyIdToken({
        idToken: credential,
        audience: process.env.GOOGLE_CLIENT_ID!
      })
      payload = ticket.getPayload()
    } catch {
      return res.status(401).json({ error: 'Invalid Google credential' })
    }
    if (!payload?.email || !payload?.sub)
      return res.status(400).json({ error: 'Missing Google data' })
    if (!payload.email_verified)
      return res.status(400).json({ error: 'Your Google email is not verified' })

    const user = await User.findOneAndUpdate(
      { email: payload.email },
      { $set: { googleId: payload.sub, name: payload.name } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    )

    if (!user)
      return res.status(500).json({ error: 'Failed to create or update user' })

    if (forceLogout) {
      await evictOldestSession(user._id)
    }

    await ensureOrganization(user) // NEW

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
    if (!payload?.email || !payload?.sub || !payload.email_verified) {
      return res.redirect(`${process.env.FRONTEND_URL}/?googleError=invalid_payload`)
    }

    const user = await User.findOneAndUpdate(
      { email: payload.email },
      { $set: { googleId: payload.sub, name: payload.name } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    )

    await ensureOrganization(user) // NEW

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
    if (!email || typeof email !== 'string') return res.status(400).json({ error: 'Email required' })

    const user = await User.findOne({ email })
    // Same response whether or not the account exists (prevents email enumeration)
    if (!user) return res.json({ message: 'Reset link sent' })

    const resetToken = crypto.randomBytes(32).toString('hex')
    const resetTokenExpiry = new Date(Date.now() + 1000 * 60 * 60) // 1 hour

    // Only a hash is stored; the raw token only exists in the emailed link
    await User.updateOne({ email }, { $set: { resetToken: hashToken(resetToken), resetTokenExpiry } })

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
    if (typeof token !== 'string' || typeof password !== 'string')
      return res.status(400).json({ error: 'Invalid request' })
    if (password.length < 8 || password.length > 128)
      return res.status(400).json({ error: 'Password must be 8–128 characters' })

    const user = await User.findOne({
      resetToken: hashToken(token),
      resetTokenExpiry: { $gt: new Date() }
    })

    if (!user) return res.status(400).json({ error: 'Invalid or expired reset link' })

    const hashed = await bcrypt.hash(password, 10)
    await User.updateOne(
      { _id: user._id },
      { $set: { password: hashed, sessions: [] }, $unset: { resetToken: '', resetTokenExpiry: '' } }
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
  const decoded = await authenticate(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const caller = await User.findById(decoded.userId)
  if (!caller) return res.status(404).json({ error: 'User not found' })
  const orgCtx = await getOrgContext(decoded.userId)
  const user = (orgCtx.isMember ? await User.findById(orgCtx.ownerId) : caller) || caller

  // Downgrade expired trials to 'none' before responding.
  // Only touches users on 'trial' — never affects paid plans or existing 'none' users.
  if (user.plan === 'trial' && user.planExpiresAt && user.planExpiresAt < new Date()) {
    user.plan = 'none'
    user.planExpiresAt = null
    await user.save()
  }

  // Optional: end a paid plan once its paid period (+3 days grace) is over. OFF by default, because plans
  // activated before renewals were recorded carry stale expiry dates. Switch on with ENFORCE_PLAN_EXPIRY=1
  // after the webhook has been live for a full billing cycle.
  if (process.env.ENFORCE_PLAN_EXPIRY === '1' && user.plan !== 'none' && user.plan !== 'trial' &&
      user.planExpiresAt && user.planExpiresAt.getTime() + 3 * 24 * 60 * 60 * 1000 < Date.now()) {
    user.plan = 'none'
    user.planExpiresAt = null
    await user.save()
  }

  // One-time: before credits could be spent, dollar top-ups only raised a money balance and gave no credits.
  // Convert those balances to credits so past USD payers get what they paid for.
  if ((user.customCreditsUSD || 0) > 0 && !user.usdCreditsMigrated) {
    const add = creditsForAmount(user.customCreditsUSD || 0, 'USD')
    const migrated: any = await User.findOneAndUpdate(
      { _id: user._id, usdCreditsMigrated: { $ne: true } },
      { $inc: { credits: add }, $set: { usdCreditsMigrated: true } },
      { new: true }
    )
    if (migrated) {
      user.credits = migrated.credits
      await logCredit(String(user._id), add, 'usd_migration', migrated.credits || 0, null)
    }
  }

  res.json({
    plan: isAdminEmail(caller.email) ? 'enterprise' : user.plan,
    planExpiresAt: user.planExpiresAt,
    aiUsageToday: user.aiUsageToday,
    aiUsageDate: user.aiUsageDate,
    name: caller.name || null,
    credits: user.credits || 0,
    customCreditsINR: user.customCreditsINR || 0,
    customCreditsUSD: user.customCreditsUSD || 0,
    creditRates: creditRates()
  })
})

// ── Dashboard summary: plan, credits, AI use and sign-ins for the landing page (read-only) ───
app.get('/api/dashboard-summary', async (req, res) => {
  const decoded = await authenticate(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const caller: any = await User.findById(decoded.userId)
  if (!caller) return res.status(404).json({ error: 'User not found' })
  const orgCtx = await getOrgContext(decoded.userId)
  const owner: any = (orgCtx.isMember ? await User.findById(orgCtx.ownerId) : caller) || caller
  const admin = isAdminEmail(caller.email)

  const trialOver = owner.plan === 'trial' && !!owner.planExpiresAt && owner.planExpiresAt < new Date()
  const plan = admin ? 'enterprise' : (trialOver ? 'none' : owner.plan)

  // Sign-ins: counted across the whole workspace, exactly like the login limit itself.
  const cutoff = Date.now() - SESSION_MAX_AGE_MS
  const orgUsers: any[] = await User.find({ _id: { $in: orgCtx.orgUserIds } }, { sessions: 1 })
  const live = (u: any) => (u.sessions || []).filter((s: any) => new Date(s.createdAt).getTime() >= cutoff)
  const activeLogins = orgUsers.reduce((n, u) => n + live(u).length, 0)
  const myDevices = live(caller).map((s: any) => ({ device: s.device || 'Unknown device', lastActive: s.lastActive || s.createdAt }))

  const today = new Date().toISOString().slice(0, 10)
  const aiLimit = AI_LIMITS[plan] || 0
  const aiUsed = owner.aiUsageDate === today ? (owner.aiUsageToday || 0) : 0

  const ledger = await CreditLedger.find({ userId: String(owner._id) }).sort({ createdAt: -1 }).limit(6).lean()
  const daysLeft = owner.planExpiresAt ? Math.max(0, Math.ceil((new Date(owner.planExpiresAt).getTime() - Date.now()) / 86400000)) : null

  res.json({
    name: caller.name || null,
    plan,
    isTrial: plan === 'trial',
    planExpiresAt: admin ? null : owner.planExpiresAt || null,
    daysLeft: admin || plan === 'none' ? null : daysLeft,
    isWorkspaceOwner: !orgCtx.isMember,
    ai: { usedToday: aiUsed, limit: aiLimit },
    credits: owner.credits || 0,
    recentCredits: ledger.map((l: any) => ({ delta: l.delta, reason: l.reason, balanceAfter: l.balanceAfter, at: l.createdAt })),
    logins: { active: activeLogins, limit: PLAN_SESSION_LIMITS[plan] || 1, mine: myDevices }
  })
})

// ── Payment processing shared by the browser callback AND the Razorpay webhook ──────────────
// Either one may arrive first (or only one, if the customer closes the tab right after paying), so every step
// here is idempotent: a payment is credited / activated once and gets exactly one receipt.

function planFromRazorpayPlanId(planId: string): { planKey: string; billingCycle: 'monthly' | 'yearly' } | null {
  for (const [key, byCurrency] of Object.entries(PLAN_IDS)) {
    for (const cur of ['INR', 'USD']) {
      for (const cyc of ['monthly', 'yearly'] as const) {
        const id = (byCurrency as any)[cur]?.[cyc]
        if (id && id === planId) return { planKey: key, billingCycle: cyc }
      }
    }
  }
  return null
}

async function applyCustomPayment(userId: string, order: any, paymentId: string) {
  const chargedAmount = Number(order.amount) / 100
  const chargedCurrency: 'INR' | 'USD' = order.currency === 'USD' ? 'USD' : 'INR'
  const balanceField = chargedCurrency === 'USD' ? 'customCreditsUSD' : 'customCreditsINR'
  // Credits are always worked out from what Razorpay says was charged, never from the browser.
  const creditsToAdd = creditsForAmount(chargedAmount, chargedCurrency)

  // Replay protection: each payment can be credited exactly once.
  try {
    await ProcessedPayment.create({ paymentId, userId })
  } catch (err: any) {
    if (err?.code === 11000) {
      const existingUser: any = await User.findById(userId)
      let existingPayment: any = null
      try { existingPayment = await Payment.findOne({ razorpayPaymentId: paymentId }) } catch { existingPayment = null }
      return {
        ok: true as const, alreadyProcessed: true, creditsAdded: 0,
        user: existingUser, payment: existingPayment ? publicPayment(existingPayment) : null
      }
    }
    throw err
  }

  let updatedUser: any
  try {
    updatedUser = await User.findOneAndUpdate(
      { _id: userId },
      { $inc: { [balanceField]: chargedAmount, credits: creditsToAdd } },
      { new: true }
    )
  } catch (err) {
    // Crediting failed: undo the "processed" marker so a retry can succeed and the customer is not charged for nothing.
    console.error('Credit update failed, rolling back payment marker:', err)
    await ProcessedPayment.deleteOne({ paymentId }).catch(() => {})
    throw err
  }
  if (!updatedUser) {
    await ProcessedPayment.deleteOne({ paymentId }).catch(() => {})
    throw new Error('User not found while crediting payment ' + paymentId)
  }
  await logCredit(userId, creditsToAdd, 'purchase', updatedUser.credits || 0, paymentId)

  // Receipt (never allowed to undo a successful credit)
  let payment: any = null
  try {
    const rec = await recordPayment({
      userId, kind: 'credits', amount: chargedAmount, currency: chargedCurrency,
      credits: creditsToAdd, balanceAfter: updatedUser.credits || 0,
      razorpayOrderId: order.id, razorpayPaymentId: paymentId,
      customerEmail: updatedUser.email, customerName: updatedUser.name
    })
    payment = rec.payment
    if (rec.created) await sendReceiptEmail(payment)
  } catch (err) {
    console.error('Could not record receipt for payment', paymentId, err)
  }
  return {
    ok: true as const, alreadyProcessed: false, creditsAdded: creditsToAdd,
    user: updatedUser, payment: payment ? publicPayment(payment) : null
  }
}

async function applySubscriptionPayment(sub: any, rpPayment: any, forceUserId?: string) {
  const found = planFromRazorpayPlanId(sub?.plan_id)
  if (!found) { console.error('Subscription payment for an unknown plan id:', sub?.plan_id); return null }
  let userId = forceUserId || String(sub.notes?.userId || '')
  if (!userId) {
    const byId: any = await User.findOne({ razorpaySubscriptionId: sub.id })
    if (byId) userId = String(byId._id)
  }
  if (!userId) { console.error('Subscription payment with no matching user:', sub?.id); return null }

  // Access is paid up to the end of the period Razorpay just charged for.
  let periodEnd: Date | null = sub.current_end ? new Date(Number(sub.current_end) * 1000) : null
  if (!periodEnd || periodEnd.getTime() <= Date.now()) {
    const now = new Date()
    periodEnd = found.billingCycle === 'yearly'
      ? new Date(now.setFullYear(now.getFullYear() + 1))
      : new Date(now.setMonth(now.getMonth() + 1))
  }
  await User.updateOne(
    { _id: userId },
    { $set: { plan: found.planKey, planExpiresAt: periodEnd, razorpaySubscriptionId: sub.id } }
  )

  if (!rpPayment?.id || !(Number(rpPayment.amount) > 0)) return { payment: null }
  try {
    const user: any = await User.findById(userId)
    const rec = await recordPayment({
      userId, kind: 'subscription', amount: Number(rpPayment.amount) / 100,
      currency: rpPayment.currency === 'USD' ? 'USD' : 'INR',
      planKey: found.planKey, billingCycle: found.billingCycle, periodEnd,
      razorpayPaymentId: rpPayment.id, razorpaySubscriptionId: sub.id,
      customerEmail: user?.email, customerName: user?.name
    })
    if (rec.created) await sendReceiptEmail(rec.payment)
    return { payment: publicPayment(rec.payment) }
  } catch (err) {
    console.error('Could not record subscription receipt for payment', rpPayment.id, err)
    return { payment: null }
  }
}

async function handleRazorpayEvent(event: any) {
  const type = event?.event
  if (type === 'order.paid') {
    const order = event.payload?.order?.entity
    const payment = event.payload?.payment?.entity
    if (order?.notes?.type === 'custom_payment' && order.notes.userId && payment?.id) {
      await applyCustomPayment(String(order.notes.userId), order, String(payment.id))
    }
  } else if (type === 'subscription.charged') {
    const sub = event.payload?.subscription?.entity
    const payment = event.payload?.payment?.entity
    if (sub?.id && payment?.id) await applySubscriptionPayment(sub, payment)
  }
  // subscription.cancelled / halted / completed need no action: access simply runs to the end of the paid period.
}

// ── Create Razorpay subscription ────────────────────────────────────────────
app.post('/api/subscribe', async (req, res) => {
  const decoded = await authenticate(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  if ((await getOrgContext(decoded.userId)).isMember)
    return res.status(403).json({ error: 'Billing is managed by your team owner' })
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
      total_count: billingCycle === 'yearly' ? 1 : 12,
      notes: { userId: String(decoded.userId) }
    })
    res.json({ subscriptionId: subscription.id, key: process.env.RAZORPAY_KEY_ID })
  } catch (err: any) {
    console.error('🔴 Razorpay subscribe error:', err)
    res.status(500).json({ error: 'Could not create subscription' })
  }
})

// ── Verify payment & activate plan ─────────────────────────────────────────
app.post('/api/verify-payment', async (req, res) => {
  const decoded = await authenticate(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  if ((await getOrgContext(decoded.userId)).isMember)
    return res.status(403).json({ error: 'Billing is managed by your team owner' })
  const { razorpay_payment_id, razorpay_subscription_id, razorpay_signature } = req.body
  if (![razorpay_payment_id, razorpay_subscription_id, razorpay_signature].every(v => typeof v === 'string' && v))
    return res.status(400).json({ error: 'Missing payment fields' })
  try {
    const body = razorpay_payment_id + '|' + razorpay_subscription_id
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET!)
      .update(body)
      .digest('hex')
    if (expectedSignature !== razorpay_signature) {
      return res.status(400).json({ error: 'Payment verification failed' })
    }

    // Ask Razorpay what was actually bought ? never trust planKey/billingCycle from the client.
    const sub: any = await razorpay.subscriptions.fetch(razorpay_subscription_id)
    if (!sub.id) sub.id = razorpay_subscription_id
    const found = planFromRazorpayPlanId(sub.plan_id)
    if (!found) return res.status(400).json({ error: 'Unknown plan for this subscription' })
    const planKey = found.planKey

    // The subscription must belong to this user
    if (sub.notes?.userId && String(sub.notes.userId) !== String(decoded.userId))
      return res.status(403).json({ error: 'Subscription does not belong to this user' })
    const takenByOther = await User.findOne({ razorpaySubscriptionId: razorpay_subscription_id, _id: { $ne: decoded.userId } })
    if (takenByOther) return res.status(409).json({ error: 'Subscription already used' })

    // Activate the plan and record the receipt. The Razorpay webhook uses the same function, so whichever
    // arrives first activates the customer and exactly one receipt is created.
    let rpPayment: any = null
    try { rpPayment = await razorpay.payments.fetch(razorpay_payment_id) } catch (e) { console.error('Could not fetch payment details for the receipt:', e) }
    const result = await applySubscriptionPayment(sub, rpPayment || { id: razorpay_payment_id }, String(decoded.userId))
    res.json({ success: true, plan: planKey, receiptId: result?.payment?.id ?? null, razorpayPaymentId: razorpay_payment_id })
  } catch (err) {
    console.error('🔴 Verify payment error:', err)
    res.status(500).json({ error: 'Could not verify payment' })
  }
})

// ── Create a one-time custom-amount payment order (NOT a subscription) ─────
// User enters any amount; this creates a Razorpay Order for that exact
// amount. No plan/backend activation happens here or in the verify route
// below — this exists purely to confirm the money reaches your bank account.
app.post('/api/create-custom-order', async (req, res) => {
  const decoded = await authenticate(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  if ((await getOrgContext(decoded.userId)).isMember)
    return res.status(403).json({ error: 'Billing is managed by your team owner' })
  const { amount, currency } = req.body
  const amountNum = Math.round(Number(amount) * 100) / 100
  if (!Number.isFinite(amountNum) || amountNum <= 0) {
    return res.status(400).json({ error: 'Enter a valid amount greater than 0' })
  }
  const selectedCurrency: 'INR' | 'USD' = currency === 'USD' ? 'USD' : 'INR'
  const limits = creditLimits(selectedCurrency)
  if (amountNum < limits.min) {
    return res.status(400).json({ error: `The minimum top-up is ${money(limits.min, selectedCurrency)}.` })
  }
  if (amountNum > limits.max) {
    return res.status(400).json({ error: `The maximum single top-up is ${money(limits.max, selectedCurrency)}. For larger amounts, contact us.` })
  }
  const creditsToGrant = creditsForAmount(amountNum, selectedCurrency)
  try {
    const order = await razorpay.orders.create({
      amount: Math.round(amountNum * 100), // Razorpay wants the smallest unit (paise/cents)
      currency: selectedCurrency,
      receipt: `custom_${Date.now()}`,
      payment_capture: true, // auto-capture so funds actually settle, not just authorize
      notes: { userId: decoded.userId, type: 'custom_payment', credits: String(creditsToGrant) }
    })
    res.json({ orderId: order.id, amount: order.amount, currency: order.currency, credits: creditsToGrant, key: process.env.RAZORPAY_KEY_ID })
  } catch (err: any) {
    console.error('Razorpay create-custom-order error:', err)
    res.status(500).json({ error: 'Could not create payment order' })
  }
})

// ── Verify the one-time custom payment ──────────────────────────────────────
// Order signature formula differs from the Subscription one above:
// HMAC_SHA256(order_id + "|" + payment_id, key_secret). No plan changes —
// this route only confirms the payment is genuine and credits the user.
app.post('/api/verify-custom-payment', async (req, res) => {
  const decoded = await authenticate(req)
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

  // Pull the order back from Razorpay — the source of truth for both the
  // legacy "credits" grant (via notes) and the real charged amount/currency
  // (via order.amount/order.currency). Neither is trusted from req.body.
  let order: any
  try {
    order = await razorpay.orders.fetch(razorpay_order_id)
  } catch (err) {
    console.error('Razorpay order fetch error:', err)
    return res.status(400).json({ success: false, error: 'Could not verify order' })
  }
  const orderUserId = order.notes?.userId
  if (orderUserId !== decoded.userId) {
    return res.status(403).json({ success: false, error: 'Order does not belong to this user' })
  }

  // Credits are worked out from Razorpay's own record of what was charged. The Razorpay webhook runs the same
  // code, so a customer who closes the tab right after paying still gets their credits (exactly once).
  try {
    const r = await applyCustomPayment(String(decoded.userId), order, razorpay_payment_id)
    res.json({
      success: true,
      alreadyProcessed: r.alreadyProcessed,
      creditsAdded: r.creditsAdded,
      credits: r.user?.credits || 0,
      customCreditsINR: r.user?.customCreditsINR || 0,
      customCreditsUSD: r.user?.customCreditsUSD || 0,
      receiptId: r.payment?.id ?? null,
      razorpayPaymentId: razorpay_payment_id
    })
  } catch (err) {
    console.error('Custom payment processing failed:', err)
    res.status(500).json({ success: false, error: 'Could not credit payment. Please retry or contact support.' })
  }
})

// ── AI usage gate ───────────────────────────────────────────────────────────
// Each AI action first uses the plan's daily allowance. When that is used up (or there is no plan at all),
// it spends 1 purchased credit. Credits never expire and work with or without a subscription.
app.post('/api/ai-usage', async (req, res) => {
  const decoded = await authenticate(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const caller = await User.findById(decoded.userId)
  if (!caller) return res.status(404).json({ error: 'User not found' })
  const orgCtx = await getOrgContext(decoded.userId)
  const user = (orgCtx.isMember ? await User.findById(orgCtx.ownerId) : caller) || caller

  const today = new Date().toISOString().slice(0, 10)
  // A finished trial no longer carries the trial allowance, even if this person stayed logged in past day 14.
  const trialOver = user.plan === 'trial' && !!user.planExpiresAt && user.planExpiresAt < new Date()
  const limit = AI_LIMITS[isAdminEmail(caller.email) ? 'enterprise' : (trialOver ? 'none' : user.plan)] || 0

  // 1) The plan's daily allowance (atomic, so two simultaneous requests cannot both take the last slot)
  if (limit > 0) {
    let r: any = await User.updateOne({ _id: user._id, aiUsageDate: { $ne: today } }, { $set: { aiUsageDate: today, aiUsageToday: 1 } })
    if (!r.modifiedCount) {
      r = await User.updateOne({ _id: user._id, aiUsageDate: today, aiUsageToday: { $lt: limit } }, { $inc: { aiUsageToday: 1 } })
    }
    if (r.modifiedCount) {
      const fresh: any = await User.findById(user._id)
      return res.json({ allowed: true, source: 'plan', usageToday: fresh?.aiUsageToday ?? 1, limit, credits: fresh?.credits || 0 })
    }
  }

  // 2) Purchased credits (atomic: only succeeds while at least 1 credit is left)
  const spent: any = await User.findOneAndUpdate({ _id: user._id, credits: { $gte: 1 } }, { $inc: { credits: -1 } }, { new: true })
  if (spent) {
    await logCredit(String(user._id), -1, 'ai', spent.credits || 0, String(decoded.userId))
    return res.json({ allowed: true, source: 'credits', limit, credits: spent.credits || 0 })
  }

  // 3) Nothing left
  if (!limit) {
    return res.status(403).json({ error: 'no_plan', message: 'AI needs a plan or credits. Buy credits to pay only for what you use, no subscription needed.', credits: 0 })
  }
  return res.status(429).json({ error: 'limit_reached', message: `You have used today's ${limit} AI actions. Buy credits to keep going now, or upgrade your plan.`, credits: 0 })
})

// ── Credit prices (public: the Pricing page shows a live "you get N credits" preview) ──
app.get('/api/credit-rates', (_req, res) => {
  res.json(creditRates())
})

// ── Billing history & receipts (each person only ever sees their own) ─────────
app.get('/api/payments', async (req, res) => {
  const decoded = await authenticate(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const rows: any[] = await Payment.find({ userId: String(decoded.userId) }).sort({ createdAt: -1 }).limit(200).lean()
  res.json(rows.map(publicPayment))
})

app.get('/api/payments/by-razorpay/:paymentId', async (req, res) => {
  const decoded = await authenticate(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  const row: any = await Payment.findOne({ razorpayPaymentId: String(req.params.paymentId), userId: String(decoded.userId) })
  if (!row) return res.status(404).json({ error: 'Receipt not found yet' })
  res.json(publicPayment(row))
})

app.get('/api/payments/:id', async (req, res) => {
  const decoded = await authenticate(req)
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' })
  let row: any = null
  try { row = await Payment.findOne({ _id: String(req.params.id), userId: String(decoded.userId) }) } catch { row = null }
  if (!row) return res.status(404).json({ error: 'Receipt not found' })
  res.json(publicPayment(row))
})

const PORT = process.env.PORT || 4000
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`))
