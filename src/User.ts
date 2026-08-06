import mongoose from 'mongoose'

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, default: null },
  googleId: { type: String, default: null },
  name: { type: String, default: null },
  resetToken: { type: String, default: null },
  resetTokenExpiry: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  plan: { type: String, enum: ['none', 'trial', 'lite', 'starter', 'pro', 'team', 'enterprise'], default: 'trial' },
  planExpiresAt: { type: Date, default: () => new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) },
  razorpaySubscriptionId: { type: String, default: null },
  hasUsedTrial: { type: Boolean, default: true },
  aiUsageToday: { type: Number, default: 0 },
  aiUsageDate: { type: String, default: null },
  sessions: {
    type: [{
      sessionId: { type: String, required: true },
      device: { type: String, default: 'Unknown device' },
      createdAt: { type: Date, default: Date.now },
      lastActive: { type: Date, default: Date.now }
    }],
    default: []
  }
})

export default mongoose.model('User', userSchema)
