import mongoose from 'mongoose'

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, default: null },
  googleId: { type: String, default: null },
  name: { type: String, default: null },
  resetToken: { type: String, default: null },
  resetTokenExpiry: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  plan: { type: String, enum: ['none', 'lite', 'starter', 'pro', 'team', 'enterprise'], default: 'none' },
  planExpiresAt: { type: Date, default: null },
  razorpaySubscriptionId: { type: String, default: null },
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
