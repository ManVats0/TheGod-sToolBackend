import mongoose, { Document, Model } from 'mongoose'

export interface ISession {
  sessionId: string
  device: string
  createdAt: Date
  lastActive: Date
}

export interface IUser extends Document {
  email: string
  password: string | null
  googleId: string | null
  name: string | null
  resetToken: string | null
  resetTokenExpiry: Date | null
  createdAt: Date
  plan: 'none' | 'trial' | 'lite' | 'starter' | 'pro' | 'team' | 'enterprise'
  planExpiresAt: Date | null
  razorpaySubscriptionId: string | null
  hasUsedTrial: boolean
  credits: number
  customCreditsINR: number
  customCreditsUSD: number
  aiUsageToday: number
  aiUsageDate: string | null
  sessions: ISession[]
}

const userSchema = new mongoose.Schema<IUser>({
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
  credits: { type: Number, default: 0 },
  customCreditsINR: { type: Number, default: 0 },
  customCreditsUSD: { type: Number, default: 0 },
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

const User: Model<IUser> = mongoose.model<IUser>('User', userSchema)
export default User
