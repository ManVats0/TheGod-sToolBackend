import mongoose, { Document, Model } from 'mongoose'

export interface IOrgMember {
  userId: mongoose.Types.ObjectId
  role: 'owner' | 'admin' | 'editor' | 'viewer'
  joinedAt: Date
}

export interface IOrganization extends Document {
  name: string
  ownerId: mongoose.Types.ObjectId
  members: IOrgMember[]
  createdAt: Date
}

const organizationSchema = new mongoose.Schema<IOrganization>({
  name: { type: String, required: true, trim: true },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  members: {
    type: [{
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      role: { type: String, enum: ['owner', 'admin', 'editor', 'viewer'], required: true },
      joinedAt: { type: Date, default: Date.now }
    }],
    default: []
  },
  createdAt: { type: Date, default: Date.now }
})

const Organization: Model<IOrganization> = mongoose.model<IOrganization>('Organization', organizationSchema)
export default Organization
