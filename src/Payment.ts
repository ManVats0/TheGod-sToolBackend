import mongoose from 'mongoose'

// One row per successful payment (credit top-up, first subscription payment, or renewal).
// This is the source for receipts, invoices and the Billing page.
const paymentSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  kind: { type: String, enum: ['credits', 'subscription'], required: true },
  status: { type: String, default: 'paid' },
  receiptNo: { type: String, unique: true, sparse: true },
  amount: { type: Number, required: true },        // major units (rupees / dollars) actually charged
  currency: { type: String, enum: ['INR', 'USD'], required: true },
  credits: { type: Number, default: 0 },           // credits added by this payment
  balanceAfter: { type: Number, default: null },   // credit balance right after this payment
  planKey: { type: String, default: null },
  billingCycle: { type: String, default: null },
  periodEnd: { type: Date, default: null },        // subscription: access paid up to
  razorpayOrderId: { type: String, default: null },
  razorpayPaymentId: { type: String, unique: true, sparse: true },
  razorpaySubscriptionId: { type: String, default: null },
  customerEmail: { type: String, default: null },
  customerName: { type: String, default: null },
  emailSent: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
})

// Sequential receipt numbers per year: TGT-2026-000001
const counterSchema = new mongoose.Schema({
  _id: { type: String },
  seq: { type: Number, default: 0 }
}, { _id: false })

// Every change to a credit balance (purchase, spend, migration), so balances can always be explained.
const ledgerSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  delta: { type: Number, required: true },
  reason: { type: String, required: true },        // 'purchase' | 'ai' | 'usd_migration' | 'adjustment'
  balanceAfter: { type: Number, default: null },
  ref: { type: String, default: null },            // payment id etc.
  createdAt: { type: Date, default: Date.now }
})

export const Payment = mongoose.model('Payment', paymentSchema)
export const Counter = mongoose.model('Counter', counterSchema)
export const CreditLedger = mongoose.model('CreditLedger', ledgerSchema)
