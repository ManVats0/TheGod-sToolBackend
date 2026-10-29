import { Payment, Counter, CreditLedger } from './Payment'

export type Currency = 'INR' | 'USD'

const positive = (v: string | undefined, fallback: number) => {
  const n = Number(v)
  return Number.isFinite(n) && n > 0 ? n : fallback
}

// ── Credit pricing ─────────────────────────────────────────────────────────
// 1 credit = 1 AI action (the same unit the plans use for "AI transforms per day").
// Read lazily so values from .env are picked up after dotenv.config() has run.
export function creditPrice(c: Currency): number {
  return c === 'USD' ? positive(process.env.USD_PER_CREDIT, 0.03) : positive(process.env.RUPEES_PER_CREDIT, 2)
}
export function creditLimits(c: Currency) {
  // Min keeps tiny payments from being eaten by gateway fees; max stays inside Razorpay's per-payment cap.
  return c === 'USD'
    ? { min: positive(process.env.MIN_TOPUP_USD, 2), max: positive(process.env.MAX_TOPUP_USD, 360) }
    : { min: positive(process.env.MIN_TOPUP_INR, 99), max: positive(process.env.MAX_TOPUP_INR, 50000) }
}
export function creditsForAmount(amount: number, c: Currency): number {
  const a = Math.round(amount * 100) / 100
  return Math.max(0, Math.floor(a / creditPrice(c) + 1e-9))
}
export function creditRates() {
  return { INR: { perCredit: creditPrice('INR'), ...creditLimits('INR') }, USD: { perCredit: creditPrice('USD'), ...creditLimits('USD') } }
}

// ── Seller details printed on receipts / invoices (set in Railway variables) ──
export function business() {
  return {
    name: process.env.BUSINESS_NAME || "The God's Tool",
    address: process.env.BUSINESS_ADDRESS || '',
    gstin: process.env.BUSINESS_GSTIN || '',
    gstRate: Number(process.env.GST_RATE) || 0,
    supportEmail: process.env.SUPPORT_EMAIL || 'support@thegodstool.com'
  }
}

export const money = (amount: number, c: Currency) =>
  (c === 'USD' ? '$' : '\u20B9') + Number(amount || 0).toLocaleString(c === 'USD' ? 'en-US' : 'en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })

const esc = (s: any) => String(s ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch] as string))

// ── Receipt numbers: TGT-2026-000001 (sequential per year) ────────────────────
export async function nextReceiptNo(date = new Date()): Promise<string> {
  const year = date.getFullYear()
  const c: any = await Counter.findOneAndUpdate({ _id: `receipt-${year}` }, { $inc: { seq: 1 } }, { new: true, upsert: true })
  return `TGT-${year}-${String(c.seq).padStart(6, '0')}`
}

export interface PaymentInput {
  userId: string
  kind: 'credits' | 'subscription'
  amount: number
  currency: Currency
  credits?: number
  balanceAfter?: number | null
  planKey?: string | null
  billingCycle?: string | null
  periodEnd?: Date | null
  razorpayOrderId?: string | null
  razorpayPaymentId: string
  razorpaySubscriptionId?: string | null
  customerEmail?: string | null
  customerName?: string | null
}

// Records a payment exactly once. The browser and the Razorpay webhook may both report the same payment;
// the second report just gets the first record back.
export async function recordPayment(p: PaymentInput): Promise<{ payment: any; created: boolean }> {
  const existing = await Payment.findOne({ razorpayPaymentId: p.razorpayPaymentId })
  if (existing) return { payment: existing, created: false }
  const receiptNo = await nextReceiptNo()
  try {
    const payment = await Payment.create({ ...p, receiptNo, status: 'paid' })
    return { payment, created: true }
  } catch (err: any) {
    if (err?.code === 11000) {
      const again = await Payment.findOne({ razorpayPaymentId: p.razorpayPaymentId })
      if (again) return { payment: again, created: false }
    }
    throw err
  }
}

export async function logCredit(userId: string, delta: number, reason: string, balanceAfter: number | null, ref?: string | null) {
  try { await CreditLedger.create({ userId, delta, reason, balanceAfter, ref: ref || null }) } catch (e) { console.error('Credit ledger write failed:', e) }
}

export function describePayment(p: any): string {
  if (p.kind === 'credits') return `${Number(p.credits || 0).toLocaleString('en-IN')} AI credits`
  const plan = String(p.planKey || '').replace(/^./, (c: string) => c.toUpperCase())
  return `${plan} plan (${p.billingCycle === 'yearly' ? 'yearly' : 'monthly'} subscription)`
}

// The shape the Billing page / Thank-you page read. Never includes anything about other people.
export function publicPayment(p: any) {
  return {
    id: String(p._id),
    receiptNo: p.receiptNo,
    kind: p.kind,
    description: describePayment(p),
    amount: p.amount,
    currency: p.currency,
    credits: p.credits || 0,
    balanceAfter: p.balanceAfter ?? null,
    planKey: p.planKey || null,
    billingCycle: p.billingCycle || null,
    periodEnd: p.periodEnd || null,
    razorpayPaymentId: p.razorpayPaymentId,
    customerEmail: p.customerEmail || null,
    customerName: p.customerName || null,
    emailed: !!p.emailSent,
    createdAt: p.createdAt,
    business: business()
  }
}

export function receiptHtml(p: any): string {
  const b = business()
  const gst = b.gstRate > 0 ? p.amount - p.amount / (1 + b.gstRate / 100) : 0
  const title = b.gstin ? 'Tax invoice' : 'Payment receipt'
  const when = new Date(p.createdAt || Date.now()).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })
  const row = (k: string, v: string) => `<tr><td style="padding:6px 0;color:#64748b;">${k}</td><td style="padding:6px 0;text-align:right;color:#0f172a;font-weight:600;">${v}</td></tr>`
  const extra =
    p.kind === 'credits'
      ? row('Credits added', `+${Number(p.credits || 0).toLocaleString('en-IN')}`) +
        (p.balanceAfter != null ? row('New credit balance', Number(p.balanceAfter).toLocaleString('en-IN')) : '')
      : p.periodEnd
        ? row('Access paid until', new Date(p.periodEnd).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' }))
        : ''
  return `
  <div style="font-family:-apple-system,Segoe UI,sans-serif;max-width:520px;margin:24px auto;padding:28px;border:1px solid #e2e8f0;border-radius:14px;background:#ffffff;color:#0f172a;">
    <h2 style="margin:0 0 4px;">Thank you${p.customerName ? ', ' + esc(p.customerName) : ''}!</h2>
    <p style="margin:0 0 20px;color:#475569;">Your payment went through. Here is your ${title.toLowerCase()}.</p>
    <table style="width:100%;border-collapse:collapse;font-size:14px;">
      ${row(title.charAt(0).toUpperCase() + title.slice(1) + ' no.', esc(p.receiptNo))}
      ${row('Date', when)}
      ${row('Item', esc(describePayment(p)))}
      ${extra}
      ${gst > 0 ? row(`Includes GST @ ${b.gstRate}%`, money(gst, p.currency)) : ''}
      <tr><td colspan="2" style="border-top:1px solid #e2e8f0;padding-top:8px;"></td></tr>
      ${row('Amount paid', money(p.amount, p.currency))}
      ${row('Payment ID', esc(p.razorpayPaymentId))}
    </table>
    <p style="margin:20px 0 0;color:#475569;font-size:13px;">Sold by ${esc(b.name)}${b.address ? ', ' + esc(b.address) : ''}${b.gstin ? ' &middot; GSTIN ' + esc(b.gstin) : ''}.<br>Need help? Write to ${esc(b.supportEmail)}.</p>
  </div>`
}

// Best effort: a failed email must never undo a successful payment.
export async function sendReceiptEmail(p: any): Promise<boolean> {
  if (!process.env.RESEND_API_KEY || !p.customerEmail) return false
  try {
    const { Resend } = require('resend')
    const resend = new Resend(process.env.RESEND_API_KEY)
    await resend.emails.send({
      from: 'The Gods Tool <noreply@thegodstool.com>',
      to: p.customerEmail,
      subject: `Your receipt ${p.receiptNo} \u2013 ${business().name}`,
      html: receiptHtml(p)
    })
    await Payment.updateOne({ _id: p._id }, { $set: { emailSent: true } })
    return true
  } catch (err) {
    console.error('Receipt email failed:', err)
    return false
  }
}
