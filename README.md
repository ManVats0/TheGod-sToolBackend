# The God's Tool: Node service

Express + MongoDB service for accounts and money: sign-in (email and Google), password reset, plans, credits, Razorpay payments, receipts and the AppSumo webhook. Data cleaning itself is in the Python service.

## Run it
```
npm install
npm run dev     # local, restarts on change
npm run build && npm start   # production
```

## Files
| File | What it does |
| --- | --- |
| `src/index.ts` | All routes. A map of sections is at the top. |
| `src/User.ts`, `src/Organization.ts`, `src/Payment.ts` | MongoDB models. |
| `src/billing.ts` | Prices, receipts, money formatting. |
| `src/appsumo.ts` | AppSumo webhook. |

## Settings (environment variables)
Core: `MONGODB_URI`, `JWT_SECRET`, `PORT`, `FRONTEND_URL`, `ADMIN_EMAILS`, `ENFORCE_PLAN_EXPIRY`
Google sign-in: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`
Email: `RESEND_API_KEY`, `SUPPORT_EMAIL`
Razorpay: `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`, and one `RAZORPAY_PLAN_<PLAN>_<MONTHLY|YEARLY>_<INR|USD>` per plan (LITE, STARTER, PRO, TEAM, ENTERPRISE)
Credits: `RUPEES_PER_CREDIT`, `USD_PER_CREDIT`, `MIN_TOPUP_INR`, `MAX_TOPUP_INR`, `MIN_TOPUP_USD`, `MAX_TOPUP_USD`, `GST_RATE`
Receipts: `BUSINESS_NAME`, `BUSINESS_ADDRESS`, `BUSINESS_GSTIN`
AppSumo: `APPSUMO_API_KEY`

## Code style
Prettier (settings in `.prettierrc.json`): `npx prettier --write src/*.ts`.
