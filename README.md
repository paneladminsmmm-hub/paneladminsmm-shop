# SMM.com — paneladminsmm.shop

A responsive SMM panel foundation with email/password accounts, SQLite persistence, server-priced orders, wallet ledger, Razorpay order creation/webhook crediting, tickets and admin APIs.

## Important scope and integrations

This is a deployable starter, not a turnkey live-money business. The site deliberately does **not** claim provider fulfilment, Google OAuth, email delivery, or password-reset delivery are active. No provider API is invented. The catalogue is seeded with legitimate campaign setup/promotion services, not fake follower/like delivery. Add only services that comply with the relevant platform terms and applicable law.

The user-facing Add Funds API creates a Razorpay order only when credentials exist. The wallet is credited only by a verified `payment.captured` webhook. The browser callback never credits funds. Razorpay Checkout UI needs its client script added to `public/index.html` before taking live payments:
```html
<script src="https://checkout.razorpay.com/v1/checkout.js"></script>
```
The webhook endpoint is `/api/payments/webhook`. Configure that exact URL in Razorpay with the same webhook secret in `RAZORPAY_WEBHOOK_SECRET` and subscribe to `payment.captured` and `payment.failed`. Test in Razorpay Test Mode first.

## Run locally

1. Install Node.js 20 or newer.
2. Extract this ZIP and open the folder in a terminal.
3. Copy `.env.example` to `.env`.
4. Set a long random `SESSION_SECRET`, plus `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD`.
5. Run:
   ```bash
   npm install
   npm start
   ```
6. Open `http://localhost:3000`. Sign up as a user, then sign in with the admin credentials to create the initial admin session.

The first admin account is created on first boot only if `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set and that email does not already exist. Keep `.env` private.

## Hosting and domain

Use Node.js hosting that supports a persistent writable disk. SQLite needs persistent storage; do not deploy this app on an ephemeral filesystem. Set the hosting start command to `npm start`, Node version 20+, and set environment variables from `.env.example`. Set `BASE_URL=https://paneladminsmm.shop`, point your domain DNS to the host, and enable HTTPS. Set `NODE_ENV=production` and a strong `SESSION_SECRET`.

For production with multiple app instances, migrate SQLite to PostgreSQL and use a shared session store. Back up `data/panel.sqlite` regularly.

## Razorpay setup

1. Create/verify your Razorpay merchant account and enable the required payment methods.
2. Copy the Key ID and Key Secret into server environment variables.
3. Add the Checkout script shown above to `public/index.html` before `/app.js`.
4. Set the webhook URL to `https://paneladminsmm.shop/api/payments/webhook`.
5. Set `RAZORPAY_WEBHOOK_SECRET` to the webhook secret configured in Razorpay.
6. Test ₹100 and ₹2,000 payments in Test Mode. Confirm that the wallet changes only after the webhook is received.
7. Switch to live credentials only after merchant verification and successful tests.

## Provider API

No generic endpoint can safely be assumed. The admin summary endpoint is available at `/api/admin/summary`; service creation/price/status endpoints are also available. Provider dispatch is intentionally not enabled until a real provider's API documentation, authentication method, request schema, status lookup and refund rules are known. Do not put provider secrets in frontend code. Add a provider adapter on the server after validating the provider documentation.

## Admin API

All routes require a logged-in account whose database role is `admin`:
- `GET /api/admin/summary`
- `POST /api/admin/services` — `platform, category, name, description, priceRupees, minQty, maxQty`
- `PATCH /api/admin/services/:id` — `priceRupees` and/or `active`
- `PATCH /api/admin/orders/:id` — `status` in Pending, Processing, Completed, Partial, Cancelled, Failed
- `POST /api/admin/tickets/:id/reply` — `reply`

Admin management endpoints are available but a complete visual admin console, admin wallet adjustment UI with audit approval, Google OAuth, email provider, password reset, automated provider status polling/refunds, and comprehensive production hardening are not included yet. Do not advertise these as live.

## Security checklist before live launch

- Set production secrets; never commit `.env`.
- Add CSRF protection and stricter per-route rate limits.
- Add email verification, password reset and Google OAuth with verified redirect URLs.
- Add transactional outbox/retry handling for provider requests and payment events.
- Add idempotent provider callbacks/status polling and audited refund workflow.
- Add privacy/terms/refund pages reviewed for your business and jurisdiction.
- Have the payment setup and consumer-facing claims reviewed for compliance.
- Use PostgreSQL for production scale, managed backups, monitoring and log redaction.
