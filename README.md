# PanelAdminSMM.shop — SMM reseller panel

A Node.js + Express + SQLite starter application for a reseller panel. It includes account registration/login, dashboard, service catalogue, new orders, order history, add-funds requests, support tickets, admin payment approval, and standard SMM-provider API service sync/order submission.

## Included project files

- `server.js` — Express app and routes
- `src/provider.js` — standard SMM API client (`services`, `add`, `status`)
- `public/style.css`, `public/app.js` — responsive UI and order estimate helper
- `views/README.md` — view/template folder note
- `.env.example` — environment variable template
- `render.yaml`, `Dockerfile` — deployment starters

## Run locally

1. Install Node.js 20 or newer.
2. Extract this ZIP and open a terminal in the `paneladminsmm-shop` folder.
3. Run `npm install`.
4. Copy `.env.example` to `.env` and change `SESSION_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD`.
5. Add your provider's API URL and API key to `.env`.
6. Run `npm start` and open `http://localhost:3000`.

The first admin account is created on the first run using `ADMIN_EMAIL` and `ADMIN_PASSWORD`. Change the example password before exposing the site publicly.

## Provider API

The connector expects the common SMM API v2 form fields: `key`, `action=services`, `action=add` with `service`, `link`, `quantity`, and `action=status` with `order`. Your provider must support this format. If its API differs, `src/provider.js` must be adapted to the provider's documentation. Admin users can import services from `/admin` after setting `SMM_API_URL` and `SMM_API_KEY`.

## Payments — important

The included Add Funds workflow is **manual UPI reference submission**. An admin must verify the payment and approve it in `/admin` before the user's balance is credited. It does not pretend to verify UPI payments automatically.

Automatic Razorpay checkout/webhooks are not activated in this ZIP because valid merchant credentials, account configuration, and webhook details have not been supplied. Do not put secret keys in browser code. Add them only as server environment variables after configuring and testing the gateway.

## Before production

- Use HTTPS and a strong unique `SESSION_SECRET` (32+ characters).
- Set a strong admin password and keep `.env` private.
- Use persistent disk/storage for `panel.sqlite` and `sessions.sqlite`; ephemeral hosting filesystems can lose data on redeploy.
- Configure backups, email verification/password reset, payment gateway webhooks, and provider-specific API compatibility before accepting live customers.
- Review the provider's terms and the applicable platform rules for every service you sell.

This is a working starter panel, not a pixel-perfect copy of VIPPROSMM and not a turnkey live payment integration. You own the domain and hosting configuration.
