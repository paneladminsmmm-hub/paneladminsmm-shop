UPLOAD THESE FILES TO THE ROOT OF YOUR GITHUB REPOSITORY:
- package.json
- server.js
- .env.example
- .gitignore

Your public folder should contain index.html and style.css (already uploaded by you).
Important: this is a starter backend, not a production-ready SMM panel. It does not connect to any SMM provider or automatically fulfil orders. Only use lawful, platform-compliant promotion services. Do not ask customers for social-media passwords.

Before deployment:
1. Use Node.js 20+ hosting with persistent disk/storage for SQLite.
2. Configure environment variables from .env.example in the hosting dashboard. Never upload a real .env file or secret keys to GitHub.
3. Set a long random SESSION_SECRET and strong ADMIN_PASSWORD.
4. Razorpay wallet credit is only processed by the signed webhook at /api/payments/webhook. Configure the exact deployed URL and webhook secret in Razorpay, test in Test Mode, and do not accept live payments until tested.
5. Google sign-in, email delivery/password reset, provider fulfilment/status polling/refunds, and a complete admin web interface are not included.
