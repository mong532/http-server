## Vercel webhook server (OxaPay → Discord role grant)

This folder is a small serverless HTTP receiver you can deploy to Vercel to get a **public URL** for OxaPay webhooks.

### What it does
- Receives `POST /webhooks/oxapay`
- Verifies the `HMAC` header (sha512) using `OXAPAY_MERCHANT_API_KEY`
- When webhook `status` becomes **Paid**, it grants the premium role via Discord REST API:
  - `PUT /guilds/{guildId}/members/{userId}/roles/{roleId}`

### Required Vercel env vars
- `OXAPAY_MERCHANT_API_KEY`
- `DISCORD_TOKEN` (your bot token)

### Bot configuration
In your bot `.env` set:
- `PUBLIC_WEBHOOK_BASE_URL=https://<your-vercel-domain>`
- `OXAPAY_MERCHANT_API_KEY=...`

The bot uses callback URL:
`https://<your-vercel-domain>/webhooks/oxapay`

### Important
The bot encodes the identifiers in `order_id` like:
`premium_<guildId>_<userId>_<roleId>_<timestamp>`

That’s how the Vercel function knows which role to grant.

