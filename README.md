# Acrionix Web & Docs

Cloudflare Worker serving:

- **`https://acrionix.cloud`** - Acrionix landing page and interactive Log-to-Patch sandbox (`SELinux AVC Denial`, `VINTF / HAL Mismatch`, `Init Service Crash`).
- **`https://docs.acrionix.net`** - Acrionix documentation portal (Quickstart, CLI Reference, SELinux Synthesizer, VINTF Resolver, HIL CI).
- **`POST /api/beta`** - Edge endpoint for OEM Beta access requests with Telegram webhook notifications.
- **`GET /health`** - Service health check.

## Local Development

```bash
npm install
npm run dev
```

## Deployment

```bash
npx wrangler secret put TELEGRAM_BOT_TOKEN
npx wrangler secret put TELEGRAM_CHAT_ID
npm run deploy
```
