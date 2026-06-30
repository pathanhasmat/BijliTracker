# BijliTracker Pro

Electricity bill tracker and tenant management PWA for Indian property managers — slab/fixed-rate billing, AI bill analysis, WhatsApp invoicing, Camera OCR meter reading, and a 3-tier subscription model.

## Repository structure

```
.
├── index.html              # Entire frontend — single-file PWA (HTML+CSS+JS)
├── manifest.json           # PWA manifest — icons, theme, install metadata
├── sw.js                   # Service worker — offline caching
├── vercel.json              # Vercel headers config (manifest content-type, SW scope)
├── .gitignore
│
├── api/
│   └── chat.js              # Vercel Edge Function — AI chat proxy (Groq + Supabase)
│
├── icons/
│   ├── icon-192.png         # PWA icon, Android/Chrome
│   ├── icon-512.png         # PWA icon, maskable
│   └── apple-touch-icon.png # iOS home-screen icon (180×180)
│
├── sql/
│   ├── 01_migration.sql     # Run FIRST — adds subscription columns to user_settings
│   └── 02_db_rls_setup.sql  # Run SECOND — RLS policies, security triggers, quota RPCs
│
└── docs/
    └── google_auth_guide.md # Step-by-step Google OAuth setup in Supabase + Google Cloud
```

## Deploy order

1. **Push this repo to GitHub**, then import it into Vercel (Framework Preset: *Other*, no build command needed — it's static + one Edge Function).

2. **Supabase setup**:
   - Create a project at supabase.com
   - Open SQL Editor → run `sql/01_migration.sql`, then `sql/02_db_rls_setup.sql` (in that order)
   - Authentication → Providers → enable Email and Google (see `docs/google_auth_guide.md`)
   - Authentication → URL Configuration → add your Vercel domain to Site URL and Redirect URLs

3. **Vercel environment variables** (Project Settings → Environment Variables):

   | Variable | Where to get it |
   |---|---|
   | `SUPABASE_URL` | Supabase → Settings → API → Project URL |
   | `SUPABASE_SERVICE_ROLE_KEY` | Supabase → Settings → API → `service_role` (server-only, never expose client-side) |
   | `SUPABASE_ANON_KEY` | Supabase → Settings → API → `anon public` |
   | `GROQ_KEY_1` … `GROQ_KEY_7` | console.groq.com → API Keys (only `GROQ_KEY_1` is required; the rest are optional failover keys) |

4. **In `index.html`**, set your own Supabase project URL/anon key and Razorpay key:
   - Search for `CENTRAL_SB_URL`, `CENTRAL_SB_ANON_KEY`, `APP_RAZORPAY_KEY_ID` and replace with your own values.

5. **Redeploy** on Vercel so the environment variables take effect.

## Local development

This is a static site with one serverless function — no build step. Any static file server works for the frontend; for the `/api/chat.js` function locally, use the Vercel CLI:

```bash
npm i -g vercel
vercel dev
```

## Notes

- `index.html` is intentionally a single file (no bundler/framework) for fast first paint and minimal dependencies — see in-file comments for the architectural reasoning.
- `api/chat.js` must stay at exactly this path — Vercel's filesystem-based routing maps `api/chat.js` → `POST /api/chat`.
- Re-run `sql/02_db_rls_setup.sql` any time — every statement is idempotent (safe to re-run).
